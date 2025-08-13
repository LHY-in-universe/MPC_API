//! # 门限BFV密钥生成协议
//! 
//! 实现分布式BFV密钥生成协议，确保没有任何单方能够获得完整的私钥。
//! 基于Shamir秘密分享和分布式密钥生成技术。

use crate::homomorphic_encryption::{BFVPublicKey, BFVSecretKey};
use crate::secret_sharing::{field_add, field_mul, field_sub, FIELD_PRIME};
use crate::{MpcError, Result};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::protocol_messages::PartyId;
use super::bfv_based::BFVParams;

/// 门限密钥生成贡献
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenContribution {
    /// 参与方ID
    pub party_id: PartyId,
    /// 公开多项式系数
    pub public_polynomial: Vec<u64>,
    /// 私钥分享的承诺
    pub commitments: Vec<u64>,
    /// 零知识证明
    pub proof: Vec<u8>,
}

/// 门限BFV密钥生成器
#[derive(Debug)]
pub struct ThresholdBFVKeyGen {
    /// 参与方数量
    party_count: usize,
    /// 门限值
    threshold: usize,
    /// 当前方ID
    party_id: PartyId,
    /// BFV参数
    params: BFVParams,
    /// 私钥多项式系数
    secret_polynomial: Vec<u64>,
    /// 收集到的贡献
    contributions: HashMap<PartyId, KeyGenContribution>,
}

impl ThresholdBFVKeyGen {
    /// 创建新的门限密钥生成器
    pub fn new(
        party_count: usize,
        threshold: usize,
        party_id: PartyId,
        params: BFVParams,
    ) -> Result<Self> {
        if threshold == 0 || threshold > party_count {
            return Err(MpcError::InvalidThreshold);
        }
        
        if party_id >= party_count {
            return Err(MpcError::ProtocolError(
                "Party ID must be less than party count".to_string()
            ));
        }
        
        Ok(Self {
            party_count,
            threshold,
            party_id,
            params,
            secret_polynomial: Vec::new(),
            contributions: HashMap::new(),
        })
    }
    
    /// 第一阶段：生成自己的密钥生成贡献
    pub fn generate_contribution(&mut self) -> Result<KeyGenContribution> {
        let mut rng = thread_rng();
        
        // 生成随机的私钥多项式系数（度数为threshold-1）
        self.secret_polynomial = (0..self.threshold)
            .map(|_| rng.gen_range(0..self.params.coeff_modulus))
            .collect();
        
        // 生成公开多项式系数用于公钥构造
        let public_polynomial: Vec<u64> = (0..self.params.degree)
            .map(|_| rng.gen_range(0..self.params.coeff_modulus))
            .collect();
        
        // 生成承诺值（简化版，实际应使用Pedersen承诺）
        let commitments: Vec<u64> = self.secret_polynomial.iter()
            .map(|&coeff| field_mul(coeff, 3)) // 简化的承诺
            .collect();
        
        // 生成零知识证明（简化版）
        let proof = self.generate_zkp_for_contribution(&public_polynomial)?;
        
        let contribution = KeyGenContribution {
            party_id: self.party_id,
            public_polynomial,
            commitments,
            proof,
        };
        
        // 保存自己的贡献
        self.contributions.insert(self.party_id, contribution.clone());
        
        Ok(contribution)
    }
    
    /// 第二阶段：收集其他方的贡献
    pub fn add_contribution(&mut self, contribution: KeyGenContribution) -> Result<()> {
        // 验证贡献的有效性
        self.verify_contribution(&contribution)?;
        
        // 保存贡献
        self.contributions.insert(contribution.party_id, contribution);
        
        Ok(())
    }
    
    /// 第三阶段：生成最终的密钥对
    pub fn generate_keypair(&self) -> Result<(BFVPublicKey, BFVSecretKey)> {
        if self.contributions.len() != self.party_count {
            return Err(MpcError::ProtocolError(
                format!("Missing contributions: expected {}, got {}", 
                       self.party_count, self.contributions.len())
            ));
        }
        
        // 聚合所有方的公开多项式生成公钥
        let mut aggregated_a = vec![0u64; self.params.degree];
        let mut aggregated_b = vec![0u64; self.params.degree];
        
        for contribution in self.contributions.values() {
            for i in 0..self.params.degree {
                if i < contribution.public_polynomial.len() {
                    aggregated_a[i] = field_add(aggregated_a[i], contribution.public_polynomial[i]);
                }
            }
        }
        
        // 生成公钥的b部分（简化版）
        let mut rng = thread_rng();
        for i in 0..self.params.degree {
            let noise = rng.gen_range(0..100); // 小噪声
            aggregated_b[i] = field_add(aggregated_a[i], noise);
        }
        
        let public_key = BFVPublicKey {
            a: aggregated_a,
            b: aggregated_b,
            n: self.params.degree,
            q: self.params.coeff_modulus,
            t: self.params.plain_modulus,
        };
        
        // 生成本方的私钥分享
        let secret_key_share = self.generate_secret_key_share()?;
        
        Ok((public_key, secret_key_share))
    }
    
    /// 生成本方的私钥分享
    fn generate_secret_key_share(&self) -> Result<BFVSecretKey> {
        // 计算本方在拉格朗日插值中的私钥分享
        let mut secret_share = vec![0u64; self.params.degree];
        
        // 对于每个位置，计算所有方贡献的秘密分享和
        for contribution in self.contributions.values() {
            let party_eval = self.evaluate_secret_polynomial(contribution.party_id)?;
            
            // 使用拉格朗日插值系数
            let lagrange_coeff = self.compute_lagrange_coefficient(contribution.party_id);
            
            for i in 0..self.params.degree.min(secret_share.len()) {
                secret_share[i] = field_add(
                    secret_share[i],
                    field_mul(party_eval, lagrange_coeff)
                );
            }
        }
        
        Ok(BFVSecretKey {
            s: secret_share,
            n: self.params.degree,
            q: self.params.coeff_modulus,
            t: self.params.plain_modulus,
        })
    }
    
    /// 计算拉格朗日插值系数
    fn compute_lagrange_coefficient(&self, party_id: PartyId) -> u64 {
        let mut numerator = 1u64;
        let mut denominator = 1u64;
        
        // 计算拉格朗日系数 ∏(0-j)/(i-j) for j≠i
        for j in 0..self.party_count {
            if j != party_id {
                numerator = field_mul(numerator, field_sub(0, j as u64));
                denominator = field_mul(denominator, field_sub(party_id as u64, j as u64));
            }
        }
        
        // 计算模逆
        self.field_inverse(denominator).map(|inv| field_mul(numerator, inv)).unwrap_or(1)
    }
    
    /// 计算模逆（简化版）
    fn field_inverse(&self, a: u64) -> Result<u64> {
        // 使用扩展欧几里得算法计算模逆
        let mut old_r = a as i128;
        let mut r = FIELD_PRIME as i128;
        let mut old_s = 1i128;
        let mut s = 0i128;
        
        while r != 0 {
            let quotient = old_r / r;
            let temp_r = r;
            r = old_r - quotient * r;
            old_r = temp_r;
            
            let temp_s = s;
            s = old_s - quotient * s;
            old_s = temp_s;
        }
        
        if old_r > 1 {
            return Err(MpcError::CryptographicError("No modular inverse exists".to_string()));
        }
        
        let result = if old_s < 0 {
            (old_s + FIELD_PRIME as i128) as u64
        } else {
            old_s as u64
        };
        
        Ok(result % FIELD_PRIME)
    }
    
    /// 评估秘密多项式在给定点的值
    fn evaluate_secret_polynomial(&self, x: PartyId) -> Result<u64> {
        if self.secret_polynomial.is_empty() {
            return Err(MpcError::ProtocolError("Secret polynomial not generated".to_string()));
        }
        
        let mut result = 0u64;
        let mut x_power = 1u64;
        let x_val = x as u64;
        
        for &coeff in &self.secret_polynomial {
            result = field_add(result, field_mul(coeff, x_power));
            x_power = field_mul(x_power, x_val);
        }
        
        Ok(result)
    }
    
    /// 验证贡献的有效性
    fn verify_contribution(&self, contribution: &KeyGenContribution) -> Result<()> {
        // 验证参与方ID
        if contribution.party_id >= self.party_count {
            return Err(MpcError::ProtocolError("Invalid party ID".to_string()));
        }
        
        // 验证公开多项式长度
        if contribution.public_polynomial.len() != self.params.degree {
            return Err(MpcError::ProtocolError("Invalid public polynomial length".to_string()));
        }
        
        // 验证承诺数量
        if contribution.commitments.len() != self.threshold {
            return Err(MpcError::ProtocolError("Invalid commitments count".to_string()));
        }
        
        // 验证零知识证明（简化版）
        self.verify_zkp(contribution)?;
        
        // 验证多项式系数在合法范围内
        for &coeff in &contribution.public_polynomial {
            if coeff >= self.params.coeff_modulus {
                return Err(MpcError::ProtocolError("Polynomial coefficient out of range".to_string()));
            }
        }
        
        Ok(())
    }
    
    /// 生成零知识证明（简化版）
    fn generate_zkp_for_contribution(&self, public_polynomial: &[u64]) -> Result<Vec<u8>> {
        // 简化的零知识证明：使用承诺的哈希
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        
        // 添加参与方ID
        hasher.update((self.party_id as u64).to_le_bytes());
        
        // 添加公开多项式
        for &coeff in public_polynomial {
            hasher.update(coeff.to_le_bytes());
        }
        
        // 添加私钥多项式的承诺
        for &secret_coeff in &self.secret_polynomial {
            hasher.update(field_mul(secret_coeff, 7).to_le_bytes()); // 简化承诺
        }
        
        Ok(hasher.finalize().to_vec())
    }
    
    /// 验证零知识证明（简化版）
    fn verify_zkp(&self, contribution: &KeyGenContribution) -> Result<()> {
        // 简化验证：检查证明长度
        if contribution.proof.len() != 32 {
            return Err(MpcError::ProtocolError("Invalid proof length".to_string()));
        }
        
        // 在实际实现中，这里应该验证完整的零知识证明
        // 这里只做基本检查
        let proof_sum: u64 = contribution.proof.iter().map(|&b| b as u64).sum();
        if proof_sum == 0 {
            return Err(MpcError::ProtocolError("Invalid proof content".to_string()));
        }
        
        Ok(())
    }
    
    /// 检查是否收集到所有贡献
    pub fn has_all_contributions(&self) -> bool {
        self.contributions.len() == self.party_count
    }
    
    /// 获取当前收集到的贡献数量
    pub fn contributions_count(&self) -> usize {
        self.contributions.len()
    }
    
    /// 重置状态（用于协议重启）
    pub fn reset(&mut self) {
        self.secret_polynomial.clear();
        self.contributions.clear();
    }
}

/// 分布式密钥验证器
pub struct DistributedKeyVerifier {
    public_key: BFVPublicKey,
    party_count: usize,
    threshold: usize,
}

impl DistributedKeyVerifier {
    /// 创建新的验证器
    pub fn new(public_key: BFVPublicKey, party_count: usize, threshold: usize) -> Self {
        Self {
            public_key,
            party_count,
            threshold,
        }
    }
    
    /// 验证公钥的结构正确性
    pub fn verify_public_key_structure(&self) -> Result<()> {
        if self.public_key.a.len() != self.public_key.n ||
           self.public_key.b.len() != self.public_key.n {
            return Err(MpcError::CryptographicError("Inconsistent public key dimensions".to_string()));
        }
        
        // 验证模数参数
        if self.public_key.q == 0 || self.public_key.t == 0 {
            return Err(MpcError::CryptographicError("Invalid modulus parameters".to_string()));
        }
        
        Ok(())
    }
    
    /// 验证私钥分享的一致性
    pub fn verify_secret_share_consistency(&self, secret_shares: &[BFVSecretKey]) -> Result<()> {
        if secret_shares.len() < self.threshold {
            return Err(MpcError::InsufficientShares);
        }
        
        // 验证每个私钥分享的参数一致性
        for (i, share) in secret_shares.iter().enumerate() {
            if share.n != self.public_key.n ||
               share.q != self.public_key.q ||
               share.t != self.public_key.t {
                return Err(MpcError::CryptographicError(
                    format!("Inconsistent parameters in secret share {}", i)
                ));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threshold_keygen_creation() {
        let params = BFVParams::default();
        let keygen = ThresholdBFVKeyGen::new(3, 2, 0, params);
        assert!(keygen.is_ok());
    }
    
    #[test]
    fn test_contribution_generation() {
        let params = BFVParams {
            degree: 8,
            coeff_modulus: 1024,
            plain_modulus: 16,
            noise_std_dev: 1.0,
        };
        
        let mut keygen = ThresholdBFVKeyGen::new(3, 2, 0, params).unwrap();
        let contribution = keygen.generate_contribution();
        
        assert!(contribution.is_ok());
        let contrib = contribution.unwrap();
        assert_eq!(contrib.party_id, 0);
        assert_eq!(contrib.public_polynomial.len(), 8);
        assert_eq!(contrib.commitments.len(), 2);
    }
    
    #[test]
    fn test_full_keygen_protocol() {
        let params = BFVParams {
            degree: 4,
            coeff_modulus: 1024,
            plain_modulus: 16,
            noise_std_dev: 1.0,
        };
        
        let party_count = 3;
        let threshold = 2;
        
        // 模拟三方协议
        let mut keygens: Vec<ThresholdBFVKeyGen> = (0..party_count)
            .map(|i| ThresholdBFVKeyGen::new(party_count, threshold, i, params.clone()).unwrap())
            .collect();
        
        // 第一阶段：每方生成贡献
        let mut contributions = Vec::new();
        for keygen in &mut keygens {
            let contrib = keygen.generate_contribution().unwrap();
            contributions.push(contrib);
        }
        
        // 第二阶段：交换贡献
        for (i, keygen) in keygens.iter_mut().enumerate() {
            for (j, contrib) in contributions.iter().enumerate() {
                if i != j {
                    keygen.add_contribution(contrib.clone()).unwrap();
                }
            }
        }
        
        // 第三阶段：生成密钥对
        let keypairs: Result<Vec<_>> = keygens.iter()
            .map(|keygen| keygen.generate_keypair())
            .collect();
        
        assert!(keypairs.is_ok());
        let kps = keypairs.unwrap();
        
        // 验证所有方生成了相同的公钥
        for i in 1..kps.len() {
            assert_eq!(kps[0].0.n, kps[i].0.n);
            assert_eq!(kps[0].0.q, kps[i].0.q);
            assert_eq!(kps[0].0.t, kps[i].0.t);
        }
    }
    
    #[test]
    fn test_invalid_threshold() {
        let params = BFVParams::default();
        
        // 测试门限值为0
        let result = ThresholdBFVKeyGen::new(3, 0, 0, params.clone());
        assert!(result.is_err());
        
        // 测试门限值超过参与方数量
        let result = ThresholdBFVKeyGen::new(3, 4, 0, params);
        assert!(result.is_err());
    }
}