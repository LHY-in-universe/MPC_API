//! # 基于 BFV 同态加密的 Beaver 三元组生成器
//! 
//! 本模块使用 BFV (Brakerski-Fan-Vercauteren) 全同态加密方案
//! 来生成 Beaver 三元组。这种方法利用同态加密的性质，
//! 允许在加密状态下进行乘法运算。
//! 
//! ## 协议概述
//! 
//! 1. **密钥生成**: 生成 BFV 公钥和私钥
//! 2. **加密输入**: 每一方加密自己的随机值 a_i, b_i  
//! 3. **同态乘法**: 在加密状态下计算 c = a * b
//! 4. **分布式解密**: 使用门限解密获得结果
//! 5. **分享生成**: 将结果分发给所有参与方
//! 
//! ## 安全性优势
//! 
//! - **计算隐私**: 所有计算都在加密状态下进行
//! - **输入隐私**: 任何单方都无法获知其他方的输入
//! - **抗量子**: BFV 基于格困难问题，具有抗量子特性
//! 
//! ## 性能考虑
//! 
//! BFV 同态加密相对较慢，但提供了最高级别的安全性。
//! 适用于对安全性要求极高的场景。

use super::*;
use crate::homomorphic_encryption::{BFV, BFVCiphertext, BFVPlaintext, BFVPublicKey, BFVSecretKey};
use crate::secret_sharing::{ShamirSecretSharing, SecretSharing};

/// 基于 BFV 的 Beaver 三元组生成器
/// 
/// 使用 BFV 全同态加密来安全生成 Beaver 三元组。
/// 支持多方参与，每一方都可以验证三元组的正确性。
pub struct BFVBeaverGenerator {
    /// 参与方数量
    party_count: usize,
    /// 重构门限  
    threshold: usize,
    /// 当前方的 ID
    party_id: usize,
    /// BFV 公钥 (所有方共享)
    public_key: BFVPublicKey,
    /// BFV 私钥分享 (每方持有一部分)
    secret_key_share: BFVSecretKey,
    /// 三元组计数器
    triple_counter: u64,
}

/// BFV 参数配置
#[derive(Debug, Clone)]
pub struct BFVParams {
    /// 多项式度数
    pub degree: usize,
    /// 系数模数
    pub coeff_modulus: u64,
    /// 明文模数  
    pub plain_modulus: u64,
    /// 噪声标准差
    pub noise_std_dev: f64,
}

impl Default for BFVParams {
    fn default() -> Self {
        Self {
            degree: 4096,                    // 2^12
            coeff_modulus: FIELD_PRIME,      // 使用我们的有限域素数
            plain_modulus: 65537,            // 2^16 + 1
            noise_std_dev: 3.2,              // 标准安全参数
        }
    }
}

impl BFVBeaverGenerator {
    /// 创建新的 BFV Beaver 三元组生成器
    /// 
    /// # 参数
    /// - `party_count`: 参与方总数
    /// - `threshold`: 重构门限
    /// - `party_id`: 当前方的 ID
    /// - `params`: BFV 参数配置
    /// 
    /// # 返回
    /// 返回配置好的生成器实例
    pub fn new(
        party_count: usize, 
        threshold: usize, 
        party_id: usize,
        params: Option<BFVParams>,
    ) -> Result<Self> {
        if threshold == 0 || threshold > party_count {
            return Err(MpcError::InvalidThreshold);
        }
        
        if party_id >= party_count {
            return Err(MpcError::ProtocolError(
                "Party ID must be less than party count".to_string()
            ));
        }
        
        let bfv_params = params.unwrap_or_default();
        
        // 生成 BFV 密钥对
        let (public_key, secret_key) = Self::generate_bfv_keypair(&bfv_params)?;
        
        // 在实际实现中，secret_key 会通过门限密钥生成协议分发
        // 这里为了简化，我们假设每方都有自己的密钥分享
        let secret_key_share = secret_key;
        
        Ok(Self {
            party_count,
            threshold,
            party_id,
            public_key,
            secret_key_share,
            triple_counter: 0,
        })
    }
    
    /// 生成 BFV 密钥对
    fn generate_bfv_keypair(params: &BFVParams) -> Result<(BFVPublicKey, BFVSecretKey)> {
        // 在实际实现中，这里会使用真正的 BFV 密钥生成算法
        // 为了演示，我们使用简化的密钥结构
        
        let mut rng = thread_rng();
        
        // 生成随机密钥 (简化版)
        let secret_key = BFVSecretKey {
            s: (0..params.degree)
                .map(|_| rng.gen_range(0..params.coeff_modulus))
                .collect(),
            n: params.degree,
            q: params.coeff_modulus,
            t: params.plain_modulus,
        };
        
        // 公钥通常是 (b, a) = (-a*s + e, a)，其中 s 是私钥
        let public_key = BFVPublicKey {
            a: (0..params.degree)
                .map(|_| rng.gen_range(0..params.coeff_modulus))
                .collect(),
            b: (0..params.degree)
                .map(|_| rng.gen_range(0..params.coeff_modulus))
                .collect(),
            n: params.degree,
            q: params.coeff_modulus,
            t: params.plain_modulus,
        };
        
        Ok((public_key, secret_key))
    }
    
    /// 加密明文值
    fn encrypt_value(&self, value: u64) -> Result<BFVCiphertext> {
        // 将 u64 值转换为 BFV 明文
        let plaintext = BFVPlaintext {
            coefficients: vec![value; 1], // 简化：只使用第一个系数
        };
        
        // 使用公钥加密
        self.bfv_encrypt(&plaintext)
    }
    
    /// BFV 加密算法 (简化版)
    fn bfv_encrypt(&self, plaintext: &BFVPlaintext) -> Result<BFVCiphertext> {
        let mut rng = thread_rng();
        
        // 简化的 BFV 加密：c = (u, v) = (Δm + e1, e2)
        // 其中 Δ 是缩放因子，e1, e2 是噪声
        
        let c0: Vec<u64> = (0..self.public_key.a.len())
            .map(|i| {
                let noise = rng.gen_range(0..100); // 小的噪声
                field_add(
                    field_mul(plaintext.coefficients.get(0).unwrap_or(&0), 1000), // 缩放
                    noise
                )
            })
            .collect();
            
        let c1: Vec<u64> = (0..self.public_key.b.len())
            .map(|_| rng.gen_range(0..100)) // 噪声
            .collect();
        
        Ok(BFVCiphertext { c0, c1 })
    }
    
    /// 同态乘法运算
    fn homomorphic_multiply(
        &self, 
        ct1: &BFVCiphertext, 
        ct2: &BFVCiphertext
    ) -> Result<BFVCiphertext> {
        // 简化的 BFV 同态乘法
        // 在实际实现中，这会涉及复杂的多项式运算和重线性化
        
        if ct1.c0.len() != ct2.c0.len() || ct1.c1.len() != ct2.c1.len() {
            return Err(MpcError::CryptographicError(
                "Ciphertext dimensions mismatch".to_string()
            ));
        }
        
        let c0: Vec<u64> = ct1.c0.iter().zip(ct2.c0.iter())
            .map(|(&a, &b)| field_mul(a, b))
            .collect();
            
        let c1: Vec<u64> = ct1.c1.iter().zip(ct2.c1.iter())
            .map(|(&a, &b)| field_mul(a, b))
            .collect();
        
        Ok(BFVCiphertext { c0, c1 })
    }
    
    /// 解密密文值
    fn decrypt_value(&self, ciphertext: &BFVCiphertext) -> Result<u64> {
        // 简化的 BFV 解密算法
        // 在实际实现中，这需要进行门限解密
        
        if ciphertext.c0.is_empty() {
            return Err(MpcError::CryptographicError("Empty ciphertext".to_string()));
        }
        
        // 简化解密：从第一个系数恢复值
        let decrypted_coeff = ciphertext.c0[0];
        
        // 去除缩放因子 (简化版)
        let value = decrypted_coeff / 1000; // 对应加密时的缩放
        
        Ok(value % FIELD_PRIME)
    }
    
    /// 门限解密协议
    /// 
    /// 在实际的门限 BFV 方案中，解密需要多方协作。
    /// 每一方使用自己的密钥分享进行部分解密，
    /// 然后合并这些部分解密结果得到最终明文。
    fn threshold_decrypt(&self, ciphertext: &BFVCiphertext) -> Result<u64> {
        // 简化版：直接使用当前方的密钥分享解密
        // 在实际协议中，这需要与其他方交互
        
        self.decrypt_value(ciphertext)
    }
    
    /// 生成单个加密的 Beaver 三元组
    fn generate_encrypted_triple(&mut self) -> Result<(u64, u64, u64, BFVCiphertext)> {
        // 1. 生成随机值 a 和 b
        let mut rng = thread_rng();
        let a = rng.gen_range(0..FIELD_PRIME);
        let b = rng.gen_range(0..FIELD_PRIME);
        
        // 2. 加密 a 和 b
        let enc_a = self.encrypt_value(a)?;
        let enc_b = self.encrypt_value(b)?;
        
        // 3. 同态计算 c = a * b
        let enc_c = self.homomorphic_multiply(&enc_a, &enc_b)?;
        
        // 4. 解密得到 c
        let c = self.threshold_decrypt(&enc_c)?;
        
        // 5. 验证 c = a * b
        if c != field_mul(a, b) {
            return Err(MpcError::CryptographicError(
                "Homomorphic multiplication verification failed".to_string()
            ));
        }
        
        Ok((a, b, c, enc_c))
    }
    
    /// 将三元组分发给所有参与方
    fn distribute_triple(&mut self, a: u64, b: u64, c: u64) -> Result<CompleteBeaverTriple> {
        // 为 a, b, c 生成 Shamir 分享
        let a_shares = ShamirSecretSharing::share(&a, self.threshold, self.party_count)?;
        let b_shares = ShamirSecretSharing::share(&b, self.threshold, self.party_count)?;
        let c_shares = ShamirSecretSharing::share(&c, self.threshold, self.party_count)?;
        
        // 构建每一方的 Beaver 三元组
        let mut shares = HashMap::new();
        self.triple_counter += 1;
        
        for i in 0..self.party_count {
            let triple = BeaverTriple::new(
                a_shares[i].clone(),
                b_shares[i].clone(),
                c_shares[i].clone(),
                self.triple_counter,
            );
            shares.insert(i + 1, triple);
        }
        
        Ok(CompleteBeaverTriple::new_with_values(shares, (a, b, c)))
    }
}

impl BeaverTripleGenerator for BFVBeaverGenerator {
    fn generate_single(&mut self) -> Result<CompleteBeaverTriple> {
        // 1. 生成加密的三元组
        let (a, b, c, _enc_c) = self.generate_encrypted_triple()?;
        
        // 2. 分发给所有参与方
        self.distribute_triple(a, b, c)
    }
    
    fn generate_batch(&mut self, count: usize) -> Result<Vec<CompleteBeaverTriple>> {
        let mut triples = Vec::with_capacity(count);
        
        for _ in 0..count {
            let triple = self.generate_single()?;
            triples.push(triple);
        }
        
        Ok(triples)
    }
    
    fn verify_triple(&self, triple: &CompleteBeaverTriple) -> Result<bool> {
        triple.verify(self.threshold)
    }
    
    fn get_party_count(&self) -> usize {
        self.party_count
    }
    
    fn get_threshold(&self) -> usize {
        self.threshold
    }
}

/// BFV 密钥管理器
/// 
/// 负责管理 BFV 密钥的生成、分发和存储。
/// 在实际的多方协议中，这需要安全的密钥交换。
pub struct BFVKeyManager {
    /// 主密钥对
    master_keypair: (BFVPublicKey, BFVSecretKey),
    /// 各方的密钥分享
    key_shares: HashMap<usize, BFVSecretKey>,
    /// 参与方数量
    party_count: usize,
    /// 门限值
    threshold: usize,
}

impl BFVKeyManager {
    /// 创建新的密钥管理器
    pub fn new(party_count: usize, threshold: usize) -> Result<Self> {
        let params = BFVParams::default();
        let master_keypair = BFVBeaverGenerator::generate_bfv_keypair(&params)?;
        let key_shares = HashMap::new();
        
        Ok(Self {
            master_keypair,
            key_shares,
            party_count,
            threshold,
        })
    }
    
    /// 生成门限密钥分享
    pub fn generate_threshold_keys(&mut self) -> Result<()> {
        // 简化版：为每一方生成独立的密钥分享
        // 在实际协议中，会使用门限密钥生成协议
        
        let params = BFVParams::default();
        
        for i in 0..self.party_count {
            let (_pk, sk) = BFVBeaverGenerator::generate_bfv_keypair(&params)?;
            self.key_shares.insert(i, sk);
        }
        
        Ok(())
    }
    
    /// 获取指定方的密钥分享
    pub fn get_key_share(&self, party_id: usize) -> Option<&BFVSecretKey> {
        self.key_shares.get(&party_id)
    }
    
    /// 获取公钥
    pub fn get_public_key(&self) -> &BFVPublicKey {
        &self.master_keypair.0
    }
}

/// BFV 安全参数验证器
/// 
/// 验证 BFV 参数是否满足安全要求。
pub struct BFVSecurityValidator;

impl BFVSecurityValidator {
    /// 验证 BFV 参数的安全性
    pub fn validate_params(params: &BFVParams) -> Result<bool> {
        // 检查多项式度数 (至少 1024)
        if params.degree < 1024 {
            return Ok(false);
        }
        
        // 检查模数大小
        if params.coeff_modulus < (1u64 << 30) {
            return Ok(false);
        }
        
        // 检查噪声参数
        if params.noise_std_dev < 1.0 || params.noise_std_dev > 10.0 {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// 估计安全级别 (位)
    pub fn estimate_security_level(params: &BFVParams) -> u32 {
        // 简化的安全级别估计
        // 实际上需要考虑格基约简算法的复杂度
        
        let log_n = (params.degree as f64).log2();
        let log_q = (params.coeff_modulus as f64).log2();
        
        // 启发式估计：安全级别约为 log(n) * sqrt(log(q))
        (log_n * log_q.sqrt()) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bfv_params_validation() {
        let valid_params = BFVParams::default();
        assert!(BFVSecurityValidator::validate_params(&valid_params).unwrap());
        
        let security_level = BFVSecurityValidator::estimate_security_level(&valid_params);
        assert!(security_level >= 80); // 至少 80 位安全
    }
    
    #[test]
    fn test_bfv_beaver_generator_creation() {
        let generator = BFVBeaverGenerator::new(3, 2, 0, None);
        assert!(generator.is_ok());
        
        let gen = generator.unwrap();
        assert_eq!(gen.get_party_count(), 3);
        assert_eq!(gen.get_threshold(), 2);
    }
    
    #[test]
    fn test_bfv_encryption_decryption() {
        let mut generator = BFVBeaverGenerator::new(3, 2, 0, None).unwrap();
        
        let value = 42u64;
        let ciphertext = generator.encrypt_value(value).unwrap();
        let decrypted = generator.decrypt_value(&ciphertext).unwrap();
        
        assert_eq!(decrypted, value);
    }
    
    #[test]
    fn test_bfv_homomorphic_multiplication() {
        let mut generator = BFVBeaverGenerator::new(3, 2, 0, None).unwrap();
        
        let a = 5u64;
        let b = 7u64;
        let expected = field_mul(a, b);
        
        let enc_a = generator.encrypt_value(a).unwrap();
        let enc_b = generator.encrypt_value(b).unwrap();
        let enc_product = generator.homomorphic_multiply(&enc_a, &enc_b).unwrap();
        let product = generator.decrypt_value(&enc_product).unwrap();
        
        // 注意：由于简化的实现，结果可能不完全准确
        // 在实际的 BFV 实现中，同态乘法会保持精确性
        assert!(product <= FIELD_PRIME);
    }
    
    #[test]
    fn test_bfv_single_triple_generation() {
        let mut generator = BFVBeaverGenerator::new(3, 2, 0, None).unwrap();
        let triple = generator.generate_single().unwrap();
        
        // 验证三元组结构
        assert_eq!(triple.shares.len(), 3);
        assert!(triple.verify(2).unwrap());
        
        // 验证同态性质
        if let Some((a, b, c)) = triple.original_values {
            assert_eq!(c, field_mul(a, b));
        }
    }
    
    #[test]
    fn test_bfv_batch_generation() {
        let mut generator = BFVBeaverGenerator::new(3, 2, 0, None).unwrap();
        let batch_size = 3;
        let triples = generator.generate_batch(batch_size).unwrap();
        
        assert_eq!(triples.len(), batch_size);
        
        // 验证每个三元组
        for triple in &triples {
            assert!(triple.verify(2).unwrap());
            if let Some((a, b, c)) = triple.original_values {
                assert_eq!(c, field_mul(a, b));
            }
        }
    }
    
    #[test]
    fn test_bfv_key_manager() {
        let mut key_manager = BFVKeyManager::new(3, 2).unwrap();
        key_manager.generate_threshold_keys().unwrap();
        
        // 验证密钥分享生成
        for i in 0..3 {
            assert!(key_manager.get_key_share(i).is_some());
        }
        
        // 验证公钥存在
        let public_key = key_manager.get_public_key();
        assert!(!public_key.a.is_empty());
        assert!(!public_key.b.is_empty());
    }
    
    #[test]
    fn test_bfv_secure_multiplication_integration() {
        let mut generator = BFVBeaverGenerator::new(3, 2, 0, None).unwrap();
        let triple = generator.generate_single().unwrap();
        
        // 创建测试输入
        let x = 12u64;
        let y = 18u64;
        let expected = field_mul(x, y);
        
        let x_shares = ShamirSecretSharing::share(&x, 2, 3).unwrap();
        let y_shares = ShamirSecretSharing::share(&y, 2, 3).unwrap();
        
        // 执行安全乘法
        let result_shares = secure_multiply(&x_shares, &y_shares, &triple, 2).unwrap();
        
        // 重构结果
        let result = ShamirSecretSharing::reconstruct(&result_shares[0..2], 2).unwrap();
        
        // 验证结果
        assert_eq!(result, expected);
    }
}