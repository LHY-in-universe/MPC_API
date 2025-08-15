//! # SPDZ 认证分享 (SPDZ Authenticated Shares)
//! 
//! 实现了 SPDZ 协议中使用的认证秘密分享。认证分享是 SPDZ 协议的核心组件，
//! 它在传统秘密分享的基础上添加了消息认证码（MAC），以防止恶意参与方的攻击。
//! 
//! ## 核心概念
//! 
//! ### 认证分享结构
//! 每个认证分享包含：
//! - **分享值**: 秘密的 Shamir 分享
//! - **MAC 值**: 对分享值的消息认证码
//! - **参与方ID**: 持有该分享的参与方标识
//! - **分享ID**: 分享的唯一标识符
//! 
//! ### 安全性质
//! - **隐私性**: 单个分享不泄露秘密信息
//! - **完整性**: MAC 确保分享未被篡改
//! - **可验证性**: 可以验证分享的正确性
//! 
//! ## 支持的操作
//! 
//! - **线性运算**: 加法、减法、标量乘法
//! - **分享生成**: 将秘密转换为认证分享
//! - **秘密重构**: 从分享中恢复原始秘密
//! - **MAC 验证**: 验证分享的完整性

use super::*;
use crate::secret_sharing::{Share as SecretShare, ShamirSecretSharing, SecretSharing};
use crate::authentication::MessageAuthenticationCode;
use std::collections::HashMap;

/// SPDZ 分享结构
/// 
/// 表示 SPDZ 协议中的单个认证分享。每个分享包含秘密值的一部分
/// 以及相应的消息认证码，确保分享的完整性和真实性。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SPDZShare {
    /// 秘密分享值
    pub value: u64,
    /// 分享值的消息认证码
    pub mac: u64,
    /// 持有该分享的参与方ID
    pub party_id: PlayerId,
    /// 分享的唯一标识符
    pub share_id: ShareId,
}

/// 认证分享集合
/// 
/// 包含来自所有参与方的 SPDZ 分享，用于表示一个完整的
/// 认证秘密分享。可以从这些分享中重构原始秘密。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedShare {
    /// 来自各参与方的分享映射
    pub shares: HashMap<PlayerId, SPDZShare>,
    /// 全局 MAC 密钥（仅以分布式形式已知）
    pub global_mac_key: Option<u64>,
}

/// SPDZ 分享协议处理器
/// 
/// 管理 SPDZ 协议的执行，包括分享生成、运算处理、
/// MAC 验证等核心功能。每个参与方维护一个协议实例。
pub struct SPDZShareProtocol {
    /// 协议参数
    params: SPDZParams,
    /// 当前参与方持有的全局 MAC 密钥分享
    mac_key_share: u64,
    /// 与其他参与方通信使用的 HMAC 密钥
    hmac_keys: HashMap<PlayerId, HmacKey>,
}

impl SPDZShare {
    /// 创建新的 SPDZ 分享
    /// 
    /// 使用指定的分享值、MAC、参与方ID和分享ID创建一个新的 SPDZ 分享。
    /// 
    /// # 参数
    /// 
    /// * `value` - 秘密分享值
    /// * `mac` - 分享值的消息认证码
    /// * `party_id` - 持有该分享的参与方ID
    /// * `share_id` - 分享的唯一标识符
    /// 
    /// # 返回值
    /// 
    /// 返回新创建的 SPDZShare 实例
    pub fn new(value: u64, mac: u64, party_id: PlayerId, share_id: ShareId) -> Self {
        Self {
            value,
            mac,
            party_id,
            share_id,
        }
    }
    
    /// 添加两个 SPDZ 分享
    /// 
    /// 执行两个分享的加法运算，同时更新 MAC 值。
    /// 两个分享必须来自同一参与方。
    /// 
    /// # 参数
    /// 
    /// * `other` - 要添加的另一个分享
    /// 
    /// # 返回值
    /// 
    /// 成功时返回新的分享，失败时返回错误
    pub fn add(&self, other: &SPDZShare) -> Result<SPDZShare> {
        if self.party_id != other.party_id {
            return Err(MpcError::ProtocolError("Cannot add shares from different parties".to_string()));
        }
        
        Ok(SPDZShare {
            value: field_add(self.value, other.value),
            mac: field_add(self.mac, other.mac),
            party_id: self.party_id,
            share_id: self.share_id.wrapping_add(other.share_id),
        })
    }
    
    /// 减去两个 SPDZ 分享
    /// 
    /// 执行两个分享的减法运算，同时更新 MAC 值。
    /// 两个分享必须来自同一参与方。
    /// 
    /// # 参数
    /// 
    /// * `other` - 要减去的另一个分享
    /// 
    /// # 返回值
    /// 
    /// 成功时返回新的分享，失败时返回错误
    pub fn sub(&self, other: &SPDZShare) -> Result<SPDZShare> {
        if self.party_id != other.party_id {
            return Err(MpcError::ProtocolError("Cannot subtract shares from different parties".to_string()));
        }
        
        Ok(SPDZShare {
            value: field_sub(self.value, other.value),
            mac: field_sub(self.mac, other.mac),
            party_id: self.party_id,
            share_id: self.share_id.wrapping_add(other.share_id),
        })
    }
    
    /// 与公开常数相乘
    /// 
    /// 将分享值和 MAC 值都乘以一个公开的常数。
    /// 这是 SPDZ 协议中的基本操作之一。
    /// 
    /// # 参数
    /// 
    /// * `constant` - 要乘的公开常数
    /// * `_mac_key` - MAC 密钥（未使用）
    /// 
    /// # 返回值
    /// 
    /// 返回乘法结果的新分享
    pub fn mul_public(&self, constant: u64, _mac_key: u64) -> SPDZShare {
        SPDZShare {
            value: field_mul(self.value, constant),
            mac: field_mul(self.mac, constant),
            party_id: self.party_id,
            share_id: self.share_id,
        }
    }
    
    /// 验证 MAC 的有效性
    /// 
    /// 检查分享的 MAC 值是否与预期一致，以验证分享的完整性。
    /// 需要全局 MAC 密钥才能执行此操作。
    /// 
    /// # 参数
    /// 
    /// * `global_mac_key` - 全局 MAC 密钥
    /// 
    /// # 返回值
    /// 
    /// 如果 MAC 有效返回 `true`，否则返回 `false`
    pub fn verify_mac(&self, global_mac_key: u64) -> bool {
        let expected_mac = field_mul(self.value, global_mac_key);
        self.mac == expected_mac
    }
}

impl Default for AuthenticatedShare {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticatedShare {
    pub fn new() -> Self {
        Self {
            shares: HashMap::new(),
            global_mac_key: None,
        }
    }
    
    pub fn add_share(&mut self, party_id: PlayerId, share: SPDZShare) {
        self.shares.insert(party_id, share);
    }
    
    pub fn get_share(&self, party_id: PlayerId) -> Option<&SPDZShare> {
        self.shares.get(&party_id)
    }
    
    // Reconstruct the secret (requires shares from all parties)
    pub fn reconstruct(&self, threshold: usize) -> Result<u64> {
        if self.shares.len() < threshold {
            return Err(MpcError::InsufficientShares);
        }
        
        // Convert to secret shares for reconstruction
        let mut secret_shares = Vec::new();
        for (party_id, spdz_share) in &self.shares {
            let share = SecretShare {
                x: *party_id as u64,
                y: spdz_share.value,
            };
            secret_shares.push(share);
        }
        
        ShamirSecretSharing::reconstruct(&secret_shares, threshold)
    }
    
    // Verify all MACs (requires global MAC key)
    pub fn verify_all_macs(&self, global_mac_key: u64) -> bool {
        for share in self.shares.values() {
            if !share.verify_mac(global_mac_key) {
                return false;
            }
        }
        true
    }
}

impl SPDZShareProtocol {
    pub fn new(params: SPDZParams) -> Result<Self> {
        if !params.is_valid() {
            return Err(MpcError::ProtocolError("Invalid SPDZ parameters".to_string()));
        }
        
        // Generate MAC key share
        let mut rng = thread_rng();
        let mac_key_share = rng.gen_range(0..FIELD_PRIME);
        
        // Generate HMAC keys for communication
        let mut hmac_keys = HashMap::new();
        for party_id in 0..params.num_parties {
            if party_id != params.party_id {
                hmac_keys.insert(party_id, HMAC::generate_key());
            }
        }
        
        Ok(Self {
            params,
            mac_key_share,
            hmac_keys,
        })
    }
    
    // Share a secret value with authentication
    pub fn share_secret(&self, secret: u64) -> Result<Vec<SPDZShare>> {
        // Create secret shares using the trait method
        let secret_shares = ShamirSecretSharing::share(
            &secret, 
            self.params.threshold,
            self.params.num_parties 
        )?;
        
        let mut spdz_shares = Vec::new();
        let mut rng = thread_rng();
        let share_id = rng.gen();
        
        for share in secret_shares {
            // Compute MAC: MAC_i = alpha_i * value + r_i
            // where alpha_i is this party's share of the MAC key
            let mac = field_add(
                field_mul(self.mac_key_share, share.y),
                rng.gen_range(0..FIELD_PRIME)  // Random mask
            );
            
            let spdz_share = SPDZShare::new(
                share.y,
                mac,
                share.x as PlayerId,
                share_id,
            );
            
            spdz_shares.push(spdz_share);
        }
        
        Ok(spdz_shares)
    }
    
    // Input a private value (share it among all parties)
    pub fn input(&self, value: u64) -> Result<AuthenticatedShare> {
        let spdz_shares = self.share_secret(value)?;
        
        let mut authenticated_share = AuthenticatedShare::new();
        for share in spdz_shares {
            authenticated_share.add_share(share.party_id, share);
        }
        
        Ok(authenticated_share)
    }
    
    // Add two authenticated shares
    pub fn add(&self, a: &AuthenticatedShare, b: &AuthenticatedShare) -> Result<AuthenticatedShare> {
        let mut result = AuthenticatedShare::new();
        
        for party_id in 0..self.params.num_parties {
            if let (Some(share_a), Some(share_b)) = (a.get_share(party_id), b.get_share(party_id)) {
                let sum_share = share_a.add(share_b)?;
                result.add_share(party_id, sum_share);
            }
        }
        
        Ok(result)
    }
    
    // Subtract two authenticated shares
    pub fn sub(&self, a: &AuthenticatedShare, b: &AuthenticatedShare) -> Result<AuthenticatedShare> {
        let mut result = AuthenticatedShare::new();
        
        for party_id in 0..self.params.num_parties {
            if let (Some(share_a), Some(share_b)) = (a.get_share(party_id), b.get_share(party_id)) {
                let diff_share = share_a.sub(share_b)?;
                result.add_share(party_id, diff_share);
            }
        }
        
        Ok(result)
    }
    
    // Multiply by public constant
    pub fn mul_public(&self, share: &AuthenticatedShare, constant: u64) -> AuthenticatedShare {
        let mut result = AuthenticatedShare::new();
        
        for party_id in 0..self.params.num_parties {
            if let Some(spdz_share) = share.get_share(party_id) {
                let mul_share = spdz_share.mul_public(constant, self.mac_key_share);
                result.add_share(party_id, mul_share);
            }
        }
        
        result
    }
    
    // Open a shared value (reveal the secret)
    pub fn open(&self, share: &AuthenticatedShare) -> Result<u64> {
        // First verify MACs if global MAC key is available
        if let Some(global_mac_key) = share.global_mac_key {
            if !share.verify_all_macs(global_mac_key) {
                return Err(MpcError::AuthenticationError("MAC verification failed".to_string()));
            }
        }
        
        // Reconstruct the secret
        share.reconstruct(self.params.threshold)
    }
    
    // Generate a random shared value
    pub fn random(&self) -> Result<AuthenticatedShare> {
        let mut rng = thread_rng();
        let random_value = rng.gen_range(0..FIELD_PRIME);
        self.input(random_value)
    }
    
    // Generate multiple random shared values
    pub fn random_batch(&self, count: usize) -> Result<Vec<AuthenticatedShare>> {
        let mut batch = Vec::new();
        for _ in 0..count {
            batch.push(self.random()?);
        }
        Ok(batch)
    }
    
    // Check if a shared value equals zero (without revealing the value)
    pub fn is_zero(&self, share: &AuthenticatedShare) -> Result<bool> {
        // This would normally involve a more complex zero-knowledge proof
        // For this implementation, we'll do a simplified check
        let opened = self.open(share)?;
        Ok(opened == 0)
    }
    
    // Batch operations for efficiency
    pub fn add_batch(
        &self, 
        shares_a: &[AuthenticatedShare], 
        shares_b: &[AuthenticatedShare]
    ) -> Result<Vec<AuthenticatedShare>> {
        if shares_a.len() != shares_b.len() {
            return Err(MpcError::ProtocolError("Batch arrays must have same length".to_string()));
        }
        
        let mut results = Vec::new();
        for (a, b) in shares_a.iter().zip(shares_b.iter()) {
            results.push(self.add(a, b)?);
        }
        
        Ok(results)
    }
    
    pub fn mul_public_batch(
        &self, 
        shares: &[AuthenticatedShare], 
        constants: &[u64]
    ) -> Result<Vec<AuthenticatedShare>> {
        if shares.len() != constants.len() {
            return Err(MpcError::ProtocolError("Batch arrays must have same length".to_string()));
        }
        
        let mut results = Vec::new();
        for (share, &constant) in shares.iter().zip(constants.iter()) {
            results.push(self.mul_public(share, constant));
        }
        
        Ok(results)
    }
    
    // Compute linear combination of shares
    pub fn linear_combination(
        &self,
        shares: &[AuthenticatedShare],
        coefficients: &[u64],
    ) -> Result<AuthenticatedShare> {
        if shares.is_empty() || shares.len() != coefficients.len() {
            return Err(MpcError::ProtocolError("Invalid linear combination parameters".to_string()));
        }
        
        let mut result = self.mul_public(&shares[0], coefficients[0]);
        
        for (share, &coeff) in shares.iter().zip(coefficients.iter()).skip(1) {
            let term = self.mul_public(share, coeff);
            result = self.add(&result, &term)?;
        }
        
        Ok(result)
    }
    
    // Get this party's MAC key share
    pub fn get_mac_key_share(&self) -> u64 {
        self.mac_key_share
    }
    
    // Get communication keys
    pub fn get_hmac_key(&self, party_id: PlayerId) -> Option<&HmacKey> {
        self.hmac_keys.get(&party_id)
    }
}

