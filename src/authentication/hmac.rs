//! # HMAC 实现 (Hash-based Message Authentication Code)
//! 
//! 本模块实现了基于哈希函数的消息认证码 (HMAC)，使用 SHA-256 作为底层哈希函数。
//! HMAC 是一种广泛使用的消息认证码算法，提供了强大的安全保证。
//! 
//! ## 算法特性
//! 
//! - **安全性**: 基于 SHA-256 的密码学强度
//! - **效率**: 适合大量数据的认证
//! - **标准化**: 符合 RFC 2104 标准
//! - **密钥长度**: 支持任意长度的密钥（推荐 32 字节）
//! - **标签长度**: 固定 32 字节输出
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::authentication::*;
//! 
//! let key = HMAC::generate_key();
//! let message = b"Hello, World!".to_vec();
//! let tag = HMAC::authenticate(&key, &message);
//! assert!(HMAC::verify(&key, &message, &tag));
//! ```

use crate::{MpcError, Result};
// use crate::secret_sharing::FIELD_PRIME; // Unused import
use super::{MessageAuthenticationCode, UnforgeableMac, SecureMac};
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

/// HMAC 密钥的推荐大小（字节）
const HMAC_KEY_SIZE: usize = 32;
/// HMAC 算法的块大小（字节），对应 SHA-256 的块大小
const HMAC_BLOCK_SIZE: usize = 64;
/// HMAC 标签的大小（字节），对应 SHA-256 的输出大小
const HMAC_TAG_SIZE: usize = 32;

/// HMAC 密钥结构
/// 
/// 封装了用于 HMAC 计算的密钥数据。密钥长度固定为 32 字节，
/// 提供了足够的安全强度。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HmacKey {
    /// 32 字节的密钥数据
    pub key: [u8; HMAC_KEY_SIZE],
}

/// HMAC 认证标签结构
/// 
/// 封装了 HMAC 算法生成的认证标签。标签长度固定为 32 字节，
/// 对应 SHA-256 哈希函数的输出长度。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HmacTag {
    /// 32 字节的认证标签
    pub tag: [u8; HMAC_TAG_SIZE],
}

/// HMAC 算法实现
/// 
/// 提供了完整的 HMAC-SHA256 实现，包括密钥生成、消息认证和验证功能。
/// 实现了 RFC 2104 标准中定义的 HMAC 算法。
pub struct HMAC;

impl MessageAuthenticationCode for HMAC {
    type Key = HmacKey;
    type Message = Vec<u8>;
    type Tag = HmacTag;
    
    /// 生成一个新的随机 HMAC 密钥
    /// 
    /// 使用密码学安全的随机数生成器生成 32 字节的随机密钥。
    /// 
    /// # 返回值
    /// 
    /// 返回新生成的 `HmacKey` 实例
    fn generate_key() -> Self::Key {
        let mut rng = thread_rng();
        let mut key = [0u8; HMAC_KEY_SIZE];
        for i in 0..HMAC_KEY_SIZE {
            key[i] = rng.gen();
        }
        HmacKey { key }
    }
    
    /// 为消息生成 HMAC 认证标签
    /// 
    /// 使用给定的密钥对消息进行 HMAC-SHA256 计算，生成认证标签。
    /// 
    /// # 参数
    /// 
    /// * `key` - 用于认证的 HMAC 密钥
    /// * `message` - 要认证的消息字节向量
    /// 
    /// # 返回值
    /// 
    /// 返回包含认证标签的 `HmacTag` 实例
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag {
        let tag = Self::compute_hmac(&key.key, message);
        HmacTag { tag }
    }
    
    /// 验证消息和认证标签的有效性
    /// 
    /// 重新计算消息的 HMAC 标签，并与提供的标签进行安全比较。
    /// 使用常时间比较算法防止时序攻击。
    /// 
    /// # 参数
    /// 
    /// * `key` - 用于验证的 HMAC 密钥
    /// * `message` - 要验证的消息
    /// * `tag` - 要验证的认证标签
    /// 
    /// # 返回值
    /// 
    /// 如果标签有效返回 `true`，否则返回 `false`
    fn verify(key: &Self::Key, message: &Self::Message, tag: &Self::Tag) -> bool {
        let computed_tag = Self::authenticate(key, message);
        Self::secure_compare(&computed_tag.tag, &tag.tag)
    }
}

impl Default for HMAC {
    /// 创建默认的 HMAC 实例
    fn default() -> Self {
        Self::new()
    }
}

impl HMAC {
    /// 创建新的 HMAC 实例
    /// 
    /// # 返回值
    /// 
    /// 返回新的 HMAC 实例
    pub fn new() -> Self {
        HMAC
    }
    
    /// 计算 HMAC-SHA256 标签
    /// 
    /// 实现标准的 HMAC 算法，按照 RFC 2104 规范：
    /// HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
    /// 
    /// # 参数
    /// 
    /// * `key` - 用于计算的密钥字节切片
    /// * `message` - 要认证的消息字节切片
    /// 
    /// # 返回值
    /// 
    /// 返回 32 字节的 HMAC 标签
    pub fn compute_hmac(key: &[u8], message: &[u8]) -> [u8; HMAC_TAG_SIZE] {
        let mut effective_key = [0u8; HMAC_BLOCK_SIZE];
        
        if key.len() > HMAC_BLOCK_SIZE {
            // Hash the key if it's too long
            let mut hasher = Sha256::new();
            hasher.update(key);
            let hash = hasher.finalize();
            effective_key[..32].copy_from_slice(&hash);
        } else {
            effective_key[..key.len()].copy_from_slice(key);
        }
        
        // Create inner and outer padding
        let mut i_key_pad = [0x36u8; HMAC_BLOCK_SIZE];
        let mut o_key_pad = [0x5cu8; HMAC_BLOCK_SIZE];
        
        for i in 0..HMAC_BLOCK_SIZE {
            i_key_pad[i] ^= effective_key[i];
            o_key_pad[i] ^= effective_key[i];
        }
        
        // Inner hash: H(K XOR ipad || message)
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&i_key_pad);
        inner_hasher.update(message);
        let inner_hash = inner_hasher.finalize();
        
        // Outer hash: H(K XOR opad || inner_hash)
        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&o_key_pad);
        outer_hasher.update(&inner_hash);
        let final_hash = outer_hasher.finalize();
        
        let mut result = [0u8; HMAC_TAG_SIZE];
        result.copy_from_slice(&final_hash);
        result
    }
    
    // Constant-time comparison to prevent timing attacks
    pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for i in 0..a.len() {
            result |= a[i] ^ b[i];
        }
        result == 0
    }
    
    pub fn compute_hmac_u64(key: &[u8], value: u64) -> [u8; HMAC_TAG_SIZE] {
        let message = value.to_le_bytes();
        Self::compute_hmac(key, &message)
    }
    
    pub fn verify_u64(key: &HmacKey, value: u64, tag: &HmacTag) -> bool {
        let computed_tag = Self::compute_hmac_u64(&key.key, value);
        Self::secure_compare(&computed_tag, &tag.tag)
    }
    
    pub fn batch_authenticate(key: &HmacKey, messages: &[Vec<u8>]) -> Vec<HmacTag> {
        messages.iter()
            .map(|msg| Self::authenticate(key, msg))
            .collect()
    }
    
    pub fn batch_verify(key: &HmacKey, messages: &[Vec<u8>], tags: &[HmacTag]) -> Result<bool> {
        if messages.len() != tags.len() {
            return Err(MpcError::AuthenticationError("Messages and tags arrays must have same length".to_string()));
        }
        
        for (msg, tag) in messages.iter().zip(tags.iter()) {
            if !Self::verify(key, msg, tag) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    // HMAC for secret shares
    pub fn authenticate_share(key: &HmacKey, share_value: u64, share_index: usize) -> HmacTag {
        let mut message = Vec::new();
        message.extend_from_slice(&share_value.to_le_bytes());
        message.extend_from_slice(&share_index.to_le_bytes());
        
        Self::authenticate(key, &message)
    }
    
    pub fn verify_share(key: &HmacKey, share_value: u64, share_index: usize, tag: &HmacTag) -> bool {
        let mut message = Vec::new();
        message.extend_from_slice(&share_value.to_le_bytes());
        message.extend_from_slice(&share_index.to_le_bytes());
        
        Self::verify(key, &message, tag)
    }
    
    // HMAC-based key derivation
    pub fn derive_key(master_key: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let mut derived_key = Vec::new();
        let mut counter = 1u32;
        
        while derived_key.len() < length {
            let mut message = Vec::new();
            message.extend_from_slice(info);
            message.extend_from_slice(&counter.to_le_bytes());
            
            let block = Self::compute_hmac(master_key, &message);
            derived_key.extend_from_slice(&block);
            counter += 1;
        }
        
        derived_key.truncate(length);
        derived_key
    }
    
    // PBKDF2-like key stretching using HMAC
    pub fn stretch_key(password: &[u8], salt: &[u8], iterations: u32) -> HmacKey {
        let mut derived_key = Vec::new();
        derived_key.extend_from_slice(salt);
        derived_key.extend_from_slice(&1u32.to_le_bytes());
        
        let mut result = Self::compute_hmac(password, &derived_key);
        let mut current = result;
        
        for _ in 1..iterations {
            current = Self::compute_hmac(password, &current);
            for i in 0..HMAC_TAG_SIZE {
                result[i] ^= current[i];
            }
        }
        
        HmacKey { key: result }
    }
}

impl UnforgeableMac for HMAC {}
impl SecureMac for HMAC {}

// HMAC variants for different hash functions
pub struct HMACSHA1;
pub struct HMACSHA512;

// Simplified implementations for demonstration
impl HMACSHA1 {
    pub fn compute_hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
        // This is a placeholder - in a real implementation, you'd use SHA-1
        let mut result = [0u8; 20];
        let sha256_result = HMAC::compute_hmac(key, message);
        result.copy_from_slice(&sha256_result[..20]);
        result
    }
}

impl HMACSHA512 {
    pub fn compute_hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
        // This is a placeholder - in a real implementation, you'd use SHA-512
        let mut result = [0u8; 64];
        let sha256_result = HMAC::compute_hmac(key, message);
        
        // Extend SHA-256 to SHA-512 size (simplified)
        result[..32].copy_from_slice(&sha256_result);
        result[32..64].copy_from_slice(&sha256_result);
        result
    }
}

// Tests moved to tests/authentication_tests.rs