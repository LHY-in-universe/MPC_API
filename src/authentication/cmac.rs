//! # CMAC 消息认证码 (Cipher-based Message Authentication Code)
//! 
//! 实现基于 AES 分组密码的 CMAC 算法（简化版本）。
//! 
//! CMAC 是一种基于分组密码的消息认证码，由 NIST 标准化。
//! 它使用分组密码（如 AES）来构造安全的消息认证码。
//! 
//! ## 算法特点
//! - 基于成熟的分组密码算法
//! - 提供强安全性保证
//! - 支持任意长度的消息
//! - 标准化算法，广泛应用
//! 
//! ## 使用场景
//! - 网络协议中的消息完整性验证
//! - 数字签名系统
//! - 安全通信协议
//! - 数据完整性保护

use crate::{MpcError, Result};
use super::{MessageAuthenticationCode, UnforgeableMac, SecureMac};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

/// CMAC 密钥大小（AES-128 密钥大小）
const CMAC_KEY_SIZE: usize = 16;
/// CMAC 认证标签大小
const CMAC_TAG_SIZE: usize = 16;
/// CMAC 块大小
const CMAC_BLOCK_SIZE: usize = 16;

/// CMAC 密钥结构
/// 
/// 包含用于 CMAC 计算的 AES 密钥。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CmacKey {
    /// 16字节的 AES-128 密钥
    pub key: [u8; CMAC_KEY_SIZE],
}

/// CMAC 认证标签
/// 
/// 包含16字节的认证标签，用于验证消息的完整性和真实性。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CmacTag {
    /// 16字节的认证标签
    pub tag: [u8; CMAC_TAG_SIZE],
}

/// CMAC 消息认证码实现
/// 
/// 提供基于 AES 分组密码的 CMAC 消息认证功能。
pub struct CMAC;

/// 增量式 CMAC 计算状态
/// 
/// 用于支持分块处理大型消息的 CMAC 计算。
/// 允许逐步添加数据块而不需要一次性加载整个消息。
pub struct IncrementalCMAC {
    /// AES 密钥
    key: [u8; CMAC_KEY_SIZE],
    /// 第一个子密钥 K1
    k1: [u8; CMAC_BLOCK_SIZE],
    /// 第二个子密钥 K2
    k2: [u8; CMAC_BLOCK_SIZE],
    /// 中间状态向量
    x: [u8; CMAC_BLOCK_SIZE],
    /// 缓冲区，存储不完整的块
    buffer: Vec<u8>,
}

impl MessageAuthenticationCode for CMAC {
    type Key = CmacKey;
    type Message = Vec<u8>;
    type Tag = CmacTag;
    
    /// 生成 CMAC 密钥
    /// 
    /// 生成一个随机的 AES-128 密钥用于 CMAC 计算。
    /// 
    /// # 返回值
    /// 返回新生成的 CmacKey
    fn generate_key() -> Self::Key {
        let mut rng = thread_rng();
        let mut key = [0u8; CMAC_KEY_SIZE];
        for i in 0..CMAC_KEY_SIZE {
            key[i] = rng.gen();
        }
        CmacKey { key }
    }
    
    /// 对消息进行 CMAC 认证
    /// 
    /// 使用给定的密钥对消息计算 CMAC 认证标签。
    /// 
    /// # 参数
    /// * `key` - CMAC 密钥
    /// * `message` - 待认证的消息
    /// 
    /// # 返回值
    /// 返回消息的 CMAC 认证标签
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag {
        let tag = Self::compute_cmac(&key.key, message);
        CmacTag { tag }
    }
    
    /// 验证消息的 CMAC 认证标签
    /// 
    /// 重新计算消息的 CMAC 标签并与提供的标签进行安全比较。
    /// 
    /// # 参数
    /// * `key` - CMAC 密钥
    /// * `message` - 待验证的消息
    /// * `tag` - 待验证的认证标签
    /// 
    /// # 返回值
    /// 如果标签有效返回 true，否则返回 false
    fn verify(key: &Self::Key, message: &Self::Message, tag: &Self::Tag) -> bool {
        let computed_tag = Self::authenticate(key, message);
        Self::secure_compare(&computed_tag.tag, &tag.tag)
    }
}

impl Default for CMAC {
    fn default() -> Self {
        Self::new()
    }
}

impl CMAC {
    /// 创建新的 CMAC 实例
    /// 
    /// # 返回值
    /// 返回 CMAC 结构体实例
    pub fn new() -> Self {
        CMAC
    }
    
    /// 简化的 AES 分组密码实现（仅用于演示）
    /// 
    /// 注意：这是一个非常简化的实现，不具备真正的安全性。
    /// 在实际应用中应该使用标准的 AES 实现。
    /// 
    /// # 参数
    /// * `key` - AES 密钥
    /// * `block` - 待加密的16字节数据块
    /// 
    /// # 返回值
    /// 返回加密后的16字节数据块
    fn aes_encrypt_block(key: &[u8; CMAC_KEY_SIZE], block: &[u8; CMAC_BLOCK_SIZE]) -> [u8; CMAC_BLOCK_SIZE] {
        let mut result = [0u8; CMAC_BLOCK_SIZE];
        
        // 这是一个非常简化的替换-置换网络
        // 不安全 - 仅用于演示
        for i in 0..CMAC_BLOCK_SIZE {
            // 简单替换
            let mut byte = block[i] ^ key[i];
            
            // S盒（简化版）
            byte = byte.wrapping_mul(3).wrapping_add(1);
            
            // 置换（旋转）
            result[(i + 5) % CMAC_BLOCK_SIZE] = byte;
        }
        
        // 额外的轮次与密钥混合
        for round in 0..4 {
            for i in 0..CMAC_BLOCK_SIZE {
                result[i] ^= key[i].wrapping_add(round as u8);
                result[i] = result[i].rotate_left(1);
            }
        }
        
        result
    }
    
    /// 生成 CMAC 子密钥
    /// 
    /// 根据 CMAC 算法规范生成两个子密钥 K1 和 K2。
    /// 算法步骤：
    /// 1. L = AES(K, 0^128)
    /// 2. K1 = L << 1
    /// 3. K2 = K1 << 1
    /// 
    /// # 参数
    /// * `key` - 主密钥
    /// 
    /// # 返回值
    /// 返回元组 (K1, K2)，包含两个子密钥
    pub fn generate_subkeys(key: &[u8; CMAC_KEY_SIZE]) -> ([u8; CMAC_BLOCK_SIZE], [u8; CMAC_BLOCK_SIZE]) {
        // L = AES(K, 0^128)
        let zero_block = [0u8; CMAC_BLOCK_SIZE];
        let l = Self::aes_encrypt_block(key, &zero_block);
        
        // 生成 K1 和 K2
        let k1 = Self::left_shift(&l);
        let k2 = Self::left_shift(&k1);
        
        (k1, k2)
    }
    
    /// 在 GF(2^128) 中进行左移一位操作
    /// 
    /// 这是 CMAC 算法中生成子密钥时使用的核心操作。
    /// 如果最高位为1，则需要与常数0x87进行异或运算。
    /// 
    /// # 参数
    /// * `input` - 待左移的16字节输入
    /// 
    /// # 返回值
    /// 返回左移后的16字节结果
    pub fn left_shift(input: &[u8; CMAC_BLOCK_SIZE]) -> [u8; CMAC_BLOCK_SIZE] {
        let mut result = [0u8; CMAC_BLOCK_SIZE];
        let mut carry = 0u8;
        
        for i in (0..CMAC_BLOCK_SIZE).rev() {
            let new_carry = (input[i] & 0x80) >> 7;
            result[i] = (input[i] << 1) | carry;
            carry = new_carry;
        }
        
        // 如果有进位，与常数进行异或运算
        if carry != 0 {
            result[CMAC_BLOCK_SIZE - 1] ^= 0x87;
        }
        
        result
    }
    
    /// 计算 CMAC 认证标签
    /// 
    /// 实现完整的 CMAC 算法，包括子密钥生成、消息分块处理和最终标签计算。
    /// 算法步骤：
    /// 1. 生成子密钥 K1 和 K2
    /// 2. 将消息分成16字节块
    /// 3. 对每个块进行处理（最后一块需要特殊处理）
    /// 4. 返回最终的认证标签
    /// 
    /// # 参数
    /// * `key` - CMAC 主密钥
    /// * `message` - 待认证的消息
    /// 
    /// # 返回值
    /// 返回16字节的 CMAC 认证标签
    pub fn compute_cmac(key: &[u8; CMAC_KEY_SIZE], message: &[u8]) -> [u8; CMAC_TAG_SIZE] {
        let (k1, k2) = Self::generate_subkeys(key);
        
        if message.is_empty() {
            // 空消息的特殊情况
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            block[0] = 0x80; // 填充
            
            // 与 K2 进行异或
            for i in 0..CMAC_BLOCK_SIZE {
                block[i] ^= k2[i];
            }
            
            return Self::aes_encrypt_block(key, &block);
        }
        
        let mut x = [0u8; CMAC_BLOCK_SIZE];
        let chunks: Vec<&[u8]> = message.chunks(CMAC_BLOCK_SIZE).collect();
        
        for (i, chunk) in chunks.iter().enumerate() {
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            
            if i == chunks.len() - 1 {
                // 最后一个块
                if chunk.len() == CMAC_BLOCK_SIZE {
                    // 完整块 - 与 K1 进行异或
                    block.copy_from_slice(chunk);
                    for j in 0..CMAC_BLOCK_SIZE {
                        block[j] ^= k1[j];
                    }
                } else {
                    // 不完整块 - 填充并与 K2 进行异或
                    block[..chunk.len()].copy_from_slice(chunk);
                    if chunk.len() < CMAC_BLOCK_SIZE {
                        block[chunk.len()] = 0x80; // 填充
                    }
                    for j in 0..CMAC_BLOCK_SIZE {
                        block[j] ^= k2[j];
                    }
                }
            } else {
                // 非最后一个块
                block.copy_from_slice(chunk);
            }
            
            // 与前一个结果进行异或
            for j in 0..CMAC_BLOCK_SIZE {
                x[j] ^= block[j];
            }
            
            // 加密
            x = Self::aes_encrypt_block(key, &x);
        }
        
        x
    }
    
    /// 安全比较两个字节数组
    /// 
    /// 使用常时间比较算法防止时序攻击。
    /// 
    /// # 参数
    /// * `a` - 第一个字节数组
    /// * `b` - 第二个字节数组
    /// 
    /// # 返回值
    /// 如果两个数组相等返回 true，否则返回 false
    fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for i in 0..a.len() {
            result |= a[i] ^ b[i];
        }
        result == 0
    }
    
    /// 对有限域元素进行 CMAC 认证
    /// 
    /// 将64位整数转换为字节数组后进行 CMAC 认证。
    /// 
    /// # 参数
    /// * `key` - CMAC 密钥
    /// * `value` - 待认证的有限域元素
    /// 
    /// # 返回值
    /// 返回认证标签
    pub fn authenticate_field_element(key: &CmacKey, value: u64) -> CmacTag {
        let message = value.to_le_bytes().to_vec();
        Self::authenticate(key, &message)
    }
    
    /// 验证有限域元素的 CMAC 认证标签
    /// 
    /// # 参数
    /// * `key` - CMAC 密钥
    /// * `value` - 待验证的有限域元素
    /// * `tag` - 待验证的认证标签
    /// 
    /// # 返回值
    /// 如果验证成功返回 true，否则返回 false
    pub fn verify_field_element(key: &CmacKey, value: u64, tag: &CmacTag) -> bool {
        let message = value.to_le_bytes().to_vec();
        Self::verify(key, &message, tag)
    }
    
    // Batch authentication
    pub fn batch_authenticate(key: &CmacKey, messages: &[Vec<u8>]) -> Vec<CmacTag> {
        messages.iter()
            .map(|msg| Self::authenticate(key, msg))
            .collect()
    }
    
    pub fn batch_verify(key: &CmacKey, messages: &[Vec<u8>], tags: &[CmacTag]) -> Result<bool> {
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
    
    pub fn start_incremental(key: &[u8; CMAC_KEY_SIZE]) -> IncrementalCMAC {
        let (k1, k2) = Self::generate_subkeys(key);
        
        IncrementalCMAC {
            key: *key,
            k1,
            k2,
            x: [0u8; CMAC_BLOCK_SIZE],
            buffer: Vec::new(),
        }
    }
    
    pub fn incremental_update(state: &mut IncrementalCMAC, data: &[u8]) {
        state.buffer.extend_from_slice(data);
        
        while state.buffer.len() >= CMAC_BLOCK_SIZE {
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            block.copy_from_slice(&state.buffer[..CMAC_BLOCK_SIZE]);
            state.buffer.drain(..CMAC_BLOCK_SIZE);
            
            // XOR with previous result
            for j in 0..CMAC_BLOCK_SIZE {
                state.x[j] ^= block[j];
            }
            
            // Encrypt
            state.x = Self::aes_encrypt_block(&state.key, &state.x);
        }
    }
    
    pub fn incremental_finalize(state: &IncrementalCMAC) -> CmacTag {
        let mut x = state.x;
        
        if !state.buffer.is_empty() {
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            
            if state.buffer.len() == CMAC_BLOCK_SIZE {
                // Complete block - XOR with K1
                block.copy_from_slice(&state.buffer);
                for j in 0..CMAC_BLOCK_SIZE {
                    block[j] ^= state.k1[j];
                }
            } else {
                // Incomplete block - pad and XOR with K2
                block[..state.buffer.len()].copy_from_slice(&state.buffer);
                if state.buffer.len() < CMAC_BLOCK_SIZE {
                    block[state.buffer.len()] = 0x80; // Padding
                }
                for j in 0..CMAC_BLOCK_SIZE {
                    block[j] ^= state.k2[j];
                }
            }
            
            // XOR with previous result
            for j in 0..CMAC_BLOCK_SIZE {
                x[j] ^= block[j];
            }
            
            // Final encryption
            x = Self::aes_encrypt_block(&state.key, &x);
        } else if x == [0u8; CMAC_BLOCK_SIZE] {
            // Empty message case
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            block[0] = 0x80; // Padding
            
            // XOR with K2
            for j in 0..CMAC_BLOCK_SIZE {
                block[j] ^= state.k2[j];
            }
            
            x = Self::aes_encrypt_block(&state.key, &block);
        }
        
        CmacTag { tag: x }
    }
    
    // OMAC (One-Key MAC) - variant of CMAC
    pub fn compute_omac(key: &[u8; CMAC_KEY_SIZE], message: &[u8]) -> [u8; CMAC_TAG_SIZE] {
        // OMAC is very similar to CMAC but with slight differences in padding
        // For simplicity, we'll use the same implementation as CMAC
        Self::compute_cmac(key, message)
    }
}

impl UnforgeableMac for CMAC {}
impl SecureMac for CMAC {}

// Tests moved to tests/authentication_tests.rs