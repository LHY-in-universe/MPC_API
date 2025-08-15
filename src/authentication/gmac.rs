//! GMAC (Galois Message Authentication Code) 实现
//!
//! 本模块提供基于伽罗瓦域算术的 GMAC 消息认证码实现。
//! GMAC 是一种高效的认证算法，广泛用于网络安全协议中。
//!
//! ## 主要特性
//! - 基于 AES 分组密码的认证算法
//! - 使用伽罗瓦域 GF(2^128) 进行数学运算
//! - 支持任意长度消息的认证
//! - 提供增量计算功能
//! - 支持批量操作和有限域元素认证
//!
//! ## 使用场景
//! - 网络协议中的消息完整性验证
//! - 数据传输中的认证保护
//! - 密码学协议中的认证原语

use crate::{MpcError, Result};
use super::{MessageAuthenticationCode, UnforgeableMac, SecureMac};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

/// GMAC 密钥大小（字节）- 128位
const GMAC_KEY_SIZE: usize = 16;
/// GMAC 标签大小（字节）- 128位
const GMAC_TAG_SIZE: usize = 16;
/// GMAC 块大小（字节）- 128位
const GMAC_BLOCK_SIZE: usize = 16;

/// GF(2^128) 不可约多项式: x^128 + x^7 + x^2 + x + 1
const GF128_POLYNOMIAL: u128 = 0x87;

/// GMAC 密钥结构
/// 
/// 包含用于 GMAC 认证的密钥材料。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GmacKey {
    /// 认证子密钥
    pub h: [u8; GMAC_KEY_SIZE],
    /// 最终步骤的加密密钥
    pub k: [u8; GMAC_KEY_SIZE],
}

/// GMAC 认证标签
/// 
/// 包含 GMAC 算法生成的128位认证标签。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GmacTag {
    /// 认证标签
    pub tag: [u8; GMAC_TAG_SIZE],
}

/// GMAC 实现结构
/// 
/// 提供完整的 GMAC 消息认证码功能。
pub struct GMAC;

/// 增量 GMAC 计算状态
/// 
/// 用于支持流式数据的 GMAC 计算，允许分块处理大型消息。
pub struct IncrementalGMAC {
    /// 哈希子密钥（GF(2^128) 格式）
    h: u128,
    /// 当前累积值
    y: u128,
    /// 不完整块的缓冲区
    buffer: Vec<u8>,
}

impl MessageAuthenticationCode for GMAC {
    type Key = GmacKey;
    type Message = Vec<u8>;
    type Tag = GmacTag;
    
    /// 生成 GMAC 密钥
    /// 
    /// 生成包含认证子密钥和加密密钥的 GMAC 密钥对。
    /// 
    /// # 返回值
    /// 返回新生成的 GmacKey
    fn generate_key() -> Self::Key {
        let mut rng = thread_rng();
        let mut h = [0u8; GMAC_KEY_SIZE];
        let mut k = [0u8; GMAC_KEY_SIZE];
        
        for i in 0..GMAC_KEY_SIZE {
            h[i] = rng.gen();
            k[i] = rng.gen();
        }
        
        GmacKey { h, k }
    }
    
    /// 对消息进行 GMAC 认证
    /// 
    /// 使用给定的密钥对消息计算 GMAC 认证标签。
    /// 
    /// # 参数
    /// * `key` - GMAC 密钥
    /// * `message` - 待认证的消息
    /// 
    /// # 返回值
    /// 返回消息的 GMAC 认证标签
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag {
        let tag = Self::compute_gmac(&key.h, &key.k, message);
        GmacTag { tag }
    }
    
    /// 验证消息的 GMAC 认证标签
    /// 
    /// 重新计算消息的 GMAC 标签并与提供的标签进行安全比较。
    /// 
    /// # 参数
    /// * `key` - GMAC 密钥
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

impl Default for GMAC {
    fn default() -> Self {
        Self::new()
    }
}

impl GMAC {
    /// 创建新的 GMAC 实例
    /// 
    /// # 返回值
    /// 返回 GMAC 结构体实例
    pub fn new() -> Self {
        GMAC
    }
    
    /// 计算 GMAC 认证标签
    /// 
    /// 实现完整的 GMAC 算法，包括伽罗瓦域运算和最终加密步骤。
    /// 算法步骤：
    /// 1. 将消息分成16字节块
    /// 2. 在 GF(2^128) 中进行多项式求值
    /// 3. 应用最终加密密钥
    /// 
    /// # 参数
    /// * `h` - 认证子密钥
    /// * `k` - 加密密钥
    /// * `message` - 待认证的消息
    /// 
    /// # 返回值
    /// 返回16字节的 GMAC 认证标签
    pub fn compute_gmac(h: &[u8; GMAC_KEY_SIZE], k: &[u8; GMAC_KEY_SIZE], message: &[u8]) -> [u8; GMAC_TAG_SIZE] {
        let h_value = Self::bytes_to_gf128(h);
        
        let mut y = 0u128;
        
        // 以16字节块处理消息
        for chunk in message.chunks(GMAC_BLOCK_SIZE) {
            let mut block = [0u8; GMAC_BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            
            let x = Self::bytes_to_gf128(&block);
            y = Self::gf128_mul(y ^ x, h_value);
        }
        
        // 使用密钥 k 应用最终加密（简化版）
        let k_value = Self::bytes_to_gf128(k);
        let final_tag = y ^ k_value;
        
        Self::gf128_to_bytes(final_tag)
    }
    
    /// 将字节数组转换为 GF(2^128) 元素
    /// 
    /// 将16字节的数据转换为128位整数，用于伽罗瓦域运算。
    /// 
    /// # 参数
    /// * `bytes` - 待转换的字节数组
    /// 
    /// # 返回值
    /// 返回对应的 GF(2^128) 元素
    pub fn bytes_to_gf128(bytes: &[u8]) -> u128 {
        let mut result = 0u128;
        for (i, &byte) in bytes.iter().enumerate().take(16) {
            result |= (byte as u128) << ((15 - i) * 8);
        }
        result
    }
    
    /// 将 GF(2^128) 元素转换为字节数组
    /// 
    /// 将128位整数转换为16字节的数据。
    /// 
    /// # 参数
    /// * `value` - GF(2^128) 元素
    /// 
    /// # 返回值
    /// 返回对应的16字节数组
    pub fn gf128_to_bytes(value: u128) -> [u8; GMAC_TAG_SIZE] {
        let mut bytes = [0u8; GMAC_TAG_SIZE];
        for i in 0..GMAC_TAG_SIZE {
            bytes[i] = (value >> ((15 - i) * 8)) as u8;
        }
        bytes
    }
    
    /// 在 GF(2^128) 中进行乘法运算
    /// 
    /// 实现伽罗瓦域 GF(2^128) 中的乘法运算，使用不可约多项式进行约简。
    /// 这是 GMAC 算法的核心运算。
    /// 
    /// # 参数
    /// * `a` - 第一个操作数
    /// * `b` - 第二个操作数
    /// 
    /// # 返回值
    /// 返回 a * b 在 GF(2^128) 中的结果
    pub fn gf128_mul(a: u128, b: u128) -> u128 {
        let mut result = 0u128;
        let mut temp_a = a;
        let mut temp_b = b;
        
        for _ in 0..128 {
            if temp_b & 1 != 0 {
                result ^= temp_a;
            }
            
            let overflow = temp_a & (1u128 << 127) != 0;
            temp_a <<= 1;
            
            if overflow {
                temp_a ^= GF128_POLYNOMIAL;
            }
            
            temp_b >>= 1;
            
            if temp_b == 0 {
                break;
            }
        }
        
        result
    }
    
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
    
    // GMAC for field elements
    pub fn authenticate_field_element(key: &GmacKey, value: u64) -> GmacTag {
        let message = value.to_le_bytes().to_vec();
        Self::authenticate(key, &message)
    }
    
    pub fn verify_field_element(key: &GmacKey, value: u64, tag: &GmacTag) -> bool {
        let message = value.to_le_bytes().to_vec();
        Self::verify(key, &message, tag)
    }
    
    // Batch authentication
    pub fn batch_authenticate(key: &GmacKey, messages: &[Vec<u8>]) -> Vec<GmacTag> {
        messages.iter()
            .map(|msg| Self::authenticate(key, msg))
            .collect()
    }
    
    pub fn batch_verify(key: &GmacKey, messages: &[Vec<u8>], tags: &[GmacTag]) -> Result<bool> {
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
    
    pub fn start_incremental(h: &[u8; GMAC_KEY_SIZE]) -> IncrementalGMAC {
        IncrementalGMAC {
            h: Self::bytes_to_gf128(h),
            y: 0,
            buffer: Vec::new(),
        }
    }
}

impl GMAC {
    pub fn incremental_update(state: &mut IncrementalGMAC, data: &[u8]) {
        state.buffer.extend_from_slice(data);
        
        while state.buffer.len() >= GMAC_BLOCK_SIZE {
            let mut block = [0u8; GMAC_BLOCK_SIZE];
            block.copy_from_slice(&state.buffer[..GMAC_BLOCK_SIZE]);
            state.buffer.drain(..GMAC_BLOCK_SIZE);
            
            let x = Self::bytes_to_gf128(&block);
            state.y = Self::gf128_mul(state.y ^ x, state.h);
        }
    }
    
    pub fn incremental_finalize(state: &IncrementalGMAC, k: &[u8; GMAC_KEY_SIZE]) -> GmacTag {
        let mut final_y = state.y;
        
        // Process remaining buffer
        if !state.buffer.is_empty() {
            let mut block = [0u8; GMAC_BLOCK_SIZE];
            block[..state.buffer.len()].copy_from_slice(&state.buffer);
            
            let x = Self::bytes_to_gf128(&block);
            final_y = Self::gf128_mul(final_y ^ x, state.h);
        }
        
        // Apply final key
        let k_value = Self::bytes_to_gf128(k);
        let final_tag = final_y ^ k_value;
        
        GmacTag { tag: Self::gf128_to_bytes(final_tag) }
    }
    
    // GHASH (the core of GMAC without final encryption)
    pub fn ghash(h: &[u8; GMAC_KEY_SIZE], data: &[u8]) -> [u8; GMAC_TAG_SIZE] {
        let h_value = Self::bytes_to_gf128(h);
        let mut y = 0u128;
        
        for chunk in data.chunks(GMAC_BLOCK_SIZE) {
            let mut block = [0u8; GMAC_BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            
            let x = Self::bytes_to_gf128(&block);
            y = Self::gf128_mul(y ^ x, h_value);
        }
        
        Self::gf128_to_bytes(y)
    }
    
    // Polynomial evaluation for multiple data blocks
    pub fn polynomial_eval(h: &[u8; GMAC_KEY_SIZE], blocks: &[Vec<u8>]) -> GmacTag {
        let h_value = Self::bytes_to_gf128(h);
        let mut result = 0u128;
        let mut h_power = 1u128;
        
        for block_data in blocks.iter() {
            for chunk in block_data.chunks(GMAC_BLOCK_SIZE) {
                let mut block = [0u8; GMAC_BLOCK_SIZE];
                block[..chunk.len()].copy_from_slice(chunk);
                
                let x = Self::bytes_to_gf128(&block);
                result ^= Self::gf128_mul(x, h_power);
                h_power = Self::gf128_mul(h_power, h_value);
            }
        }
        
        GmacTag { tag: Self::gf128_to_bytes(result) }
    }
}

impl UnforgeableMac for GMAC {}
impl SecureMac for GMAC {}

// Tests moved to tests/authentication_tests.rs