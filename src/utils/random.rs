//! # 随机数工具函数 (Random Utility Functions)
//! 
//! 本模块提供了密码学安全的随机数生成功能，用于 MPC 协议中的各种随机化操作。
//! 所有函数都使用线程安全的随机数生成器，确保密码学安全性。
//! 
//! ## 主要功能
//! - 生成随机字节序列
//! - 生成随机整数
//! - 生成有限域中的随机元素
//! 
//! 这些函数为密钥生成、随机化协议、噪声添加等提供支持。

use rand::{RngCore, thread_rng, Rng};
use crate::secret_sharing::FIELD_PRIME;

/// 生成指定长度的随机字节序列
/// 
/// 使用密码学安全的随机数生成器生成指定长度的随机字节。
/// 适用于密钥生成、随机掩码、噪声生成等场景。
/// 
/// # 参数
/// * `len` - 需要生成的字节数量
/// 
/// # 返回值
/// 返回包含随机字节的 Vec<u8>
/// 
/// # 示例
/// ```rust
/// let key = random_bytes(32); // 生成32字节的随机密钥
/// ```
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// 生成随机的64位无符号整数
/// 
/// 使用密码学安全的随机数生成器生成一个随机的 u64 值。
/// 适用于生成随机标识符、随机种子等场景。
/// 
/// # 返回值
/// 返回一个随机的 u64 值
/// 
/// # 示例
/// ```rust
/// let random_id = random_u64();
/// ```
pub fn random_u64() -> u64 {
    let mut rng = thread_rng();
    rng.next_u64()
}

/// 生成有限域中的随机元素
/// 
/// 在有限域 GF(p) 中生成一个随机元素，其中 p = FIELD_PRIME。
/// 为了保证更好的随机性，排除了0值。
/// 适用于秘密共享、多项式系数生成等密码学协议。
/// 
/// # 返回值
/// 返回范围在 [1, FIELD_PRIME) 内的随机数
/// 
/// # 示例
/// ```rust
/// let random_share = random_field_element(); // 生成随机的域元素
/// ```
pub fn random_field_element() -> u64 {
    let mut rng = thread_rng();
    rng.gen_range(1..FIELD_PRIME) // 排除0以获得更好的随机性
}