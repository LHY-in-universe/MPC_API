//! # 秘密分享模块 (Secret Sharing Module)
//! 
//! 本模块实现了各种秘密分享方案，主要包括 Shamir 秘密分享和加法秘密分享。
//! 所有运算都在有限域 GF(p) 上进行，其中 p = 2^61 - 1。
//! 
//! ## 核心概念 (Core Concepts)
//! 
//! ### Shamir 秘密分享
//! Shamir 秘密分享是一种 (t,n) 门限方案，其中：
//! - n: 总分享数量
//! - t: 重构所需的最小分享数量  
//! - 任意 t 个分享可以重构秘密
//! - 少于 t 个分享无法获得秘密的任何信息
//! 
//! ### 有限域运算
//! 使用素数域 GF(p)，其中 p = 2305843009213693951 = 2^61 - 1
//! 提供了安全的模运算，包括：
//! - 加法：(a + b) mod p
//! - 减法：(a - b) mod p (处理负数)
//! - 乘法：(a * b) mod p
//! - 逆元：a^(-1) mod p (使用扩展欧几里德算法)
//! 
//! ## 安全性质 (Security Properties)
//! 
//! 1. **完美保密性**: 任何少于门限值的分享都不泄露秘密信息
//! 2. **同态性**: 支持在分享上直接进行加法和标量乘法
//! 3. **可验证性**: 可以验证分享的正确性 (通过多项式承诺等方法)
//! 
//! ## 使用示例 (Usage Examples)
//! 
//! ```rust
//! use mpc_api::secret_sharing::*;
//! 
//! // 基本秘密分享
//! let secret = 42u64;
//! let shares = ShamirSecretSharing::share(&secret, 2, 3)?;  // (2,3) 门限
//! let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..2], 2)?;
//! assert_eq!(reconstructed, secret);
//! 
//! // 同态加法
//! let shares1 = ShamirSecretSharing::share(&10, 2, 3)?;
//! let shares2 = ShamirSecretSharing::share(&20, 2, 3)?;
//! let sum_shares = shares1.iter().zip(shares2.iter())
//!     .map(|(s1, s2)| ShamirSecretSharing::add_shares(s1, s2))
//!     .collect::<Result<Vec<_>>>()?;
//! let sum = ShamirSecretSharing::reconstruct(&sum_shares[0..2], 2)?;
//! assert_eq!(sum, field_add(10, 20));
//! ```

pub mod shamir;
pub mod additive;

pub use shamir::*;
pub use additive::*;

// 重新导出主要的 trait (traits are defined in this module)
// pub use {SecretSharing, AdditiveSecretSharing, MultiplicationSecretSharing};

use serde::{Deserialize, Serialize};
use crate::Result;

// 使用 u64 有限域运算
/// 有限域的素数模数
/// 
/// 使用 18446744069414584321 作为有限域 GF(p) 的模数。这是一个大素数，
/// 提供了足够的安全性和计算效率。选择这个素数的原因：
/// 1. 是一个大素数，提供强安全性
/// 2. 在 u64 范围内，避免溢出问题
/// 3. 提供约 64 位的安全强度
/// 4. 用户指定的素数值，满足特定应用需求
pub const FIELD_PRIME: u64 = 18446744069414584321; // 用户指定的大素数

/// 秘密分享结构
/// 
/// 表示一个秘密分享，包含参与方索引和分享值。
/// 在 Shamir 秘密分享中，这对应于多项式上的一个点 (x, y)。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Share {
    /// 参与方索引（多项式的 x 坐标）
    pub x: u64,
    /// 分享值（多项式的 y 坐标）
    pub y: u64,
}

impl Share {
    /// 创建新的分享
    /// 
    /// # 参数
    /// 
    /// * `x` - 参与方索引
    /// * `y` - 分享值
    /// 
    /// # 返回值
    /// 
    /// 返回新创建的分享实例
    pub fn new(x: u64, y: u64) -> Self {
        Self { x, y }
    }
}

/// 有限域加法
/// 
/// 在有限域 GF(p) 中执行加法运算，其中 p 是 FIELD_PRIME。
/// 使用 u128 来避免溢出问题。
/// 
/// # 参数
/// 
/// * `a` - 第一个操作数
/// * `b` - 第二个操作数
/// 
/// # 返回值
/// 
/// 返回 (a + b) mod p 的结果
pub fn field_add(a: u64, b: u64) -> u64 {
    let sum = (a as u128 + b as u128) % FIELD_PRIME as u128;
    sum as u64
}

/// 有限域减法
/// 
/// 在有限域 GF(p) 中执行减法运算，其中 p 是 FIELD_PRIME。
/// 当 a < b 时，结果为 p - (b - a)，确保结果始终为正数。
/// 
/// # 参数
/// 
/// * `a` - 被减数
/// * `b` - 减数
/// 
/// # 返回值
/// 
/// 返回 (a - b) mod p 的结果
pub fn field_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        FIELD_PRIME - (b - a)
    }
}

/// 有限域乘法
/// 
/// 在有限域 GF(p) 中执行乘法运算，其中 p 是 FIELD_PRIME。
/// 使用 u128 来避免溢出问题。
/// 
/// # 参数
/// 
/// * `a` - 第一个操作数
/// * `b` - 第二个操作数
/// 
/// # 返回值
/// 
/// 返回 (a * b) mod p 的结果
pub fn field_mul(a: u64, b: u64) -> u64 {
    let product = (a as u128 * b as u128) % FIELD_PRIME as u128;
    product as u64
}

/// 有限域乘法逆元
/// 
/// 计算元素 a 在有限域 GF(p) 中的乘法逆元，即找到 b 使得 a * b ≡ 1 (mod p)。
/// 使用扩展欧几里德算法实现。
/// 
/// # 参数
/// 
/// * `a` - 要计算逆元的元素
/// 
/// # 返回值
/// 
/// 如果逆元存在则返回 Some(逆元)，否则返回 None
pub fn field_inv(a: u64) -> Option<u64> {
    extended_gcd(a, FIELD_PRIME).map(|(inv, _)| inv)
}

/// 扩展欧几里德算法
/// 
/// 计算 gcd(a, b) 以及满足 ax + by = gcd(a, b) 的整数 x, y。
/// 用于计算模逆元。
/// 
/// # 参数
/// 
/// * `a` - 第一个整数
/// * `b` - 第二个整数
/// 
/// # 返回值
/// 
/// 返回 (x, y) 使得 ax + by = gcd(a, b)，如果 gcd != 1 则返回 None
fn extended_gcd(a: u64, b: u64) -> Option<(u64, u64)> {
    if a == 0 {
        return Some((0, 1));
    }
    
    let (mut old_r, mut r) = (a as i128, b as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    let (mut old_t, mut t) = (0i128, 1i128);
    
    while r != 0 {
        let quotient = old_r / r;
        
        let temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;
        
        let temp_s = s;
        s = old_s - quotient * s;
        old_s = temp_s;
        
        let temp_t = t;
        t = old_t - quotient * t;
        old_t = temp_t;
    }
    
    if old_r == 1 {
        let result = if old_s < 0 {
            (old_s + b as i128) as u64
        } else {
            old_s as u64
        };
        Some((result, old_t as u64))
    } else {
        None
    }
}

/// 秘密分享协议 trait
/// 
/// 定义了所有秘密分享方案必须实现的基本操作。
/// 这是所有秘密分享协议的基础接口。
pub trait SecretSharing {
    /// 秘密类型
    type Secret;
    /// 分享类型
    type Share;

    /// 将秘密分享给多个参与方
    /// 
    /// 将一个秘密分割成多个分享，使得任意 threshold 个分享可以重构秘密，
    /// 但少于 threshold 个分享无法获得秘密的任何信息。
    /// 
    /// # 参数
    /// 
    /// * `secret` - 要分享的秘密
    /// * `threshold` - 重构秘密所需的最小分享数量
    /// * `total_parties` - 总参与方数量
    /// 
    /// # 返回值
    /// 
    /// 返回包含所有分享的向量，或者在出错时返回错误
    fn share(secret: &Self::Secret, threshold: usize, total_parties: usize) -> Result<Vec<Self::Share>>;
    
    /// 从分享重构秘密
    /// 
    /// 使用足够数量的分享来重构原始秘密。需要至少 threshold 个分享。
    /// 
    /// # 参数
    /// 
    /// * `shares` - 用于重构的分享数组
    /// * `threshold` - 重构所需的最小分享数量
    /// 
    /// # 返回值
    /// 
    /// 返回重构的秘密，或者在出错时返回错误
    fn reconstruct(shares: &[Self::Share], threshold: usize) -> Result<Self::Secret>;
}

/// 加法秘密分享协议 trait
/// 
/// 扩展基本秘密分享协议，支持在分享上直接进行同态运算。
/// 这允许在不重构秘密的情况下对秘密进行计算。
pub trait AdditiveSecretSharing: SecretSharing {
    /// 分享加法
    /// 
    /// 计算两个分享的和，对应于秘密的加法。
    /// 即如果 share1 对应秘密 s1，share2 对应秘密 s2，
    /// 则结果分享对应秘密 s1 + s2。
    /// 
    /// # 参数
    /// 
    /// * `share1` - 第一个分享
    /// * `share2` - 第二个分享
    /// 
    /// # 返回值
    /// 
    /// 返回和分享，或者在出错时返回错误
    fn add_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share>;
    
    /// 分享减法
    /// 
    /// 计算两个分享的差，对应于秘密的减法。
    /// 即如果 share1 对应秘密 s1，share2 对应秘密 s2，
    /// 则结果分享对应秘密 s1 - s2。
    /// 
    /// # 参数
    /// 
    /// * `share1` - 被减分享
    /// * `share2` - 减数分享
    /// 
    /// # 返回值
    /// 
    /// 返回差分享，或者在出错时返回错误
    fn sub_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share>;
    
    /// 标量乘法
    /// 
    /// 将分享乘以一个标量，对应于秘密乘以该标量。
    /// 即如果 share 对应秘密 s，则结果分享对应秘密 s * scalar。
    /// 
    /// # 参数
    /// 
    /// * `share` - 要乘的分享
    /// * `scalar` - 标量值
    /// 
    /// # 返回值
    /// 
    /// 返回乘积分享，或者在出错时返回错误
    fn scalar_mul(share: &Self::Share, scalar: &Self::Secret) -> Result<Self::Share>;
}

/// 乘法秘密分享协议 trait
/// 
/// 扩展加法秘密分享协议，支持分享之间的乘法运算。
/// 由于乘法运算会增加分享的度数，通常需要特殊的协议来处理。
pub trait MultiplicationSecretSharing: AdditiveSecretSharing {
    /// 分享乘法
    /// 
    /// 计算两个分享的乘积，对应于秘密的乘法。
    /// 注意：这个操作通常需要通信或预处理，因为乘法会增加多项式的度数。
    /// 
    /// # 参数
    /// 
    /// * `share1` - 第一个分享
    /// * `share2` - 第二个分享
    /// 
    /// # 返回值
    /// 
    /// 返回乘积分享，或者在出错时返回错误
    fn mul_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share>;

    /// Beaver 三元组乘法
    /// 
    /// 使用预计算的 Beaver 三元组 (a, b, c) 来计算两个分享的乘积，
    /// 其中 c = a * b。这是 MPC 中最常用的乘法协议之一。
    /// 
    /// # 参数
    /// 
    /// * `share_x` - 第一个要相乘的分享
    /// * `share_y` - 第二个要相乘的分享
    /// * `beaver_a` - Beaver 三元组中的 a 分享
    /// * `beaver_b` - Beaver 三元组中的 b 分享
    /// * `beaver_c` - Beaver 三元组中的 c 分享 (c = a * b)
    /// 
    /// # 返回值
    /// 
    /// 返回 x * y 的分享，或者在出错时返回错误
    /// 
    /// # 协议说明
    /// 
    /// Beaver 乘法协议的步骤：
    /// 1. 计算 d = x - a, e = y - b
    /// 2. 公开 d 和 e 的值（需要通信）
    /// 3. 计算 xy = c + d*b + e*a + d*e
    fn beaver_mul(
        share_x: &Self::Share,
        share_y: &Self::Share,
        beaver_a: &Self::Share,
        beaver_b: &Self::Share,
        beaver_c: &Self::Share,
        d: &Self::Secret,  // 公开的 d = x - a
        e: &Self::Secret,  // 公开的 e = y - b
    ) -> Result<Self::Share>;

    /// 生成 Beaver 三元组
    /// 
    /// 生成满足 c = a * b 的随机三元组 (a, b, c)。
    /// 在实际的 MPC 协议中，这通常在预处理阶段完成。
    /// 
    /// # 参数
    /// 
    /// * `threshold` - 门限值
    /// * `total_parties` - 总参与方数量
    /// 
    /// # 返回值
    /// 
    /// 返回包含所有参与方的 (a, b, c) 三元组分享
    fn generate_beaver_triple(
        threshold: usize,
        total_parties: usize,
    ) -> Result<(Vec<Self::Share>, Vec<Self::Share>, Vec<Self::Share>)>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_sharing::{ShamirSecretSharing, SecretSharing, AdditiveSecretSharing, AdditiveSecretSharingScheme, field_add, field_mul};

    #[test]
    fn test_shamir_secret_sharing() {
        let secret = 42u64;
        let threshold = 3;
        let total_parties = 5;
        
        let shares = ShamirSecretSharing::share(&secret, threshold, total_parties).unwrap();
        assert_eq!(shares.len(), total_parties);
        
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[..threshold], threshold).unwrap();
        assert_eq!(secret, reconstructed);
    }

    #[test]
    fn test_shamir_additive_operations() {
        let secret1 = 1000u64;
        let secret2 = 2000u64;
        let threshold = 2;
        let total_parties = 3;
        
        let shares1 = ShamirSecretSharing::share(&secret1, threshold, total_parties).unwrap();
        let shares2 = ShamirSecretSharing::share(&secret2, threshold, total_parties).unwrap();
        
        // Test addition
        let mut sum_shares = Vec::new();
        for i in 0..threshold {
            let sum_share = ShamirSecretSharing::add_shares(&shares1[i], &shares2[i]).unwrap();
            sum_shares.push(sum_share);
        }
        
        let sum_result = ShamirSecretSharing::reconstruct(&sum_shares, threshold).unwrap();
        assert_eq!(sum_result, field_add(secret1, secret2));
        
        // Test scalar multiplication
        let scalar = 3u64;
        let mut scaled_shares = Vec::new();
        for i in 0..threshold {
            let scaled_share = ShamirSecretSharing::scalar_mul(&shares1[i], &scalar).unwrap();
            scaled_shares.push(scaled_share);
        }
        
        let scaled_result = ShamirSecretSharing::reconstruct(&scaled_shares, threshold).unwrap();
        assert_eq!(scaled_result, field_mul(secret1, scalar));
    }

    #[test]
    fn test_additive_secret_sharing() {
        let scheme = AdditiveSecretSharingScheme::new();
        let secret = 1000u64;
        let num_parties = 5;
        
        let shares = scheme.share_additive(&secret, num_parties).unwrap();
        assert_eq!(shares.len(), num_parties);
        
        let reconstructed = scheme.reconstruct_additive(&shares).unwrap();
        assert_eq!(secret, reconstructed);
    }

    #[test]
    fn test_additive_operations() {
        let scheme = AdditiveSecretSharingScheme::new();
        let secret1 = 100u64;
        let secret2 = 200u64;
        let num_parties = 3;
        
        let shares1 = scheme.share_additive(&secret1, num_parties).unwrap();
        let shares2 = scheme.share_additive(&secret2, num_parties).unwrap();
        
        // Test addition
        let mut sum_shares = Vec::new();
        for i in 0..num_parties {
            let sum_share = scheme.add_additive_shares(&shares1[i], &shares2[i]).unwrap();
            sum_shares.push(sum_share);
        }
        
        let sum_result = scheme.reconstruct_additive(&sum_shares).unwrap();
        assert_eq!(sum_result, field_add(secret1, secret2));
        
        // Test scalar multiplication
        let scalar = 3u64;
        let mut scaled_shares = Vec::new();
        for share in &shares1 {
            let scaled_share = scheme.scalar_mul_additive(share, &scalar).unwrap();
            scaled_shares.push(scaled_share);
        }
        
        let scaled_result = scheme.reconstruct_additive(&scaled_shares).unwrap();
        assert_eq!(scaled_result, field_mul(secret1, scalar));
    }
}