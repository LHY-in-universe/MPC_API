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

use serde::{Deserialize, Serialize};
use crate::{MpcError, Result};

// Using u64 finite field operations
pub const FIELD_PRIME: u64 = 2305843009213693951; // 2^61 - 1, a large prime

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Share {
    pub x: u64,  // party index
    pub y: u64,  // share value
}

impl Share {
    pub fn new(x: u64, y: u64) -> Self {
        Self { x, y }
    }
}

pub fn field_add(a: u64, b: u64) -> u64 {
    let sum = (a as u128 + b as u128) % FIELD_PRIME as u128;
    sum as u64
}

pub fn field_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        FIELD_PRIME - (b - a)
    }
}

pub fn field_mul(a: u64, b: u64) -> u64 {
    let product = (a as u128 * b as u128) % FIELD_PRIME as u128;
    product as u64
}

pub fn field_inv(a: u64) -> Option<u64> {
    extended_gcd(a, FIELD_PRIME).map(|(inv, _)| inv)
}

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

pub trait SecretSharing {
    type Secret;
    type Share;
    
    fn share(secret: &Self::Secret, threshold: usize, total_parties: usize) -> Result<Vec<Self::Share>>;
    fn reconstruct(shares: &[Self::Share], threshold: usize) -> Result<Self::Secret>;
}

pub trait AdditiveSecretSharing: SecretSharing {
    fn add_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share>;
    fn sub_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share>;
    fn scalar_mul(share: &Self::Share, scalar: &Self::Secret) -> Result<Self::Share>;
}