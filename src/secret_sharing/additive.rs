//! 加法秘密分享实现
//!
//! 加法秘密分享是最简单的秘密分享方案之一，其中秘密被分割成n个随机份额，
//! 这些份额的和等于原始秘密。该方案具有以下特点：
//!
//! ## 核心特性
//! - **完美安全性**: 任何少于n个份额都无法泄露秘密信息
//! - **线性同态性**: 支持份额上的加法和标量乘法运算
//! - **计算效率**: 分享和重构操作都非常高效
//! - **简单性**: 实现简单，适合作为其他协议的构建块
//!
//! ## 数学原理
//! 对于秘密s，生成n个随机数r₁, r₂, ..., rₙ₋₁，
//! 最后一个份额rₙ = s - (r₁ + r₂ + ... + rₙ₋₁) mod p
//!
//! ## 安全模型
//! - **隐私性**: 需要所有n个份额才能重构秘密
//! - **完整性**: 通过有限域运算保证数学正确性
//! - **可验证性**: 重构结果可以通过数学验证
//!
//! 所有运算都在u64有限域中进行，确保密码学安全性。

use super::{FIELD_PRIME, field_add, field_sub, field_mul};
use crate::{MpcError, Result};
use rand::Rng;

/// 加法秘密分享的份额结构
///
/// 表示加法秘密分享方案中的单个份额，包含参与方标识和份额值。
/// 在加法秘密分享中，所有份额的和等于原始秘密。
///
/// # 字段说明
/// - `party_id`: 持有该份额的参与方标识符
/// - `value`: 份额的数值，在有限域中表示
pub struct AdditiveShare {
    /// 参与方标识符，用于区分不同的参与方
    pub party_id: usize,
    /// 份额值，在有限域GF(p)中的元素
    pub value: u64,
}

impl AdditiveShare {
    /// 创建新的加法秘密分享份额
    ///
    /// # 参数
    /// - `party_id`: 参与方标识符
    /// - `value`: 份额值（有限域元素）
    ///
    /// # 返回值
    /// 返回新创建的AdditiveShare实例
    ///
    /// # 示例
    /// ```
    /// let share = AdditiveShare::new(0, 12345);
    /// assert_eq!(share.party_id, 0);
    /// assert_eq!(share.value, 12345);
    /// ```
    pub fn new(party_id: usize, value: u64) -> Self {
        Self { party_id, value }
    }
}

/// 加法秘密分享方案实现
///
/// 提供加法秘密分享的核心功能，包括秘密分享、重构以及份额上的同态运算。
/// 该方案在有限域GF(p)中工作，支持加法和标量乘法操作。
pub struct AdditiveSecretSharingScheme;

impl Default for AdditiveSecretSharingScheme {
    /// 创建加法秘密分享方案的默认实例
    ///
    /// # 返回值
    /// 返回AdditiveSecretSharingScheme的新实例
    fn default() -> Self {
        Self::new()
    }
}

impl AdditiveSecretSharingScheme {
    /// 创建加法秘密分享方案的新实例
    ///
    /// # 返回值
    /// 返回AdditiveSecretSharingScheme的新实例
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
    
    /// 将秘密分享为多个加法份额
    ///
    /// 使用加法秘密分享方案将秘密分割成n个随机份额，这些份额的和等于原始秘密。
    /// 该方法生成n-1个随机份额，并计算最后一个份额使总和等于秘密值。
    ///
    /// # 参数
    /// - `secret`: 要分享的秘密值
    /// - `num_parties`: 参与方数量（生成的份额数量）
    ///
    /// # 返回值
    /// 成功时返回包含n个AdditiveShare的向量，每个份额分配给不同的参与方
    ///
    /// # 错误
    /// 当参与方数量为0时返回InvalidThreshold错误
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let secret = 42u64;
    /// let shares = scheme.share_additive(&secret, 3)?;
    /// assert_eq!(shares.len(), 3);
    /// ```
    ///
    /// # 安全性
    /// 该方法使用密码学安全的随机数生成器创建份额，确保份额的随机性和不可预测性。
    /// 在加法秘密分享中，需要所有n个份额才能重构秘密。
    pub fn share_additive(&self, secret: &u64, num_parties: usize) -> Result<Vec<AdditiveShare>> {
        if num_parties == 0 {
            return Err(MpcError::InvalidThreshold);
        }
        
        let mut rng = rand::thread_rng();
        let mut shares = Vec::with_capacity(num_parties);
        let mut sum = 0u64;
        
        // 生成n-1个随机份额
        for i in 0..num_parties - 1 {
            let share_value = rng.gen_range(0..FIELD_PRIME);
            sum = field_add(sum, share_value);
            shares.push(AdditiveShare::new(i, share_value));
        }
        
        // 最后一个份额 = 秘密 - 前面份额的和 (模素数)
        let last_share = field_sub(*secret, sum);
        shares.push(AdditiveShare::new(num_parties - 1, last_share));
        
        Ok(shares)
    }
    
    /// 从加法份额中重构秘密
    ///
    /// 通过计算所有份额的和来重构原始秘密。在加法秘密分享中，
    /// 需要所有参与方的份额才能完全重构秘密。
    ///
    /// # 参数
    /// - `shares`: 加法秘密分享份额的切片
    ///
    /// # 返回值
    /// 成功时返回重构的秘密值
    ///
    /// # 错误
    /// 当份额列表为空时返回InsufficientShares错误
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let secret = 42u64;
    /// let shares = scheme.share_additive(&secret, 3)?;
    /// let reconstructed = scheme.reconstruct_additive(&shares)?;
    /// assert_eq!(reconstructed, secret);
    /// ```
    ///
    /// # 安全性
    /// 该方法需要所有n个份额才能正确重构秘密。缺少任何一个份额都会导致重构失败或得到错误的结果。
    pub fn reconstruct_additive(&self, shares: &[AdditiveShare]) -> Result<u64> {
        if shares.is_empty() {
            return Err(MpcError::InsufficientShares);
        }
        
        let mut sum = 0u64;
        for share in shares {
            sum = field_add(sum, share.value);
        }
        
        Ok(sum)
    }
    
    /// 加法份额的加法运算
    ///
    /// 计算两个加法份额的和，实现加法秘密分享的同态加法特性。
    /// 两个份额必须属于同一个参与方（具有相同的party_id）。
    ///
    /// # 参数
    /// - `share1`: 第一个加法份额
    /// - `share2`: 第二个加法份额
    ///
    /// # 返回值
    /// 成功时返回两个份额的和
    ///
    /// # 错误
    /// 当两个份额的party_id不同时返回InvalidSecretShare错误
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let share1 = AdditiveShare::new(0, 10);
    /// let share2 = AdditiveShare::new(0, 20);
    /// let sum_share = scheme.add_additive_shares(&share1, &share2)?;
    /// assert_eq!(sum_share.value, 30); // 在有限域中计算
    /// ```
    ///
    /// # 同态性质
    /// 如果share1是秘密s1的份额，share2是秘密s2的份额，
    /// 则sum_share是秘密(s1+s2)的有效份额。
    pub fn add_additive_shares(&self, share1: &AdditiveShare, share2: &AdditiveShare) -> Result<AdditiveShare> {
        if share1.party_id != share2.party_id {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let sum = field_add(share1.value, share2.value);
        Ok(AdditiveShare::new(share1.party_id, sum))
    }
    
    /// 加法份额的标量乘法运算
    ///
    /// 计算加法份额与标量的乘积，实现加法秘密分享的同态标量乘法特性。
    ///
    /// # 参数
    /// - `share`: 加法份额
    /// - `scalar`: 标量值
    ///
    /// # 返回值
    /// 返回份额与标量的乘积
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let share = AdditiveShare::new(0, 10);
    /// let scalar = 5u64;
    /// let product_share = scheme.scalar_mul_additive(&share, &scalar)?;
    /// assert_eq!(product_share.value, 50); // 在有限域中计算
    /// ```
    ///
    /// # 同态性质
    /// 如果share是秘密s的份额，则product_share是秘密(s*scalar)的有效份额。
    pub fn scalar_mul_additive(&self, share: &AdditiveShare, scalar: &u64) -> Result<AdditiveShare> {
        let product = field_mul(share.value, *scalar);
        Ok(AdditiveShare::new(share.party_id, product))
    }
}

