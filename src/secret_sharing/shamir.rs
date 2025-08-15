//! Shamir秘密分享实现
//!
//! 实现经典的(t,n)门限秘密分享方案，其中任意t个份额可以重构秘密，
//! 但t-1个份额无法泄露任何秘密信息。该方案基于多项式插值理论。
//!
//! ## 核心特性
//! - **门限安全性**: 任意t个份额可以重构秘密，少于t个份额无法获得任何信息
//! - **完美安全性**: 信息论安全，即使攻击者拥有无限计算能力也无法破解
//! - **线性同态性**: 支持份额上的加法、减法和标量乘法运算
//! - **灵活性**: 支持任意的(t,n)参数组合，适应不同的安全需求
//!
//! ## 数学原理
//! Shamir秘密分享基于多项式插值：
//! - 构造t-1次多项式 f(x) = a₀ + a₁x + a₂x² + ... + aₜ₋₁x^(t-1)
//! - 其中a₀ = secret，其他系数随机选择
//! - 份额为 (i, f(i))，i = 1, 2, ..., n
//! - 重构时使用拉格朗日插值计算f(0) = secret
//!
//! ## 安全模型
//! - **隐私性**: 任何少于t个份额的集合都无法泄露秘密信息
//! - **完整性**: 通过有限域运算保证数学正确性
//! - **可验证性**: 可以验证份额的有效性和重构结果的正确性
//!
//! 所有运算都在u64有限域中进行，确保密码学安全性。

use super::{Share, SecretSharing, AdditiveSecretSharing, FIELD_PRIME, field_add, field_sub, field_mul, field_inv};
use crate::{MpcError, Result};
use rand::Rng;
// use serde::{Deserialize, Serialize}; // Commented out unused imports

/// Shamir秘密分享方案实现
///
/// 提供Shamir秘密分享的核心功能，包括秘密分享、重构以及份额上的同态运算。
/// 该方案基于多项式插值理论，在有限域GF(p)中工作。
pub struct ShamirSecretSharing;

impl Default for ShamirSecretSharing {
    /// 创建Shamir秘密分享方案的默认实例
    ///
    /// # 返回值
    /// 返回ShamirSecretSharing的新实例
    fn default() -> Self {
        Self::new()
    }
}

impl ShamirSecretSharing {
    /// 创建Shamir秘密分享方案的新实例
    ///
    /// # 返回值
    /// 返回ShamirSecretSharing的新实例
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
    
    /// 计算多项式在给定点的值
    ///
    /// 使用霍纳方法（Horner's method）高效计算多项式f(x) = a₀ + a₁x + a₂x² + ... + aₙx^n的值。
    ///
    /// # 参数
    /// - `coefficients`: 多项式系数数组，从常数项开始
    /// - `x`: 计算点的x坐标
    ///
    /// # 返回值
    /// 返回多项式在点x处的值
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let coeffs = vec![5, 3, 2]; // f(x) = 5 + 3x + 2x²
    /// let result = scheme.evaluate_polynomial(&coeffs, 2); // f(2) = 5 + 6 + 8 = 19
    /// ```
    fn evaluate_polynomial(&self, coefficients: &[u64], x: u64) -> u64 {
        let mut result = 0u64;
        let mut x_power = 1u64;
        
        for &coeff in coefficients {
            result = field_add(result, field_mul(coeff, x_power));
            x_power = field_mul(x_power, x);
        }
        
        result
    }
    
    /// 使用拉格朗日插值法重构秘密
    ///
    /// 通过拉格朗日插值公式计算多项式在x=0处的值，即原始秘密。
    /// 拉格朗日插值公式：f(0) = Σ yᵢ * Lᵢ(0)，其中Lᵢ(0)是拉格朗日基函数。
    ///
    /// # 参数
    /// - `shares`: 用于重构的份额数组
    ///
    /// # 返回值
    /// 成功时返回重构的秘密值
    ///
    /// # 错误
    /// - 当份额数组为空时返回InsufficientShares错误
    /// - 当计算模逆时失败返回CryptographicError错误
    ///
    /// # 数学原理
    /// 拉格朗日基函数：Lᵢ(0) = ∏(0-xⱼ)/(xᵢ-xⱼ) for j≠i
    /// 最终结果：f(0) = Σ yᵢ * Lᵢ(0)
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let shares = vec![Share::new(1, 10), Share::new(2, 15), Share::new(3, 22)];
    /// let secret = scheme.lagrange_interpolation(&shares)?;
    /// ```
    fn lagrange_interpolation(&self, shares: &[Share]) -> Result<u64> {
        if shares.is_empty() {
            return Err(MpcError::InsufficientShares);
        }
        
        let mut result = 0u64;
        
        // 拉格朗日插值：计算在x=0处的多项式值
        for i in 0..shares.len() {
            let mut numerator = 1u64;
            let mut denominator = 1u64;
            
            // 计算拉格朗日基函数 L_i(0) = ∏(0-x_j)/(x_i-x_j) for j≠i
            for j in 0..shares.len() {
                if i != j {
                    // 分子：(0 - x_j) = (-x_j) = field_sub(0, x_j)
                    let neg_xj = field_sub(0, shares[j].x);
                    numerator = field_mul(numerator, neg_xj);
                    
                    // 分母：(x_i - x_j)
                    let diff = field_sub(shares[i].x, shares[j].x);
                    denominator = field_mul(denominator, diff);
                }
            }
            
            let denominator_inv = field_inv(denominator)
                .ok_or_else(|| MpcError::CryptographicError("No modular inverse exists".to_string()))?;
            let lagrange_coeff = field_mul(numerator, denominator_inv);
            
            result = field_add(result, field_mul(shares[i].y, lagrange_coeff));
        }
        
        Ok(result)
    }
}

/// 实现SecretSharing trait，提供Shamir秘密分享的核心功能
impl SecretSharing for ShamirSecretSharing {
    /// 秘密类型，使用u64表示有限域元素
    type Secret = u64;
    /// 份额类型，使用Share结构体表示
    type Share = Share;
    
    /// 将秘密分享为多个Shamir份额
    ///
    /// 使用Shamir秘密分享方案将秘密分割成n个份额，其中任意t个份额可以重构秘密。
    /// 该方法构造一个t-1次多项式，其常数项为秘密值，其他系数随机生成。
    ///
    /// # 参数
    /// - `secret`: 要分享的秘密值
    /// - `threshold`: 重构秘密所需的最小份额数量(t)
    /// - `total_parties`: 参与方总数(n)
    ///
    /// # 返回值
    /// 成功时返回包含n个Share的向量，每个份额分配给不同的参与方
    ///
    /// # 错误
    /// 当门限值无效（为0或大于参与方总数）时返回InvalidThreshold错误
    ///
    /// # 示例
    /// ```
    /// let secret = 42u64;
    /// let shares = ShamirSecretSharing::share(&secret, 2, 3)?;
    /// assert_eq!(shares.len(), 3);
    /// ```
    ///
    /// # 安全性
    /// 该方法使用密码学安全的随机数生成器创建多项式系数，确保份额的随机性和不可预测性。
    /// 在Shamir秘密分享中，少于t个份额无法泄露任何关于秘密的信息。
    fn share(secret: &Self::Secret, threshold: usize, total_parties: usize) -> Result<Vec<Self::Share>> {
        if threshold == 0 || threshold > total_parties {
            return Err(MpcError::InvalidThreshold);
        }
        
        let sss = Self::new();
        let mut rng = rand::thread_rng();
        
        // 生成(threshold - 1)次多项式的随机系数
        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(*secret); // a_0 = secret
        
        for _ in 1..threshold {
            let coeff = rng.gen_range(0..FIELD_PRIME);
            coefficients.push(coeff);
        }
        
        // 在点1, 2, ..., total_parties处计算多项式的值
        let mut shares = Vec::with_capacity(total_parties);
        for i in 1..=total_parties {
            let x = i as u64;
            let y = sss.evaluate_polynomial(&coefficients, x);
            shares.push(Share::new(x, y));
        }
        
        Ok(shares)
    }
    
    /// 从Shamir份额中重构秘密
    ///
    /// 使用拉格朗日插值法从至少t个份额中重构原始秘密。
    /// 该方法选择前t个份额进行插值计算，得到多项式在x=0处的值。
    ///
    /// # 参数
    /// - `shares`: Shamir秘密分享份额的切片
    /// - `threshold`: 重构秘密所需的最小份额数量(t)
    ///
    /// # 返回值
    /// 成功时返回重构的秘密值
    ///
    /// # 错误
    /// 当提供的份额数量少于门限值时返回InsufficientShares错误
    ///
    /// # 示例
    /// ```
    /// let secret = 42u64;
    /// let shares = ShamirSecretSharing::share(&secret, 2, 3)?;
    /// let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..2], 2)?;
    /// assert_eq!(reconstructed, secret);
    /// ```
    ///
    /// # 安全性
    /// 该方法需要至少t个有效份额才能正确重构秘密。使用少于t个份额将导致重构失败。
    fn reconstruct(shares: &[Self::Share], threshold: usize) -> Result<Self::Secret> {
        if shares.len() < threshold {
            return Err(MpcError::InsufficientShares);
        }
        
        let sss = Self::new();
        let shares_subset = &shares[..threshold];
        sss.lagrange_interpolation(shares_subset)
    }
}

/// 实现AdditiveSecretSharing trait，提供Shamir份额的同态运算功能
impl AdditiveSecretSharing for ShamirSecretSharing {
    /// Shamir份额的加法运算
    ///
    /// 计算两个Shamir份额的和，实现Shamir秘密分享的同态加法特性。
    /// 两个份额必须对应相同的x坐标（相同的参与方位置）。
    ///
    /// # 参数
    /// - `share1`: 第一个Shamir份额
    /// - `share2`: 第二个Shamir份额
    ///
    /// # 返回值
    /// 成功时返回两个份额的和
    ///
    /// # 错误
    /// 当两个份额的x坐标不同时返回InvalidSecretShare错误
    ///
    /// # 示例
    /// ```
    /// let share1 = Share::new(1, 10);
    /// let share2 = Share::new(1, 20);
    /// let sum_share = ShamirSecretSharing::add_shares(&share1, &share2)?;
    /// assert_eq!(sum_share.y, 30); // 在有限域中计算
    /// ```
    ///
    /// # 同态性质
    /// 如果share1是秘密s1的份额，share2是秘密s2的份额，
    /// 则sum_share是秘密(s1+s2)的有效份额。
    fn add_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share> {
        if share1.x != share2.x {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let y = field_add(share1.y, share2.y);
        Ok(Share::new(share1.x, y))
    }
    
    /// Shamir份额的减法运算
    ///
    /// 计算两个Shamir份额的差，实现Shamir秘密分享的同态减法特性。
    /// 两个份额必须对应相同的x坐标（相同的参与方位置）。
    ///
    /// # 参数
    /// - `share1`: 被减数份额
    /// - `share2`: 减数份额
    ///
    /// # 返回值
    /// 成功时返回两个份额的差
    ///
    /// # 错误
    /// 当两个份额的x坐标不同时返回InvalidSecretShare错误
    ///
    /// # 示例
    /// ```
    /// let share1 = Share::new(1, 30);
    /// let share2 = Share::new(1, 10);
    /// let diff_share = ShamirSecretSharing::sub_shares(&share1, &share2)?;
    /// assert_eq!(diff_share.y, 20); // 在有限域中计算
    /// ```
    ///
    /// # 同态性质
    /// 如果share1是秘密s1的份额，share2是秘密s2的份额，
    /// 则diff_share是秘密(s1-s2)的有效份额。
    fn sub_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share> {
        if share1.x != share2.x {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let y = field_sub(share1.y, share2.y);
        Ok(Share::new(share1.x, y))
    }
    
    /// Shamir份额的标量乘法运算
    ///
    /// 计算Shamir份额与标量的乘积，实现Shamir秘密分享的同态标量乘法特性。
    ///
    /// # 参数
    /// - `share`: Shamir份额
    /// - `scalar`: 标量值
    ///
    /// # 返回值
    /// 返回份额与标量的乘积
    ///
    /// # 示例
    /// ```
    /// let share = Share::new(1, 10);
    /// let scalar = 5u64;
    /// let product_share = ShamirSecretSharing::scalar_mul(&share, &scalar)?;
    /// assert_eq!(product_share.y, 50); // 在有限域中计算
    /// ```
    ///
    /// # 同态性质
    /// 如果share是秘密s的份额，则product_share是秘密(s*scalar)的有效份额。
    fn scalar_mul(share: &Self::Share, scalar: &Self::Secret) -> Result<Self::Share> {
        let y = field_mul(share.y, *scalar);
        Ok(Share::new(share.x, y))
    }
}

