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

    /// 加法份额的减法运算
    ///
    /// 计算两个加法份额的差，实现加法秘密分享的同态减法特性。
    /// 两个份额必须属于同一个参与方（具有相同的party_id）。
    ///
    /// # 参数
    /// - `share1`: 被减数份额
    /// - `share2`: 减数份额
    ///
    /// # 返回值
    /// 成功时返回两个份额的差
    ///
    /// # 错误
    /// 当两个份额的party_id不同时返回InvalidSecretShare错误
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let share1 = AdditiveShare::new(0, 30);
    /// let share2 = AdditiveShare::new(0, 10);
    /// let diff_share = scheme.sub_additive_shares(&share1, &share2)?;
    /// assert_eq!(diff_share.value, 20); // 在有限域中计算
    /// ```
    ///
    /// # 同态性质
    /// 如果share1是秘密s1的份额，share2是秘密s2的份额，
    /// 则diff_share是秘密(s1-s2)的有效份额。
    pub fn sub_additive_shares(&self, share1: &AdditiveShare, share2: &AdditiveShare) -> Result<AdditiveShare> {
        if share1.party_id != share2.party_id {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let diff = field_sub(share1.value, share2.value);
        Ok(AdditiveShare::new(share1.party_id, diff))
    }

    /// 加法份额的乘法运算
    ///
    /// 计算两个加法份额的乘积。注意：与 Shamir 分享不同，
    /// 加法分享的乘法不能直接进行，因为会破坏线性性质。
    /// 该方法仅作为局部运算，实际应用中需要额外的协议。
    ///
    /// # 参数
    /// - `share1`: 第一个份额
    /// - `share2`: 第二个份额
    ///
    /// # 返回值
    /// 成功时返回两个份额的乘积
    ///
    /// # 错误
    /// 当两个份额的party_id不同时返回InvalidSecretShare错误
    ///
    /// # 警告
    /// 这个方法只计算局部乘积，不是安全的 MPC 乘法！
    /// 在实际 MPC 协议中，需要使用 Beaver 三元组等技术。
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let share1 = AdditiveShare::new(0, 5);
    /// let share2 = AdditiveShare::new(0, 6);
    /// let product_share = scheme.mul_additive_shares(&share1, &share2)?;
    /// assert_eq!(product_share.value, 30); // 在有限域中计算
    /// ```
    pub fn mul_additive_shares(&self, share1: &AdditiveShare, share2: &AdditiveShare) -> Result<AdditiveShare> {
        if share1.party_id != share2.party_id {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let product = field_mul(share1.value, share2.value);
        Ok(AdditiveShare::new(share1.party_id, product))
    }

    /// Beaver 三元组乘法（加法分享版本）
    ///
    /// 使用 Beaver 三元组实现安全的加法分享乘法。
    /// 这是在加法秘密分享框架下实现安全乘法的标准方法。
    ///
    /// # 参数
    /// - `share_x`: 第一个要相乘的份额
    /// - `share_y`: 第二个要相乘的份额
    /// - `beaver_a`: Beaver 三元组中的 a 份额
    /// - `beaver_b`: Beaver 三元组中的 b 份额
    /// - `beaver_c`: Beaver 三元组中的 c 份额 (c = a * b)
    /// - `d`: 公开值 d = x - a
    /// - `e`: 公开值 e = y - b
    ///
    /// # 返回值
    /// 成功时返回 x * y 的加法分享
    ///
    /// # 错误
    /// 当份额的party_id不一致时返回InvalidSecretShare错误
    ///
    /// # 协议详细
    /// Beaver 乘法协议（加法分享版本）：
    /// 1. 各方计算 d_i = x_i - a_i, e_i = y_i - b_i
    /// 2. 重构并公开 d = Σd_i, e = Σe_i
    /// 3. 各方计算 z_i = c_i + d·b_i + e·a_i，party 0 额外加上 d·e
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// // 假设已经有了 Beaver 三元组和公开值
    /// let result = scheme.beaver_mul_additive(&share_x, &share_y, &a, &b, &c, &d, &e)?;
    /// ```
    pub fn beaver_mul_additive(
        &self,
        share_x: &AdditiveShare,
        share_y: &AdditiveShare,
        beaver_a: &AdditiveShare,
        beaver_b: &AdditiveShare,
        beaver_c: &AdditiveShare,
        d: &u64,
        e: &u64,
    ) -> Result<AdditiveShare> {
        // 验证所有份额属于同一参与方
        if share_x.party_id != share_y.party_id || 
           share_x.party_id != beaver_a.party_id || 
           share_x.party_id != beaver_b.party_id || 
           share_x.party_id != beaver_c.party_id {
            return Err(MpcError::InvalidSecretShare);
        }

        // 计算 z = c + d*b + e*a + d*e
        // 注意：在加法秘密分享中，d*e 项只有 party 0 添加
        let db = field_mul(*d, beaver_b.value);
        let ea = field_mul(*e, beaver_a.value);
        let de = if share_x.party_id == 0 { // party 0 负责常数项
            field_mul(*d, *e)
        } else {
            0
        };
        
        let result_value = field_add(
            field_add(beaver_c.value, db),
            field_add(ea, de)
        );
        
        Ok(AdditiveShare::new(share_x.party_id, result_value))
    }

    /// 生成 Beaver 三元组（加法分享版本）
    ///
    /// 生成满足 c = a * b 的随机三元组，并使用加法秘密分享进行分享。
    /// 在实际的 MPC 协议中，这通常在预处理阶段完成。
    ///
    /// # 参数
    /// - `num_parties`: 参与方数量
    ///
    /// # 返回值
    /// 成功时返回三个向量，分别包含所有参与方的 a、b、c 加法分享
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let (shares_a, shares_b, shares_c) = scheme.generate_beaver_triple_additive(3)?;
    /// assert_eq!(shares_a.len(), 3);
    /// assert_eq!(shares_b.len(), 3);
    /// assert_eq!(shares_c.len(), 3);
    /// ```
    ///
    /// # 安全性
    /// 该方法生成的三元组满足 MPC 所需的随机性和正确性要求。
    /// 在实际协议中，应当使用分布式的生成协议而不是可信方生成。
    pub fn generate_beaver_triple_additive(
        &self,
        num_parties: usize,
    ) -> Result<(Vec<AdditiveShare>, Vec<AdditiveShare>, Vec<AdditiveShare>)> {
        let mut rng = rand::thread_rng();
        
        // 生成随机的 a 和 b
        let a: u64 = rng.gen_range(0..FIELD_PRIME);
        let b: u64 = rng.gen_range(0..FIELD_PRIME);
        let c = field_mul(a, b);
        
        // 对 a, b, c 分别进行加法分享
        let shares_a = self.share_additive(&a, num_parties)?;
        let shares_b = self.share_additive(&b, num_parties)?;
        let shares_c = self.share_additive(&c, num_parties)?;
        
        Ok((shares_a, shares_b, shares_c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_additive_arithmetic() {
        let scheme = AdditiveSecretSharingScheme::new();
        let secret1 = 30u64;
        let secret2 = 10u64;
        let num_parties = 3;

        // 测试加法
        let shares1 = scheme.share_additive(&secret1, num_parties).unwrap();
        let shares2 = scheme.share_additive(&secret2, num_parties).unwrap();

        let sum_shares: Vec<AdditiveShare> = shares1.iter()
            .zip(shares2.iter())
            .map(|(s1, s2)| scheme.add_additive_shares(s1, s2))
            .collect::<Result<Vec<_>>>().unwrap();

        let sum = scheme.reconstruct_additive(&sum_shares).unwrap();
        assert_eq!(sum, field_add(secret1, secret2));

        // 测试减法
        let diff_shares: Vec<AdditiveShare> = shares1.iter()
            .zip(shares2.iter())
            .map(|(s1, s2)| scheme.sub_additive_shares(s1, s2))
            .collect::<Result<Vec<_>>>().unwrap();

        let diff = scheme.reconstruct_additive(&diff_shares).unwrap();
        assert_eq!(diff, field_sub(secret1, secret2));

        // 测试标量乘法
        let scalar = 5u64;
        let scaled_shares: Vec<AdditiveShare> = shares1.iter()
            .map(|share| scheme.scalar_mul_additive(share, &scalar))
            .collect::<Result<Vec<_>>>().unwrap();

        let scaled = scheme.reconstruct_additive(&scaled_shares).unwrap();
        assert_eq!(scaled, field_mul(secret1, scalar));
    }

    #[test]
    fn test_additive_beaver_multiplication() {
        let scheme = AdditiveSecretSharingScheme::new();
        let secret1 = 6u64;
        let secret2 = 7u64;
        let num_parties = 3;

        // 生成要相乘的分享
        let shares_x = scheme.share_additive(&secret1, num_parties).unwrap();
        let shares_y = scheme.share_additive(&secret2, num_parties).unwrap();

        // 生成 Beaver 三元组
        let (shares_a, shares_b, shares_c) = 
            scheme.generate_beaver_triple_additive(num_parties).unwrap();

        // 计算 d = x - a
        let d_shares: Vec<AdditiveShare> = shares_x.iter()
            .zip(shares_a.iter())
            .map(|(sx, sa)| scheme.sub_additive_shares(sx, sa))
            .collect::<Result<Vec<_>>>().unwrap();
        let d = scheme.reconstruct_additive(&d_shares).unwrap();

        // 计算 e = y - b
        let e_shares: Vec<AdditiveShare> = shares_y.iter()
            .zip(shares_b.iter())
            .map(|(sy, sb)| scheme.sub_additive_shares(sy, sb))
            .collect::<Result<Vec<_>>>().unwrap();
        let e = scheme.reconstruct_additive(&e_shares).unwrap();

        // 执行 Beaver 乘法
        let result_shares: Vec<AdditiveShare> = (0..num_parties).map(|i| {
            scheme.beaver_mul_additive(
                &shares_x[i], &shares_y[i],
                &shares_a[i], &shares_b[i], &shares_c[i],
                &d, &e
            )
        }).collect::<Result<Vec<_>>>().unwrap();

        let result = scheme.reconstruct_additive(&result_shares).unwrap();
        assert_eq!(result, field_mul(secret1, secret2));
    }
}

