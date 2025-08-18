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

    /// 验证加法份额的完整性
    ///
    /// 检查加法份额是否完整且有效。由于加法秘密分享需要所有份额才能重构，
    /// 此方法主要验证份额的数量和格式。
    ///
    /// # 参数
    /// - `shares`: 要验证的份额切片
    /// - `expected_parties`: 预期的参与方数量
    ///
    /// # 返回值
    /// 如果份额有效返回true，否则返回false
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let secret = 42u64;
    /// let shares = scheme.share_additive(&secret, 3)?;
    /// let is_valid = scheme.verify_additive_shares(&shares, 3);
    /// assert!(is_valid);
    /// ```
    pub fn verify_additive_shares(&self, shares: &[AdditiveShare], expected_parties: usize) -> bool {
        if shares.len() != expected_parties {
            return false;
        }

        // 检查party_id是否连续且唯一
        let mut party_ids: Vec<usize> = shares.iter().map(|s| s.party_id).collect();
        party_ids.sort();
        
        for (i, &party_id) in party_ids.iter().enumerate() {
            if party_id != i {
                return false;
            }
        }

        true
    }

    /// 转换为兼容的Shamir份额格式
    ///
    /// 将加法秘密分享的份额转换为Shamir兼容格式，便于在不同协议间切换。
    ///
    /// # 参数
    /// - `additive_shares`: 加法份额切片
    ///
    /// # 返回值
    /// 返回转换后的Share向量
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let secret = 42u64;
    /// let additive_shares = scheme.share_additive(&secret, 3)?;
    /// let shamir_shares = scheme.to_shamir_shares(&additive_shares);
    /// ```
    pub fn to_shamir_shares(&self, additive_shares: &[AdditiveShare]) -> Vec<super::Share> {
        additive_shares.iter()
            .map(|share| super::Share::new((share.party_id + 1) as u64, share.value))
            .collect()
    }

    /// 从Shamir份额格式转换
    ///
    /// 将Shamir格式的份额转换为加法秘密分享格式。
    ///
    /// # 参数
    /// - `shamir_shares`: Shamir份额切片
    ///
    /// # 返回值
    /// 成功时返回转换后的AdditiveShare向量
    ///
    /// # 错误
    /// 当Shamir份额的x坐标不连续时返回错误
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let shamir_shares = vec![Share::new(1, 10), Share::new(2, 20), Share::new(3, 30)];
    /// let additive_shares = scheme.from_shamir_shares(&shamir_shares)?;
    /// ```
    pub fn from_shamir_shares(&self, shamir_shares: &[super::Share]) -> Result<Vec<AdditiveShare>> {
        let mut additive_shares = Vec::with_capacity(shamir_shares.len());
        
        for (i, share) in shamir_shares.iter().enumerate() {
            if share.x != (i + 1) as u64 {
                return Err(MpcError::InvalidSecretShare);
            }
            additive_shares.push(AdditiveShare::new(i, share.y));
        }
        
        Ok(additive_shares)
    }

    /// 生成零的加法份额
    ///
    /// 生成一组加法份额，它们的和为0。这在协议中用作掩码或随机化。
    ///
    /// # 参数
    /// - `num_parties`: 参与方数量
    ///
    /// # 返回值
    /// 成功时返回零加法份额的向量
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let zero_shares = scheme.generate_zero_additive_shares(3)?;
    /// let reconstructed = scheme.reconstruct_additive(&zero_shares)?;
    /// assert_eq!(reconstructed, 0);
    /// ```
    pub fn generate_zero_additive_shares(&self, num_parties: usize) -> Result<Vec<AdditiveShare>> {
        self.share_additive(&0u64, num_parties)
    }

    /// 生成随机加法份额
    ///
    /// 生成一组加法份额，对应一个随机的秘密值。返回秘密值和对应的份额。
    ///
    /// # 参数
    /// - `num_parties`: 参与方数量
    ///
    /// # 返回值
    /// 成功时返回(秘密值, 份额向量)的元组
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let (secret, shares) = scheme.generate_random_additive_shares(3)?;
    /// let reconstructed = scheme.reconstruct_additive(&shares)?;
    /// assert_eq!(reconstructed, secret);
    /// ```
    pub fn generate_random_additive_shares(&self, num_parties: usize) -> Result<(u64, Vec<AdditiveShare>)> {
        let mut rng = rand::thread_rng();
        let secret = rng.gen_range(0..FIELD_PRIME);
        let shares = self.share_additive(&secret, num_parties)?;
        Ok((secret, shares))
    }

    /// 份额的求反运算
    ///
    /// 计算加法份额的相反数，对应于秘密的求反。
    ///
    /// # 参数
    /// - `share`: 要求反的份额
    ///
    /// # 返回值
    /// 返回求反后的份额
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let share = AdditiveShare::new(0, 10);
    /// let neg_share = scheme.negate_additive_share(&share);
    /// // neg_share.value 应该是 (-10) mod FIELD_PRIME
    /// ```
    pub fn negate_additive_share(&self, share: &AdditiveShare) -> AdditiveShare {
        let neg_value = field_sub(0, share.value);
        AdditiveShare::new(share.party_id, neg_value)
    }

    /// 多个份额的加法
    ///
    /// 计算多个加法份额的和，支持超过两个份额的批量加法。
    ///
    /// # 参数
    /// - `shares`: 要相加的份额切片
    ///
    /// # 返回值
    /// 成功时返回所有份额的和
    ///
    /// # 错误
    /// 当份额列表为空或party_id不一致时返回错误
    ///
    /// # 示例
    /// ```
    /// let scheme = AdditiveSecretSharingScheme::new();
    /// let shares = vec![
    ///     AdditiveShare::new(0, 10),
    ///     AdditiveShare::new(0, 20),
    ///     AdditiveShare::new(0, 30),
    /// ];
    /// let sum_share = scheme.add_multiple_additive_shares(&shares)?;
    /// assert_eq!(sum_share.value, 60);
    /// ```
    pub fn add_multiple_additive_shares(&self, shares: &[AdditiveShare]) -> Result<AdditiveShare> {
        if shares.is_empty() {
            return Err(MpcError::InsufficientShares);
        }

        let party_id = shares[0].party_id;
        let mut sum = 0u64;

        for share in shares {
            if share.party_id != party_id {
                return Err(MpcError::InvalidSecretShare);
            }
            sum = field_add(sum, share.value);
        }

        Ok(AdditiveShare::new(party_id, sum))
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
