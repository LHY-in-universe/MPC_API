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
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
// use serde::{Deserialize, Serialize}; // Commented out unused imports

/// 横坐标选择策略
#[derive(Debug, Clone, Copy)]
pub enum XCoordinateStrategy {
    /// 顺序选择：x = 1, 2, 3, ...
    Sequential,
    /// 随机选择：使用随机数生成器选择横坐标
    Random,
    /// 种子控制的随机选择：使用指定种子生成可重现的横坐标
    SeededRandom(u64),
}

impl Default for XCoordinateStrategy {
    fn default() -> Self {
        XCoordinateStrategy::Sequential
    }
}

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

    /// 验证份额的有效性
    ///
    /// 检查给定的份额是否对同一个秘密有效。这通过验证份额是否来自同一个多项式来实现。
    ///
    /// # 参数
    /// - `shares`: 要验证的份额数组
    /// - `threshold`: 原始的门限值
    ///
    /// # 返回值
    /// 如果份额有效返回true，否则返回false
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let secret = 42u64;
    /// let shares = ShamirSecretSharing::share(&secret, 2, 3)?;
    /// let is_valid = scheme.verify_shares(&shares[0..2], 2);
    /// assert!(is_valid);
    /// ```
    pub fn verify_shares(&self, shares: &[Share], threshold: usize) -> bool {
        if shares.len() < threshold {
            return false;
        }

        // 使用前threshold个份额重构秘密
        let shares_subset = &shares[..threshold];
        if let Ok(secret1) = self.lagrange_interpolation(shares_subset) {
            // 如果有更多份额，使用不同的threshold个份额再次重构
            if shares.len() > threshold {
                for i in 1..=(shares.len() - threshold) {
                    let alt_shares = &shares[i..i + threshold];
                    if let Ok(secret2) = self.lagrange_interpolation(alt_shares) {
                        if secret1 != secret2 {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// 更新现有份额（份额刷新）
    ///
    /// 生成新的随机多项式份额，但保持相同的秘密。这用于提高安全性，
    /// 防止攻击者通过长期观察学习到份额信息。
    ///
    /// # 参数
    /// - `old_shares`: 现有的份额
    /// - `threshold`: 门限值
    ///
    /// # 返回值
    /// 成功时返回刷新后的份额
    ///
    /// # 错误
    /// 当份额不足或重构失败时返回错误
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let secret = 42u64;
    /// let old_shares = ShamirSecretSharing::share(&secret, 2, 3)?;
    /// let new_shares = scheme.refresh_shares(&old_shares, 2, 3)?;
    /// // 新份额对应相同的秘密但有不同的随机性
    /// ```
    pub fn refresh_shares(&self, old_shares: &[Share], threshold: usize, total_parties: usize) -> Result<Vec<Share>> {
        // 首先重构秘密
        let secret = self.lagrange_interpolation(&old_shares[..threshold])?;
        
        // 生成新的份额
        Self::share(&secret, threshold, total_parties)
    }

    /// 分割秘密为多个子秘密
    ///
    /// 将一个秘密分割为多个较小的子秘密，每个子秘密可以独立分享。
    /// 这对于管理大型秘密或实现分层访问控制很有用。
    ///
    /// # 参数
    /// - `secret`: 要分割的秘密
    /// - `num_parts`: 分割的部分数量
    ///
    /// # 返回值
    /// 成功时返回子秘密的向量
    ///
    /// # 错误
    /// 当分割部分数量为0时返回错误
    ///
    /// # 数学原理
    /// secret = part1 + part2 + ... + part(n-1) + part_n (mod p)
    /// 其中前n-1个部分是随机生成的，最后一个部分确保总和等于原秘密
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let secret = 100u64;
    /// let parts = scheme.split_secret(&secret, 3)?;
    /// let reconstructed = parts.iter().fold(0u64, |acc, &x| field_add(acc, x));
    /// assert_eq!(reconstructed, secret);
    /// ```
    pub fn split_secret(&self, secret: &u64, num_parts: usize) -> Result<Vec<u64>> {
        if num_parts == 0 {
            return Err(MpcError::InvalidThreshold);
        }

        let mut rng = rand::thread_rng();
        let mut parts = Vec::with_capacity(num_parts);
        let mut sum = 0u64;

        // 生成前n-1个随机部分
        for _ in 0..num_parts - 1 {
            let part = rng.gen_range(0..FIELD_PRIME);
            sum = field_add(sum, part);
            parts.push(part);
        }

        // 最后一个部分确保总和等于秘密
        let last_part = field_sub(*secret, sum);
        parts.push(last_part);

        Ok(parts)
    }

    /// 合并子秘密
    ///
    /// 将通过split_secret分割的子秘密重新合并为原始秘密。
    ///
    /// # 参数
    /// - `parts`: 子秘密的切片
    ///
    /// # 返回值
    /// 返回合并后的秘密
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let secret = 100u64;
    /// let parts = scheme.split_secret(&secret, 3)?;
    /// let reconstructed = scheme.combine_secret(&parts);
    /// assert_eq!(reconstructed, secret);
    /// ```
    pub fn combine_secret(&self, parts: &[u64]) -> u64 {
        parts.iter().fold(0u64, |acc, &x| field_add(acc, x))
    }

    /// 生成零份额
    ///
    /// 生成一组份额，它们对应的秘密值为0。这在某些协议中用作掩码或随机性。
    ///
    /// # 参数
    /// - `threshold`: 门限值
    /// - `total_parties`: 总参与方数量
    ///
    /// # 返回值
    /// 成功时返回零份额的向量
    ///
    /// # 示例
    /// ```
    /// let zero_shares = ShamirSecretSharing::generate_zero_shares(2, 3)?;
    /// let reconstructed = ShamirSecretSharing::reconstruct(&zero_shares[0..2], 2)?;
    /// assert_eq!(reconstructed, 0);
    /// ```
    pub fn generate_zero_shares(threshold: usize, total_parties: usize) -> Result<Vec<Share>> {
        Self::share(&0u64, threshold, total_parties)
    }

    /// 生成随机份额
    ///
    /// 生成一组份额，对应一个随机的秘密值。返回份额和对应的秘密。
    ///
    /// # 参数
    /// - `threshold`: 门限值
    /// - `total_parties`: 总参与方数量
    ///
    /// # 返回值
    /// 成功时返回(秘密值, 份额向量)的元组
    ///
    /// # 示例
    /// ```
    /// let (secret, shares) = ShamirSecretSharing::generate_random_shares(2, 3)?;
    /// let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..2], 2)?;
    /// assert_eq!(reconstructed, secret);
    /// ```
    pub fn generate_random_shares(threshold: usize, total_parties: usize) -> Result<(u64, Vec<Share>)> {
        let mut rng = rand::thread_rng();
        let secret = rng.gen_range(0..FIELD_PRIME);
        let shares = Self::share(&secret, threshold, total_parties)?;
        Ok((secret, shares))
    }
    
    /// 计算多项式在给定点的值（霍纳方法）
    ///
    /// 使用霍纳方法（Horner's method）高效计算多项式f(x) = a₀ + a₁x + a₂x² + ... + aₙx^n的值。
    /// 霍纳方法通过重新组织计算顺序减少乘法次数，提高计算效率。
    ///
    /// # 参数
    /// - `coefficients`: 多项式系数数组，从常数项开始
    /// - `x`: 计算点的x坐标
    ///
    /// # 返回值
    /// 返回多项式在点x处的值
    ///
    /// # 算法复杂度
    /// - 时间复杂度：O(n)，其中n是多项式的度数
    /// - 空间复杂度：O(1)
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let coeffs = vec![5, 3, 2]; // f(x) = 5 + 3x + 2x²
    /// let result = scheme.evaluate_polynomial(&coeffs, 2); // f(2) = 19
    /// ```
    pub fn evaluate_polynomial(&self, coefficients: &[u64], x: u64) -> u64 {
        if coefficients.is_empty() {
            return 0;
        }
        
        // 霍纳方法：从最高次项开始，逆向计算
        // f(x) = a₀ + x(a₁ + x(a₂ + x(a₃ + ...)))
        let mut result = coefficients[coefficients.len() - 1];
        
        for &coeff in coefficients.iter().rev().skip(1) {
            result = field_add(field_mul(result, x), coeff);
        }
        
        result
    }
    
    
    /// 快速多项式更新 - 添加新系数
    ///
    /// 高效地更新现有多项式，添加新的系数项。这比重新构造整个多项式要快。
    /// 适用于动态调整秘密分享参数的场景。
    ///
    /// # 参数
    /// - `old_coefficients`: 原有的多项式系数
    /// - `new_coefficient`: 要添加的新系数
    /// - `degree`: 新系数对应的度数
    ///
    /// # 返回值
    /// 返回更新后的多项式系数
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let old_coeffs = vec![5, 3];  // f(x) = 5 + 3x
    /// let new_coeffs = scheme.update_polynomial(&old_coeffs, 2, 2);  // 添加 2x²
    /// // 结果: f(x) = 5 + 3x + 2x²
    /// ```
    pub fn update_polynomial(&self, old_coefficients: &[u64], new_coefficient: u64, degree: usize) -> Vec<u64> {
        let mut coefficients = old_coefficients.to_vec();
        
        // 确保数组大小足够
        if coefficients.len() <= degree {
            coefficients.resize(degree + 1, 0);
        }
        
        // 添加新系数（在有限域中进行加法）
        coefficients[degree] = field_add(coefficients[degree], new_coefficient);
        
        coefficients
    }
    
    /// 多项式合并 - 两个多项式相加
    ///
    /// 高效地合并两个多项式，计算它们的和。这在多方计算中经常用到。
    ///
    /// # 参数
    /// - `poly1`: 第一个多项式的系数
    /// - `poly2`: 第二个多项式的系数
    ///
    /// # 返回值
    /// 返回两个多项式和的系数
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let p1 = vec![1, 2, 3];  // 1 + 2x + 3x²
    /// let p2 = vec![4, 5];     // 4 + 5x
    /// let sum = scheme.merge_polynomials(&p1, &p2);  // 5 + 7x + 3x²
    /// ```
    pub fn merge_polynomials(&self, poly1: &[u64], poly2: &[u64]) -> Vec<u64> {
        let max_len = poly1.len().max(poly2.len());
        let mut result = Vec::with_capacity(max_len);
        
        for i in 0..max_len {
            let c1 = poly1.get(i).cloned().unwrap_or(0);
            let c2 = poly2.get(i).cloned().unwrap_or(0);
            result.push(field_add(c1, c2));
        }
        
        result
    }
    
    /// 增量式份额更新
    ///
    /// 基于现有份额和多项式更新，高效地计算新的份额值。
    /// 避免重新计算整个多项式，只计算增量部分。
    ///
    /// # 参数
    /// - `old_shares`: 现有的份额
    /// - `delta_coefficients`: 多项式变化的系数
    ///
    /// # 返回值
    /// 返回更新后的份额
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let old_shares = vec![Share::new(1, 10), Share::new(2, 15)];
    /// let delta = vec![0, 5];  // 添加 5x 项
    /// let new_shares = scheme.incremental_share_update(&old_shares, &delta);
    /// ```
    pub fn incremental_share_update(&self, old_shares: &[Share], delta_coefficients: &[u64]) -> Vec<Share> {
        old_shares.iter().map(|share| {
            let delta_value = self.evaluate_polynomial(delta_coefficients, share.x);
            let new_y = field_add(share.y, delta_value);
            Share::new(share.x, new_y)
        }).collect()
    }
    
    /// 快速份额验证 - 使用多项式一致性检查
    ///
    /// 通过检查份额是否满足多项式关系来快速验证份额的一致性。
    /// 比完整重构验证要快得多。
    ///
    /// # 参数
    /// - `shares`: 要验证的份额
    /// - `threshold`: 预期的门限值
    ///
    /// # 返回值
    /// 如果份额一致返回true，否则返回false
    ///
    /// # 算法
    /// 使用差分检验法，检查相邻份额之间的差值是否符合多项式规律
    pub fn fast_share_consistency_check(&self, shares: &[Share], threshold: usize) -> bool {
        if shares.len() < threshold {
            return false;
        }
        
        // 如果只有门限数量的份额，直接尝试重构
        if shares.len() == threshold {
            return self.lagrange_interpolation(shares).is_ok();
        }
        
        // 使用多个子集重构，检查结果一致性
        let mut previous_secret = None;
        
        for i in 0..=(shares.len() - threshold) {
            let subset = &shares[i..i + threshold];
            if let Ok(secret) = self.lagrange_interpolation(subset) {
                if let Some(prev) = previous_secret {
                    if prev != secret {
                        return false;
                    }
                } else {
                    previous_secret = Some(secret);
                }
            } else {
                return false;
            }
        }
        
        true
    }
    
    /// 生成横坐标序列
    ///
    /// 根据指定的策略生成份额的横坐标。支持顺序、随机和种子控制的生成方式。
    ///
    /// # 参数
    /// - `total_parties`: 参与方总数
    /// - `strategy`: 横坐标选择策略
    ///
    /// # 返回值
    /// 返回生成的横坐标向量
    ///
    /// # 安全性
    /// - 确保生成的横坐标在有效范围内且不重复
    /// - 种子控制的生成方式提供可重现性
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let x_coords = scheme.generate_x_coordinates(5, XCoordinateStrategy::Sequential);
    /// // 结果: [1, 2, 3, 4, 5]
    /// 
    /// let seeded_coords = scheme.generate_x_coordinates(5, XCoordinateStrategy::SeededRandom(12345));
    /// // 结果: 可重现的随机坐标序列
    /// ```
    pub fn generate_x_coordinates(&self, total_parties: usize, strategy: XCoordinateStrategy) -> Vec<u64> {
        match strategy {
            XCoordinateStrategy::Sequential => {
                (1..=total_parties as u64).collect()
            }
            
            XCoordinateStrategy::Random => {
                let mut rng = rand::thread_rng();
                let mut coords = Vec::with_capacity(total_parties);
                let mut used_coords = std::collections::HashSet::new();
                
                while coords.len() < total_parties {
                    // 生成范围在 [1, FIELD_PRIME) 的随机横坐标
                    let x = rng.gen_range(1..FIELD_PRIME);
                    if used_coords.insert(x) {
                        coords.push(x);
                    }
                }
                
                coords
            }
            
            XCoordinateStrategy::SeededRandom(seed) => {
                let mut rng = StdRng::seed_from_u64(seed);
                let mut coords = Vec::with_capacity(total_parties);
                let mut used_coords = std::collections::HashSet::new();
                
                while coords.len() < total_parties {
                    // 使用种子生成可重现的随机横坐标
                    let x = rng.gen_range(1..FIELD_PRIME);
                    if used_coords.insert(x) {
                        coords.push(x);
                    }
                }
                
                coords
            }
        }
    }
    
    /// 使用指定横坐标策略分享秘密
    ///
    /// 提供对横坐标生成策略的完全控制，支持确定性和随机性选择。
    ///
    /// # 参数
    /// - `secret`: 要分享的秘密值
    /// - `threshold`: 重构所需的最小份额数量
    /// - `total_parties`: 参与方总数
    /// - `strategy`: 横坐标选择策略
    ///
    /// # 返回值
    /// 成功时返回包含份额的向量
    ///
    /// # 错误
    /// 当参数无效时返回相应错误
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let secret = 42u64;
    /// 
    /// // 使用顺序横坐标
    /// let shares1 = scheme.share_with_coordinates(&secret, 2, 3, XCoordinateStrategy::Sequential)?;
    /// 
    /// // 使用种子控制的随机横坐标
    /// let shares2 = scheme.share_with_coordinates(&secret, 2, 3, XCoordinateStrategy::SeededRandom(12345))?;
    /// 
    /// // 两次使用相同种子会生成相同的横坐标
    /// let shares3 = scheme.share_with_coordinates(&secret, 2, 3, XCoordinateStrategy::SeededRandom(12345))?;
    /// assert_eq!(shares2[0].x, shares3[0].x); // 横坐标相同
    /// ```
    pub fn share_with_coordinates(&self, secret: &u64, threshold: usize, total_parties: usize, 
                                 strategy: XCoordinateStrategy) -> Result<Vec<Share>> {
        // 验证参数
        super::validate_threshold_params(threshold, total_parties)?;
        
        if !super::validate_field_element(*secret) {
            return Err(MpcError::CryptographicError("Secret value out of field range".to_string()));
        }
        
        // 生成横坐标
        let x_coordinates = self.generate_x_coordinates(total_parties, strategy);
        
        // 生成多项式系数
        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(*secret); // a_0 = secret
        
        match strategy {
            XCoordinateStrategy::SeededRandom(seed) => {
                // 如果使用种子控制横坐标，也使用相同种子的另一个生成器来生成系数
                // 这样整个分享过程都是确定的
                let mut rng = StdRng::seed_from_u64(seed.wrapping_add(1));
                for _ in 1..threshold {
                    let coeff = rng.gen_range(0..FIELD_PRIME);
                    coefficients.push(coeff);
                }
            }
            _ => {
                let mut rng = rand::thread_rng();
                for _ in 1..threshold {
                    let coeff = rng.gen_range(0..FIELD_PRIME);
                    coefficients.push(coeff);
                }
            }
        }
        
        // 计算份额
        let mut shares = Vec::with_capacity(total_parties);
        for &x in &x_coordinates {
            let y = self.evaluate_polynomial(&coefficients, x);
            shares.push(Share::new(x, y));
        }
        
        Ok(shares)
    }
    
    /// 使用种子控制生成确定性份额
    ///
    /// 这是一个便利方法，专门用于生成完全确定的份额（包括横坐标和多项式系数）。
    ///
    /// # 参数
    /// - `secret`: 要分享的秘密值
    /// - `threshold`: 重构所需的最小份额数量
    /// - `total_parties`: 参与方总数
    /// - `seed`: 随机数种子
    ///
    /// # 返回值
    /// 成功时返回包含份额的向量
    ///
    /// # 特性
    /// - 完全确定性：相同输入始终产生相同输出
    /// - 可重现性：适用于测试和调试
    /// - 安全性：保持Shamir方案的数学安全性
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let secret = 123u64;
    /// let seed = 54321u64;
    /// 
    /// let shares1 = scheme.deterministic_share(&secret, 2, 3, seed)?;
    /// let shares2 = scheme.deterministic_share(&secret, 2, 3, seed)?;
    /// 
    /// // 两次生成的份额完全相同
    /// assert_eq!(shares1, shares2);
    /// ```
    pub fn deterministic_share(&self, secret: &u64, threshold: usize, total_parties: usize, 
                              seed: u64) -> Result<Vec<Share>> {
        self.share_with_coordinates(secret, threshold, total_parties, XCoordinateStrategy::SeededRandom(seed))
    }
    
    /// 预计算拉格朗日系数
    ///
    /// 预计算给定x坐标组合的拉格朗日系数，用于快速重构。
    /// 适用于重复使用相同份额组合进行重构的场景。
    ///
    /// # 参数
    /// - `x_coords`: 参与重构的x坐标
    ///
    /// # 返回值
    /// 返回预计算的拉格朗日系数
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let x_coords = vec![1, 2, 3];
    /// let lagrange_coeffs = scheme.precompute_lagrange_coefficients(&x_coords)?;
    /// ```
    pub fn precompute_lagrange_coefficients(&self, x_coords: &[u64]) -> Result<Vec<u64>> {
        let mut coefficients = Vec::with_capacity(x_coords.len());
        
        for i in 0..x_coords.len() {
            let mut numerator = 1u64;
            let mut denominator = 1u64;
            
            for j in 0..x_coords.len() {
                if i != j {
                    // 计算 (0 - x_j) 和 (x_i - x_j)
                    let neg_xj = field_sub(0, x_coords[j]);
                    numerator = field_mul(numerator, neg_xj);
                    
                    let diff = field_sub(x_coords[i], x_coords[j]);
                    denominator = field_mul(denominator, diff);
                }
            }
            
            let denominator_inv = field_inv(denominator)
                .ok_or_else(|| MpcError::CryptographicError("No modular inverse exists".to_string()))?;
            let coeff = field_mul(numerator, denominator_inv);
            coefficients.push(coeff);
        }
        
        Ok(coefficients)
    }
    
    /// 使用预计算系数快速重构
    ///
    /// 使用预先计算的拉格朗日系数快速重构秘密，避免重复计算。
    ///
    /// # 参数
    /// - `shares`: 参与重构的份额
    /// - `lagrange_coeffs`: 预计算的拉格朗日系数
    ///
    /// # 返回值
    /// 返回重构的秘密
    ///
    /// # 前提条件
    /// lagrange_coeffs必须与shares的x坐标对应
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let shares = vec![Share::new(1, 10), Share::new(2, 15)];
    /// let x_coords = vec![1, 2];
    /// let coeffs = scheme.precompute_lagrange_coefficients(&x_coords)?;
    /// let secret = scheme.fast_reconstruct_with_coeffs(&shares, &coeffs);
    /// ```
    pub fn fast_reconstruct_with_coeffs(&self, shares: &[Share], lagrange_coeffs: &[u64]) -> u64 {
        if shares.len() != lagrange_coeffs.len() {
            return 0; // 错误处理：长度不匹配
        }
        
        let mut result = 0u64;
        for (share, &coeff) in shares.iter().zip(lagrange_coeffs.iter()) {
            result = field_add(result, field_mul(share.y, coeff));
        }
        
        result
    }
    
    /// 动态阈值调整
    ///
    /// 在不改变秘密的情况下，调整份额的阈值。这通过重新分发份额实现。
    /// 适用于安全需求变化的场景。
    ///
    /// # 参数
    /// - `shares`: 现有份额
    /// - `old_threshold`: 原阈值
    /// - `new_threshold`: 新阈值
    /// - `new_total_parties`: 新的参与方总数
    ///
    /// # 返回值
    /// 返回调整后的份额
    ///
    /// # 算法
    /// 1. 使用现有份额重构秘密
    /// 2. 使用新参数重新分享秘密
    ///
    /// # 示例
    /// ```
    /// let scheme = ShamirSecretSharing::new();
    /// let old_shares = // ... 现有的(2,3)份额
    /// let new_shares = scheme.adjust_threshold(&old_shares, 2, 3, 5)?;
    /// // 现在是(3,5)份额
    /// ```
    pub fn adjust_threshold(&self, shares: &[Share], old_threshold: usize, 
                           new_threshold: usize, new_total_parties: usize) -> Result<Vec<Share>> {
        // 验证参数
        if shares.len() < old_threshold {
            return Err(MpcError::InsufficientShares);
        }
        
        // 重构秘密
        let secret = self.lagrange_interpolation(&shares[..old_threshold])?;
        
        // 使用新参数重新分享
        Self::share(&secret, new_threshold, new_total_parties)
    }
    
    /// 份额压缩存储
    ///
    /// 将多个份额压缩为紧凑格式，减少存储空间。
    /// 适用于大规模部署中的存储优化。
    ///
    /// # 参数
    /// - `shares`: 要压缩的份额
    ///
    /// # 返回值
    /// 返回压缩后的字节数组
    ///
    /// # 格式
    /// 每个份额使用16字节：8字节x坐标 + 8字节y坐标
    pub fn compress_shares(&self, shares: &[Share]) -> Vec<u8> {
        let mut compressed = Vec::with_capacity(shares.len() * 16);
        
        for share in shares {
            compressed.extend_from_slice(&share.x.to_le_bytes());
            compressed.extend_from_slice(&share.y.to_le_bytes());
        }
        
        compressed
    }
    
    /// 份额解压缩
    ///
    /// 从压缩格式恢复份额数据。
    ///
    /// # 参数
    /// - `compressed_data`: 压缩的字节数据
    ///
    /// # 返回值
    /// 返回解压缩的份额
    ///
    /// # 错误
    /// 如果数据长度不是16的倍数，返回错误
    pub fn decompress_shares(&self, compressed_data: &[u8]) -> Result<Vec<Share>> {
        if compressed_data.len() % 16 != 0 {
            return Err(MpcError::CryptographicError("Invalid compressed data length".to_string()));
        }
        
        let mut shares = Vec::with_capacity(compressed_data.len() / 16);
        
        for chunk in compressed_data.chunks(16) {
            let x = u64::from_le_bytes(chunk[0..8].try_into()
                .map_err(|_| MpcError::CryptographicError("Invalid x coordinate".to_string()))?);
            let y = u64::from_le_bytes(chunk[8..16].try_into()
                .map_err(|_| MpcError::CryptographicError("Invalid y coordinate".to_string()))?);
            shares.push(Share::new(x, y));
        }
        
        Ok(shares)
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
    pub fn lagrange_interpolation(&self, shares: &[Share]) -> Result<u64> {
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
        // 验证参数
        super::validate_threshold_params(threshold, total_parties)?;
        
        // 验证秘密值
        if !super::validate_field_element(*secret) {
            return Err(MpcError::CryptographicError("Secret value out of field range".to_string()));
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

/// 高级Shamir秘密分享的测试模块
#[cfg(test)]
mod advanced_tests {
    use super::*;
    use crate::secret_sharing::{Share, field_add};
    
    #[test]
    fn test_horner_polynomial_evaluation() {
        let scheme = ShamirSecretSharing::new();
        let coeffs = vec![5, 3, 2]; // f(x) = 5 + 3x + 2x²
        
        // f(2) = 5 + 3*2 + 2*4 = 5 + 6 + 8 = 19
        let result = scheme.evaluate_polynomial(&coeffs, 2);
        assert_eq!(result, 19);
        
        // f(0) = 5
        let result = scheme.evaluate_polynomial(&coeffs, 0);
        assert_eq!(result, 5);
    }
    
    #[test]
    fn test_multiple_polynomial_evaluation() {
        let scheme = ShamirSecretSharing::new();
        let coeffs = vec![5, 3, 2]; // f(x) = 5 + 3x + 2x²
        let x_values = vec![0, 1, 2, 3];
        
        // 单独计算每个点的值
        let mut results = Vec::new();
        for &x in &x_values {
            results.push(scheme.evaluate_polynomial(&coeffs, x));
        }
        
        // 验证每个点的值
        assert_eq!(results[0], 5);  // f(0) = 5
        assert_eq!(results[1], 10); // f(1) = 5 + 3 + 2 = 10
        assert_eq!(results[2], 19); // f(2) = 5 + 6 + 8 = 19
        assert_eq!(results[3], 32); // f(3) = 5 + 9 + 18 = 32
    }
    
    #[test]
    fn test_polynomial_update() {
        let scheme = ShamirSecretSharing::new();
        let old_coeffs = vec![5, 3]; // f(x) = 5 + 3x
        
        // 添加 2x² 项
        let new_coeffs = scheme.update_polynomial(&old_coeffs, 2, 2);
        assert_eq!(new_coeffs, vec![5, 3, 2]);
        
        // 更新常数项
        let updated_coeffs = scheme.update_polynomial(&new_coeffs, 10, 0);
        assert_eq!(updated_coeffs[0], field_add(5, 10));
    }
    
    #[test]
    fn test_polynomial_merging() {
        let scheme = ShamirSecretSharing::new();
        let poly1 = vec![1, 2, 3]; // 1 + 2x + 3x²
        let poly2 = vec![4, 5];    // 4 + 5x
        
        let merged = scheme.merge_polynomials(&poly1, &poly2);
        assert_eq!(merged, vec![5, 7, 3]); // 5 + 7x + 3x²
    }
    
    #[test]
    fn test_incremental_share_update() {
        let scheme = ShamirSecretSharing::new();
        let old_shares = vec![
            Share::new(1, 10),
            Share::new(2, 15),
            Share::new(3, 20)
        ];
        
        let delta_coeffs = vec![0, 5]; // 添加 5x 项
        let new_shares = scheme.incremental_share_update(&old_shares, &delta_coeffs);
        
        // 验证更新后的值
        assert_eq!(new_shares[0].y, field_add(10, 5)); // 10 + 5*1
        assert_eq!(new_shares[1].y, field_add(15, 10)); // 15 + 5*2
        assert_eq!(new_shares[2].y, field_add(20, 15)); // 20 + 5*3
    }
    
    #[test]
    fn test_multiple_secret_sharing() {
        let _scheme = ShamirSecretSharing::new();
        let secrets = vec![100, 200, 300];
        
        // 分别生成每个秘密的份额
        let mut all_shares = Vec::new();
        for &secret in &secrets {
            let shares = ShamirSecretSharing::share(&secret, 2, 3).unwrap();
            all_shares.push(shares);
        }
        assert_eq!(all_shares.len(), 3);
        
        // 验证每组份额都能正确重构对应的秘密
        for (i, shares) in all_shares.iter().enumerate() {
            assert_eq!(shares.len(), 3);
            let reconstructed = ShamirSecretSharing::reconstruct(&shares[..2], 2).unwrap();
            assert_eq!(reconstructed, secrets[i]);
        }
    }
    
    #[test]
    fn test_precompute_lagrange_coefficients() {
        let scheme = ShamirSecretSharing::new();
        let x_coords = vec![1, 2, 3];
        
        let coeffs = scheme.precompute_lagrange_coefficients(&x_coords).unwrap();
        assert_eq!(coeffs.len(), 3);
        
        // 使用预计算系数重构
        let shares = vec![
            Share::new(1, 10),
            Share::new(2, 20),
            Share::new(3, 30)
        ];
        
        let secret1 = scheme.lagrange_interpolation(&shares).unwrap();
        let secret2 = scheme.fast_reconstruct_with_coeffs(&shares, &coeffs);
        assert_eq!(secret1, secret2);
    }
    
    #[test]
    fn test_threshold_adjustment() {
        let scheme = ShamirSecretSharing::new();
        let secret = 42u64;
        
        // 创建 (2,3) 份额
        let old_shares = ShamirSecretSharing::share(&secret, 2, 3).unwrap();
        
        // 调整为 (3,5) 份额
        let new_shares = scheme.adjust_threshold(&old_shares, 2, 3, 5).unwrap();
        assert_eq!(new_shares.len(), 5);
        
        // 验证新份额能正确重构
        let reconstructed = ShamirSecretSharing::reconstruct(&new_shares[..3], 3).unwrap();
        assert_eq!(reconstructed, secret);
    }
    
    #[test]
    fn test_share_compression() {
        let scheme = ShamirSecretSharing::new();
        let shares = vec![
            Share::new(1, 100),
            Share::new(2, 200),
            Share::new(3, 300)
        ];
        
        // 压缩和解压缩
        let compressed = scheme.compress_shares(&shares);
        assert_eq!(compressed.len(), 48); // 3 shares * 16 bytes each
        
        let decompressed = scheme.decompress_shares(&compressed).unwrap();
        assert_eq!(decompressed, shares);
    }
    
    #[test]
    fn test_fast_consistency_check() {
        let scheme = ShamirSecretSharing::new();
        let secret = 123u64;
        let shares = ShamirSecretSharing::share(&secret, 2, 4).unwrap();
        
        // 有效份额应该通过一致性检查
        assert!(scheme.fast_share_consistency_check(&shares, 2));
        
        // 修改一个份额，应该失败
        let mut invalid_shares = shares.clone();
        invalid_shares[0].y = field_add(invalid_shares[0].y, 1);
        assert!(!scheme.fast_share_consistency_check(&invalid_shares, 2));
    }
    
    #[test]
    fn test_performance_comparison() {
        let scheme = ShamirSecretSharing::new();
        let x_coords = vec![1, 2, 3];
        let shares = vec![
            Share::new(1, 12345),
            Share::new(2, 23456),
            Share::new(3, 34567)
        ];
        
        // 预计算系数
        let coeffs = scheme.precompute_lagrange_coefficients(&x_coords).unwrap();
        
        // 多次重构测试性能提升
        for _ in 0..1000 {
            let secret1 = scheme.lagrange_interpolation(&shares).unwrap();
            let secret2 = scheme.fast_reconstruct_with_coeffs(&shares, &coeffs);
            assert_eq!(secret1, secret2);
        }
    }

    #[test]
    fn test_coordinate_strategy_sequential() {
        let scheme = ShamirSecretSharing::new();
        let coords = scheme.generate_x_coordinates(5, XCoordinateStrategy::Sequential);
        
        assert_eq!(coords.len(), 5);
        assert_eq!(coords, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_coordinate_strategy_random() {
        let scheme = ShamirSecretSharing::new();
        let coords1 = scheme.generate_x_coordinates(5, XCoordinateStrategy::Random);
        let coords2 = scheme.generate_x_coordinates(5, XCoordinateStrategy::Random);
        
        assert_eq!(coords1.len(), 5);
        assert_eq!(coords2.len(), 5);
        
        // 随机生成的坐标应该不同
        assert_ne!(coords1, coords2);
        
        // 确保没有重复坐标
        let mut unique_coords = std::collections::HashSet::new();
        for &coord in &coords1 {
            assert!(unique_coords.insert(coord), "Duplicate coordinate found: {}", coord);
        }
    }

    #[test]
    fn test_coordinate_strategy_seeded_random() {
        let scheme = ShamirSecretSharing::new();
        let seed = 12345u64;
        
        // 使用相同种子生成的坐标应该相同
        let coords1 = scheme.generate_x_coordinates(5, XCoordinateStrategy::SeededRandom(seed));
        let coords2 = scheme.generate_x_coordinates(5, XCoordinateStrategy::SeededRandom(seed));
        
        assert_eq!(coords1.len(), 5);
        assert_eq!(coords2.len(), 5);
        assert_eq!(coords1, coords2);
        
        // 使用不同种子应该生成不同坐标
        let coords3 = scheme.generate_x_coordinates(5, XCoordinateStrategy::SeededRandom(54321));
        assert_ne!(coords1, coords3);
        
        // 确保坐标在有效范围内
        for &coord in &coords1 {
            assert!(coord > 0 && coord < FIELD_PRIME);
        }
    }

    #[test]
    fn test_share_with_coordinates_sequential() {
        let scheme = ShamirSecretSharing::new();
        let secret = 42u64;
        let threshold = 2;
        let total_parties = 3;
        
        let shares = scheme.share_with_coordinates(&secret, threshold, total_parties, 
                                                  XCoordinateStrategy::Sequential).unwrap();
        
        assert_eq!(shares.len(), total_parties);
        assert_eq!(shares[0].x, 1);
        assert_eq!(shares[1].x, 2);
        assert_eq!(shares[2].x, 3);
        
        // 验证能够正确重构
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[..threshold], threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_share_with_coordinates_seeded_deterministic() {
        let scheme = ShamirSecretSharing::new();
        let secret = 123u64;
        let threshold = 2;
        let total_parties = 4;
        let seed = 98765u64;
        
        // 使用相同种子生成两次份额
        let shares1 = scheme.share_with_coordinates(&secret, threshold, total_parties, 
                                                   XCoordinateStrategy::SeededRandom(seed)).unwrap();
        let shares2 = scheme.share_with_coordinates(&secret, threshold, total_parties, 
                                                   XCoordinateStrategy::SeededRandom(seed)).unwrap();
        
        assert_eq!(shares1.len(), total_parties);
        assert_eq!(shares2.len(), total_parties);
        
        // 横坐标应该相同（确定性）
        for i in 0..total_parties {
            assert_eq!(shares1[i].x, shares2[i].x);
        }
        
        // 份额值也应该相同（完全确定性）
        for i in 0..total_parties {
            assert_eq!(shares1[i].y, shares2[i].y);
        }
        
        // 验证两组份额都能正确重构
        let reconstructed1 = ShamirSecretSharing::reconstruct(&shares1[..threshold], threshold).unwrap();
        let reconstructed2 = ShamirSecretSharing::reconstruct(&shares2[..threshold], threshold).unwrap();
        assert_eq!(reconstructed1, secret);
        assert_eq!(reconstructed2, secret);
    }

    #[test]
    fn test_deterministic_share_convenience_method() {
        let scheme = ShamirSecretSharing::new();
        let secret = 456u64;
        let threshold = 3;
        let total_parties = 5;
        let seed = 11111u64;
        
        // 使用便捷方法生成确定性份额
        let shares1 = scheme.deterministic_share(&secret, threshold, total_parties, seed).unwrap();
        let shares2 = scheme.deterministic_share(&secret, threshold, total_parties, seed).unwrap();
        
        assert_eq!(shares1.len(), total_parties);
        assert_eq!(shares2.len(), total_parties);
        
        // 完全相同的份额
        for i in 0..total_parties {
            assert_eq!(shares1[i].x, shares2[i].x);
            assert_eq!(shares1[i].y, shares2[i].y);
        }
        
        // 验证重构
        let reconstructed = ShamirSecretSharing::reconstruct(&shares1[..threshold], threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_different_seeds_produce_different_coordinates() {
        let scheme = ShamirSecretSharing::new();
        let secret = 789u64;
        let threshold = 2;
        let total_parties = 3;
        
        let shares1 = scheme.share_with_coordinates(&secret, threshold, total_parties, 
                                                   XCoordinateStrategy::SeededRandom(1111)).unwrap();
        let shares2 = scheme.share_with_coordinates(&secret, threshold, total_parties, 
                                                   XCoordinateStrategy::SeededRandom(2222)).unwrap();
        
        // 不同种子应该产生不同的横坐标
        let mut coordinates_differ = false;
        for i in 0..total_parties {
            if shares1[i].x != shares2[i].x {
                coordinates_differ = true;
                break;
            }
        }
        assert!(coordinates_differ, "Different seeds should produce different coordinates");
        
        // 但是都应该能正确重构相同的秘密
        let reconstructed1 = ShamirSecretSharing::reconstruct(&shares1[..threshold], threshold).unwrap();
        let reconstructed2 = ShamirSecretSharing::reconstruct(&shares2[..threshold], threshold).unwrap();
        assert_eq!(reconstructed1, secret);
        assert_eq!(reconstructed2, secret);
    }

    #[test]
    fn test_coordinate_uniqueness() {
        let scheme = ShamirSecretSharing::new();
        let total_parties = 10;
        
        for seed in [12345, 54321, 99999] {
            let coords = scheme.generate_x_coordinates(total_parties, 
                                                      XCoordinateStrategy::SeededRandom(seed));
            
            // 验证没有重复坐标
            let mut unique_coords = std::collections::HashSet::new();
            for &coord in &coords {
                assert!(unique_coords.insert(coord), 
                       "Duplicate coordinate {} found with seed {}", coord, seed);
            }
            
            assert_eq!(unique_coords.len(), total_parties);
        }
    }

    #[test]
    fn test_large_party_count_with_seeded_coordinates() {
        let scheme = ShamirSecretSharing::new();
        let secret = 999999u64;
        let threshold = 50;
        let total_parties = 100;
        let seed = 777777u64;
        
        let shares = scheme.share_with_coordinates(&secret, threshold, total_parties, 
                                                  XCoordinateStrategy::SeededRandom(seed)).unwrap();
        
        assert_eq!(shares.len(), total_parties);
        
        // 验证坐标唯一性
        let mut unique_coords = std::collections::HashSet::new();
        for share in &shares {
            assert!(unique_coords.insert(share.x), 
                   "Duplicate coordinate found: {}", share.x);
        }
        
        // 验证重构
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[..threshold], threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }
}

impl super::MultiplicationSecretSharing for ShamirSecretSharing {
    /// Shamir 分享乘法
    /// 
    /// 计算两个 Shamir 分享的乘积。注意：这会导致多项式度数翻倍，
    /// 因此结果分享需要 2t-1 个才能重构，而不是原来的 t 个。
    /// 在实际应用中，通常需要度数降低协议。
    /// 
    /// # 参数
    /// 
    /// * `share1` - 第一个分享
    /// * `share2` - 第二个分享
    /// 
    /// # 返回值
    /// 
    /// 返回乘积分享，注意度数已经翻倍
    /// 
    /// # 安全性
    /// 
    /// 该方法实现了 Shamir 分享的局部乘法，但结果分享的安全阈值变化了。
    /// 如果原始分享是 (t,n) 方案，则乘积分享是 (2t-1,n) 方案。
    fn mul_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share> {
        if share1.x != share2.x {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let y = field_mul(share1.y, share2.y);
        Ok(Share::new(share1.x, y))
    }

    /// Beaver 三元组乘法实现
    /// 
    /// 使用 Beaver 三元组实现安全的分享乘法，保持原有的阈值特性。
    /// 该协议是 BGW 协议的核心组件。
    /// 
    /// # 参数
    /// 
    /// * `share_x` - 第一个要相乘的分享
    /// * `share_y` - 第二个要相乘的分享
    /// * `beaver_a` - Beaver 三元组中的 a 分享
    /// * `beaver_b` - Beaver 三元组中的 b 分享
    /// * `beaver_c` - Beaver 三元组中的 c 分享 (c = a * b)
    /// * `d` - 公开值 d = x - a
    /// * `e` - 公开值 e = y - b
    /// 
    /// # 返回值
    /// 
    /// 返回 x * y 的分享
    /// 
    /// # 协议详细
    /// 
    /// Beaver 乘法协议：
    /// 1. 各方计算 d_i = x_i - a_i, e_i = y_i - b_i
    /// 2. 重构并公开 d = Σd_i, e = Σe_i
    /// 3. 各方计算 z_i = c_i + d·b_i + e·a_i + d·e (仅party 0计算最后一项)
    fn beaver_mul(
        share_x: &Self::Share,
        share_y: &Self::Share,
        beaver_a: &Self::Share,
        beaver_b: &Self::Share,
        beaver_c: &Self::Share,
        d: &Self::Secret,
        e: &Self::Secret,
    ) -> Result<Self::Share> {
        // 验证所有分享的 x 坐标一致
        if share_x.x != share_y.x || 
           share_x.x != beaver_a.x || 
           share_x.x != beaver_b.x || 
           share_x.x != beaver_c.x {
            return Err(MpcError::InvalidSecretShare);
        }

        // 计算 z = c + d*b + e*a + d*e
        // 注意：在实际协议中，d*e 项只有一个参与方（通常是 party 0）添加
        let db = field_mul(*d, beaver_b.y);
        let ea = field_mul(*e, beaver_a.y);
        let de = if share_x.x == 1 { // 假设 party 0 对应 x=1
            field_mul(*d, *e)
        } else {
            0
        };
        
        let result_y = field_add(
            field_add(beaver_c.y, db),
            field_add(ea, de)
        );
        
        Ok(Share::new(share_x.x, result_y))
    }

    /// 生成 Beaver 三元组
    /// 
    /// 生成随机的 Beaver 三元组 (a, b, c)，其中 c = a * b。
    /// 在实际的 MPC 协议中，这通常在离线预处理阶段完成。
    /// 
    /// # 参数
    /// 
    /// * `threshold` - 重构阈值
    /// * `total_parties` - 总参与方数量
    /// 
    /// # 返回值
    /// 
    /// 返回三个向量，分别包含所有参与方的 a、b、c 分享
    /// 
    /// # 安全性
    /// 
    /// 该方法生成的三元组满足 MPC 所需的随机性和正确性要求。
    /// 在实际协议中，应当使用分布式的生成协议而不是可信方生成。
    fn generate_beaver_triple(
        threshold: usize,
        total_parties: usize,
    ) -> Result<(Vec<Self::Share>, Vec<Self::Share>, Vec<Self::Share>)> {
        let mut rng = rand::thread_rng();
        
        // 生成随机的 a 和 b
        let a: u64 = rng.gen_range(0..FIELD_PRIME);
        let b: u64 = rng.gen_range(0..FIELD_PRIME);
        let c = field_mul(a, b);
        
        // 对 a, b, c 分别进行 Shamir 分享
        let shares_a = Self::share(&a, threshold, total_parties)?;
        let shares_b = Self::share(&b, threshold, total_parties)?;
        let shares_c = Self::share(&c, threshold, total_parties)?;
        
        Ok((shares_a, shares_b, shares_c))
    }
}
