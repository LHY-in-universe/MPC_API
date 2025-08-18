//! 复制秘密分享实现 (Replicated Secret Sharing)
//!
//! 复制秘密分享是一种高效的秘密分享方案，特别适用于3方安全多方计算。
//! 在这个方案中，每个参与方持有多个随机值的组合，这些值被复制给其他参与方。
//!
//! ## 核心特性
//! - **高效性**: 加法和乘法运算都很高效，无需通信
//! - **简单性**: 实现相对简单，计算开销小
//! - **3方优化**: 特别适用于3方MPC协议
//! - **信息论安全**: 提供完美的安全性保证
//!
//! ## 数学原理
//! 对于3方复制秘密分享：
//! - 秘密 s = r1 + r2 + r3 (mod p)
//! - Party 1 持有 (r1, r2)
//! - Party 2 持有 (r2, r3)  
//! - Party 3 持有 (r3, r1)
//! 
//! 每个参与方都持有两个随机值，任意两方可以重构秘密。
//!
//! ## 安全模型
//! - **隐私性**: 任何单个参与方都无法获得秘密信息
//! - **完整性**: 通过冗余信息可以检测和纠正错误
//! - **门限**: 适用于 (2,3) 门限方案
//!
//! ## 适用场景
//! - 3方安全计算协议
//! - 高频率的安全计算
//! - 需要高效乘法的场景
//! - 分布式系统中的秘密管理

use super::{FIELD_PRIME, field_add, field_sub, field_mul};
use crate::{MpcError, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// 复制秘密分享的份额结构
///
/// 在复制秘密分享中，每个参与方持有两个相关的随机值。
/// 这些值在参与方之间有重叠，形成复制结构。
///
/// # 字段说明
/// - `party_id`: 持有该份额的参与方标识符
/// - `share1`: 第一个随机值分量
/// - `share2`: 第二个随机值分量
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplicatedShare {
    /// 参与方标识符
    pub party_id: usize,
    /// 第一个分量
    pub share1: u64,
    /// 第二个分量
    pub share2: u64,
}

impl ReplicatedShare {
    /// 创建新的复制秘密分享份额
    ///
    /// # 参数
    /// - `party_id`: 参与方标识符
    /// - `share1`: 第一个分量值
    /// - `share2`: 第二个分量值
    ///
    /// # 返回值
    /// 返回新创建的ReplicatedShare实例
    ///
    /// # 示例
    /// ```
    /// let share = ReplicatedShare::new(0, 12345, 67890);
    /// assert_eq!(share.party_id, 0);
    /// assert_eq!(share.share1, 12345);
    /// assert_eq!(share.share2, 67890);
    /// ```
    pub fn new(party_id: usize, share1: u64, share2: u64) -> Self {
        Self { party_id, share1, share2 }
    }

    /// 获取份额的局部值
    ///
    /// 计算该参与方对秘密的局部贡献值。
    ///
    /// # 返回值
    /// 返回 share1 + share2 (mod p)
    ///
    /// # 示例
    /// ```
    /// let share = ReplicatedShare::new(0, 10, 20);
    /// let local_value = share.local_value();
    /// assert_eq!(local_value, field_add(10, 20));
    /// ```
    pub fn local_value(&self) -> u64 {
        field_add(self.share1, self.share2)
    }
}

/// 复制秘密分享方案实现
///
/// 提供复制秘密分享的核心功能，包括秘密分享、重构以及份额上的高效运算。
/// 该方案特别适用于3方安全多方计算场景。
pub struct ReplicatedSecretSharing;

impl Default for ReplicatedSecretSharing {
    /// 创建复制秘密分享方案的默认实例
    ///
    /// # 返回值
    /// 返回ReplicatedSecretSharing的新实例
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicatedSecretSharing {
    /// 创建复制秘密分享方案的新实例
    ///
    /// # 返回值
    /// 返回ReplicatedSecretSharing的新实例
    ///
    /// # 示例
    /// ```
    /// let scheme = ReplicatedSecretSharing::new();
    /// ```
    pub fn new() -> Self {
        Self
    }

    /// 将秘密分享为复制份额（3方版本）
    ///
    /// 使用复制秘密分享方案将秘密分割成3个份额，其中任意2个份额可以重构秘密。
    /// 每个参与方持有两个随机值，这些值在参与方之间有重叠。
    ///
    /// # 参数
    /// - `secret`: 要分享的秘密值
    ///
    /// # 返回值
    /// 成功时返回包含3个ReplicatedShare的向量
    ///
    /// # 示例
    /// ```
    /// let scheme = ReplicatedSecretSharing::new();
    /// let secret = 42u64;
    /// let shares = scheme.share_replicated(&secret)?;
    /// assert_eq!(shares.len(), 3);
    /// ```
    ///
    /// # 安全性
    /// 该方法使用密码学安全的随机数生成器创建随机值，确保份额的随机性和不可预测性。
    /// 任何单个参与方都无法从其份额中获得关于秘密的信息。
    pub fn share_replicated(&self, secret: &u64) -> Result<Vec<ReplicatedShare>> {
        let mut rng = rand::thread_rng();

        // 生成三个随机值 r1, r2, r3
        // 使得 secret = r1 + r2 + r3 (mod p)
        let r1 = rng.gen_range(0..FIELD_PRIME);
        let r2 = rng.gen_range(0..FIELD_PRIME);
        let sum_r1_r2 = field_add(r1, r2);
        let r3 = field_sub(*secret, sum_r1_r2);

        // 分配份额：
        // Party 0: (r1, r2)
        // Party 1: (r2, r3)
        // Party 2: (r3, r1)
        let shares = vec![
            ReplicatedShare::new(0, r1, r2),
            ReplicatedShare::new(1, r2, r3),
            ReplicatedShare::new(2, r3, r1),
        ];

        Ok(shares)
    }

    /// 从复制份额中重构秘密
    ///
    /// 使用任意两个复制份额来重构原始秘密。由于复制结构的特性，
    /// 任意两个不同的参与方都可以合作重构秘密。
    ///
    /// # 参数
    /// - `shares`: 复制秘密分享份额的切片（至少需要2个）
    ///
    /// # 返回值
    /// 成功时返回重构的秘密值
    ///
    /// # 错误
    /// 当提供的份额数量少于2个时返回InsufficientShares错误
    ///
    /// # 示例
    /// ```
    /// let scheme = ReplicatedSecretSharing::new();
    /// let secret = 42u64;
    /// let shares = scheme.share_replicated(&secret)?;
    /// let reconstructed = scheme.reconstruct_replicated(&shares[0..2])?;
    /// assert_eq!(reconstructed, secret);
    /// ```
    pub fn reconstruct_replicated(&self, shares: &[ReplicatedShare]) -> Result<u64> {
        if shares.len() < 2 {
            return Err(MpcError::InsufficientShares);
        }

        // 根据参与方的组合来重构秘密
        let party1 = shares[0].party_id;
        let party2 = shares[1].party_id;

        match (party1, party2) {
            (0, 1) | (1, 0) => {
                // Party 0: (r1, r2), Party 1: (r2, r3)
                // secret = r1 + r2 + r3
                let r1 = shares[0].share1;
                let r2 = shares[0].share2; // 或者 shares[1].share1，应该相等
                let r3 = shares[1].share2;
                Ok(field_add(field_add(r1, r2), r3))
            },
            (0, 2) | (2, 0) => {
                // Party 0: (r1, r2), Party 2: (r3, r1)
                let r1 = shares[0].share1; // 或者 shares[1].share2
                let r2 = shares[0].share2;
                let r3 = shares[1].share1;
                Ok(field_add(field_add(r1, r2), r3))
            },
            (1, 2) | (2, 1) => {
                // Party 1: (r2, r3), Party 2: (r3, r1)
                let r2 = shares[0].share1;
                let r3 = shares[0].share2; // 或者 shares[1].share1
                let r1 = shares[1].share2;
                Ok(field_add(field_add(r1, r2), r3))
            },
            _ => Err(MpcError::InvalidSecretShare),
        }
    }

    /// 复制份额的加法运算
    ///
    /// 计算两个复制份额的和，实现复制秘密分享的同态加法特性。
    /// 两个份额必须属于同一个参与方。
    ///
    /// # 参数
    /// - `share1`: 第一个复制份额
    /// - `share2`: 第二个复制份额
    ///
    /// # 返回值
    /// 成功时返回两个份额的和
    ///
    /// # 错误
    /// 当两个份额的party_id不同时返回InvalidSecretShare错误
    ///
    /// # 示例
    /// ```
    /// let scheme = ReplicatedSecretSharing::new();
    /// let share1 = ReplicatedShare::new(0, 10, 20);
    /// let share2 = ReplicatedShare::new(0, 5, 15);
    /// let sum_share = scheme.add_replicated_shares(&share1, &share2)?;
    /// ```
    pub fn add_replicated_shares(&self, share1: &ReplicatedShare, share2: &ReplicatedShare) -> Result<ReplicatedShare> {
        if share1.party_id != share2.party_id {
            return Err(MpcError::InvalidSecretShare);
        }

        let new_share1 = field_add(share1.share1, share2.share1);
        let new_share2 = field_add(share1.share2, share2.share2);

        Ok(ReplicatedShare::new(share1.party_id, new_share1, new_share2))
    }

    /// 复制份额的减法运算
    ///
    /// 计算两个复制份额的差，实现复制秘密分享的同态减法特性。
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
    pub fn sub_replicated_shares(&self, share1: &ReplicatedShare, share2: &ReplicatedShare) -> Result<ReplicatedShare> {
        if share1.party_id != share2.party_id {
            return Err(MpcError::InvalidSecretShare);
        }

        let new_share1 = field_sub(share1.share1, share2.share1);
        let new_share2 = field_sub(share1.share2, share2.share2);

        Ok(ReplicatedShare::new(share1.party_id, new_share1, new_share2))
    }

    /// 复制份额的标量乘法运算
    ///
    /// 计算复制份额与标量的乘积，实现复制秘密分享的同态标量乘法特性。
    ///
    /// # 参数
    /// - `share`: 复制份额
    /// - `scalar`: 标量值
    ///
    /// # 返回值
    /// 返回份额与标量的乘积
    pub fn scalar_mul_replicated(&self, share: &ReplicatedShare, scalar: &u64) -> ReplicatedShare {
        let new_share1 = field_mul(share.share1, *scalar);
        let new_share2 = field_mul(share.share2, *scalar);

        ReplicatedShare::new(share.party_id, new_share1, new_share2)
    }

    /// 复制份额的局部乘法运算
    ///
    /// 执行两个复制份额的局部乘法。这是复制秘密分享的一个关键优势，
    /// 因为乘法可以在本地执行而无需通信。
    ///
    /// # 参数
    /// - `share1`: 第一个复制份额
    /// - `share2`: 第二个复制份额
    ///
    /// # 返回值
    /// 成功时返回乘法的局部结果
    ///
    /// # 注意
    /// 这个操作产生的是乘法的局部部分。要完成完整的乘法，
    /// 需要所有参与方的局部乘法结果进行重分享。
    ///
    /// # 错误
    /// 当两个份额的party_id不同时返回InvalidSecretShare错误
    pub fn local_mul_replicated(&self, share1: &ReplicatedShare, share2: &ReplicatedShare) -> Result<(u64, u64, u64, u64)> {
        if share1.party_id != share2.party_id {
            return Err(MpcError::InvalidSecretShare);
        }

        // 计算所有的乘积项
        let prod11 = field_mul(share1.share1, share2.share1);
        let prod12 = field_mul(share1.share1, share2.share2);
        let prod21 = field_mul(share1.share2, share2.share1);
        let prod22 = field_mul(share1.share2, share2.share2);

        Ok((prod11, prod12, prod21, prod22))
    }

    /// 生成零的复制份额
    ///
    /// 生成一组复制份额，它们对应的秘密值为0。
    ///
    /// # 返回值
    /// 成功时返回零复制份额的向量
    ///
    /// # 示例
    /// ```
    /// let scheme = ReplicatedSecretSharing::new();
    /// let zero_shares = scheme.generate_zero_replicated_shares()?;
    /// let reconstructed = scheme.reconstruct_replicated(&zero_shares[0..2])?;
    /// assert_eq!(reconstructed, 0);
    /// ```
    pub fn generate_zero_replicated_shares(&self) -> Result<Vec<ReplicatedShare>> {
        self.share_replicated(&0u64)
    }

    /// 生成随机复制份额
    ///
    /// 生成一组复制份额，对应一个随机的秘密值。返回秘密值和对应的份额。
    ///
    /// # 返回值
    /// 成功时返回(秘密值, 份额向量)的元组
    ///
    /// # 示例
    /// ```
    /// let scheme = ReplicatedSecretSharing::new();
    /// let (secret, shares) = scheme.generate_random_replicated_shares()?;
    /// let reconstructed = scheme.reconstruct_replicated(&shares[0..2])?;
    /// assert_eq!(reconstructed, secret);
    /// ```
    pub fn generate_random_replicated_shares(&self) -> Result<(u64, Vec<ReplicatedShare>)> {
        let mut rng = rand::thread_rng();
        let secret = rng.gen_range(0..FIELD_PRIME);
        let shares = self.share_replicated(&secret)?;
        Ok((secret, shares))
    }

    /// 验证复制份额的有效性
    ///
    /// 检查复制份额是否有效和一致。这通过验证重叠的值是否匹配来实现。
    ///
    /// # 参数
    /// - `shares`: 要验证的复制份额切片
    ///
    /// # 返回值
    /// 如果份额有效返回true，否则返回false
    ///
    /// # 示例
    /// ```
    /// let scheme = ReplicatedSecretSharing::new();
    /// let secret = 42u64;
    /// let shares = scheme.share_replicated(&secret)?;
    /// let is_valid = scheme.verify_replicated_shares(&shares);
    /// assert!(is_valid);
    /// ```
    pub fn verify_replicated_shares(&self, shares: &[ReplicatedShare]) -> bool {
        if shares.len() != 3 {
            return false;
        }

        // 验证重叠值是否匹配
        // Party 0: (r1, r2), Party 1: (r2, r3), Party 2: (r3, r1)
        let party0_r2 = shares[0].share2;
        let party1_r2 = shares[1].share1;
        if party0_r2 != party1_r2 {
            return false;
        }

        let party1_r3 = shares[1].share2;
        let party2_r3 = shares[2].share1;
        if party1_r3 != party2_r3 {
            return false;
        }

        let party2_r1 = shares[2].share2;
        let party0_r1 = shares[0].share1;
        if party2_r1 != party0_r1 {
            return false;
        }

        true
    }

    /// 份额的求反运算
    ///
    /// 计算复制份额的相反数，对应于秘密的求反。
    ///
    /// # 参数
    /// - `share`: 要求反的份额
    ///
    /// # 返回值
    /// 返回求反后的份额
    pub fn negate_replicated_share(&self, share: &ReplicatedShare) -> ReplicatedShare {
        let neg_share1 = field_sub(0, share.share1);
        let neg_share2 = field_sub(0, share.share2);
        ReplicatedShare::new(share.party_id, neg_share1, neg_share2)
    }
}