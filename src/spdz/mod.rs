//! # SPDZ 协议实现 (SPDZ Protocol Implementation)
//! 
//! SPDZ（发音为 "Speedz"）是一种安全多方计算协议，允许多个参与方
//! 在不泄露各自私有输入的情况下联合计算函数。
//! 
//! ## 核心概念
//! 
//! SPDZ 协议基于认证的秘密分享，提供以下特性：
//! - **主动安全性**: 能够抵御恶意参与方的攻击
//! - **信息论安全**: 在计算上无条件安全
//! - **高效性**: 支持大规模并行计算
//! - **通用性**: 支持任意算术电路的计算
//! 
//! ## 协议阶段
//! 
//! 1. **预处理阶段**: 生成 Beaver 三元组和其他预处理材料
//! 2. **在线阶段**: 使用预处理材料进行实际计算
//! 3. **验证阶段**: 验证计算结果的正确性
//! 
//! ## 安全模型
//! 
//! - **对手模型**: 恶意对手，最多 t < n/2 个腐败参与方
//! - **网络模型**: 同步网络，具有认证通道
//! - **安全性**: 提供隐私性和正确性保证

pub mod share;

pub use share::*;

use crate::{MpcError, Result};
use crate::secret_sharing::{FIELD_PRIME, field_add, field_sub, field_mul};
use crate::authentication::{HMAC, HmacKey};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

/// 参与方标识符类型
/// 
/// 用于唯一标识 SPDZ 协议中的每个参与方
pub type PlayerId = usize;

/// 分享标识符类型
/// 
/// 用于标识和跟踪不同的秘密分享值
pub type ShareId = u64;

/// SPDZ 协议参数结构
/// 
/// 包含 SPDZ 协议运行所需的所有配置参数，包括参与方数量、
/// 当前参与方ID、门限值和安全参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SPDZParams {
    /// 参与方总数
    pub num_parties: usize,
    /// 当前参与方的ID
    pub party_id: PlayerId,
    /// 门限值（最多可容忍的腐败参与方数量）
    pub threshold: usize,
    /// 安全参数（比特长度）
    pub security_parameter: usize,
}

impl SPDZParams {
    /// 创建新的 SPDZ 参数
    /// 
    /// 使用默认的128位安全参数创建协议参数。
    /// 
    /// # 参数
    /// 
    /// * `num_parties` - 参与方总数
    /// * `party_id` - 当前参与方的ID
    /// * `threshold` - 门限值
    /// 
    /// # 返回值
    /// 
    /// 返回新创建的 SPDZParams 实例
    pub fn new(num_parties: usize, party_id: PlayerId, threshold: usize) -> Self {
        Self {
            num_parties,
            party_id,
            threshold,
            security_parameter: 128,
        }
    }
    
    /// 验证参数的有效性
    /// 
    /// 检查协议参数是否满足 SPDZ 协议的基本要求：
    /// - 参与方ID必须在有效范围内
    /// - 门限值必须大于0且小于参与方总数
    /// 
    /// # 返回值
    /// 
    /// 如果参数有效返回 `true`，否则返回 `false`
    pub fn is_valid(&self) -> bool {
        self.party_id < self.num_parties 
            && self.threshold > 0 
            && self.threshold < self.num_parties
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spdz::{share::*, SPDZParams};
    use crate::secret_sharing::{field_add, field_sub, field_mul, FIELD_PRIME};

    #[test]
    fn test_spdz_share_creation() {
        let share = SPDZShare::new(42, 123, 0, 1);
        assert_eq!(share.value, 42);
        assert_eq!(share.mac, 123);
        assert_eq!(share.party_id, 0);
        assert_eq!(share.share_id, 1);
    }

    #[test]
    fn test_spdz_share_addition() {
        let share1 = SPDZShare::new(10, 20, 0, 1);
        let share2 = SPDZShare::new(15, 25, 0, 2);
        
        let result = share1.add(&share2).unwrap();
        assert_eq!(result.value, field_add(10, 15));
        assert_eq!(result.mac, field_add(20, 25));
    }

    #[test]
    fn test_spdz_share_subtraction() {
        let share1 = SPDZShare::new(20, 30, 0, 1);
        let share2 = SPDZShare::new(5, 10, 0, 2);
        
        let result = share1.sub(&share2).unwrap();
        assert_eq!(result.value, field_sub(20, 5));
        assert_eq!(result.mac, field_sub(30, 10));
    }

    #[test]
    fn test_authenticated_share() {
        let mut auth_share = AuthenticatedShare::new();
        let share = SPDZShare::new(42, 123, 0, 1);
        
        auth_share.add_share(0, share.clone());
        
        let retrieved = auth_share.get_share(0).unwrap();
        assert_eq!(retrieved.value, share.value);
        assert_eq!(retrieved.mac, share.mac);
    }

    #[test]
    fn test_spdz_protocol_creation() {
        let params = SPDZParams::new(3, 0, 2);
        let protocol = SPDZShareProtocol::new(params);
        assert!(protocol.is_ok());
    }

    #[test]
    fn test_secret_sharing() {
        let params = SPDZParams::new(3, 0, 2);
        let protocol = SPDZShareProtocol::new(params).unwrap();
        
        let secret = 42u64;
        let shares = protocol.share_secret(secret).unwrap();
        
        assert_eq!(shares.len(), 3);
        for share in &shares {
            assert!(share.value < FIELD_PRIME);
        }
    }

    #[test]
    fn test_input_and_reconstruction() {
        let params = SPDZParams::new(3, 0, 2);
        let protocol = SPDZShareProtocol::new(params).unwrap();
        
        let secret = 42u64;
        let auth_share = protocol.input(secret).unwrap();
        
        // In a real scenario, MAC verification would be done
        // For this test, we'll skip it
        let reconstructed = auth_share.reconstruct(2).unwrap();
        // Check that reconstruction works - the value might be equivalent in the field
        assert!(reconstructed == secret || reconstructed == field_add(secret, 0));
    }

    #[test]
    fn test_share_operations() {
        let params = SPDZParams::new(3, 0, 2);
        let protocol = SPDZShareProtocol::new(params).unwrap();
        
        let share_a = protocol.input(10).unwrap();
        let share_b = protocol.input(20).unwrap();
        
        let sum = protocol.add(&share_a, &share_b).unwrap();
        let diff = protocol.sub(&share_a, &share_b).unwrap();
        let scaled = protocol.mul_public(&share_a, 5);
        
        // Verify operations (in practice, these would be verified with MACs)
        assert_eq!(sum.reconstruct(2).unwrap(), field_add(10, 20));
        assert_eq!(diff.reconstruct(2).unwrap(), field_sub(10, 20));
        assert_eq!(scaled.reconstruct(2).unwrap(), field_mul(10, 5));
    }

    #[test]
    fn test_batch_operations() {
        let params = SPDZParams::new(3, 0, 2);
        let protocol = SPDZShareProtocol::new(params).unwrap();
        
        let shares_a = vec![
            protocol.input(10).unwrap(),
            protocol.input(20).unwrap(),
        ];
        let shares_b = vec![
            protocol.input(5).unwrap(),
            protocol.input(15).unwrap(),
        ];
        
        let sums = protocol.add_batch(&shares_a, &shares_b).unwrap();
        
        assert_eq!(sums.len(), 2);
        assert_eq!(sums[0].reconstruct(2).unwrap(), field_add(10, 5));
        assert_eq!(sums[1].reconstruct(2).unwrap(), field_add(20, 15));
    }

    #[test]
    fn test_linear_combination() {
        let params = SPDZParams::new(3, 0, 2);
        let protocol = SPDZShareProtocol::new(params).unwrap();
        
        let shares = vec![
            protocol.input(10).unwrap(),
            protocol.input(20).unwrap(),
            protocol.input(30).unwrap(),
        ];
        let coefficients = vec![1, 2, 3];
        
        let result = protocol.linear_combination(&shares, &coefficients).unwrap();
        
        // Expected: 1*10 + 2*20 + 3*30 = 10 + 40 + 90 = 140
        let expected = field_add(
            field_add(
                field_mul(1, 10), 
                field_mul(2, 20)
            ), 
            field_mul(3, 30)
        );
        assert_eq!(result.reconstruct(2).unwrap(), expected);
    }

    #[test]
    fn test_random_generation() {
        let params = SPDZParams::new(3, 0, 2);
        let protocol = SPDZShareProtocol::new(params).unwrap();
        
        let random_share = protocol.random().unwrap();
        let value = random_share.reconstruct(2).unwrap();
        
        assert!(value < FIELD_PRIME);
    }
}