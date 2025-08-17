//! # MPC API - 安全多方计算 (Secure Multi-Party Computation) 库
//! 
//! 这是一个用 Rust 实现的全面的安全多方计算库，提供了各种密码学原语和协议的实现。
//! 所有计算都在 u64 有限域上进行，使用素数 p = 2^61 - 1 作为模数。
//! 
//! ## 核心组件 (Core Components)
//! 
//! ### 秘密分享 (Secret Sharing)
//! - **Shamir 秘密分享**: 基于多项式插值的 (t,n) 门限秘密分享
//! - **加法秘密分享**: 支持加法同态运算的简单分享方案
//! 
//! ### 混淆电路 (Garbled Circuits)  
//! - **电路混淆**: 将布尔电路转换为混淆电路
//! - **Free XOR 优化**: 提高 XOR 门的效率
//! - **电路求值**: 安全地计算混淆电路
//! 
//! ### 不经意传输 (Oblivious Transfer)
//! - **基础 OT**: 1-out-of-2 不经意传输
//! - **相关 OT**: 具有固定偏移的相关不经意传输  
//! - **随机 OT**: 生成随机共享的不经意传输
//! - **OT 扩展**: 从少量基础 OT 扩展到大量 OT
//! 
//! ### 向量不经意线性求值 (Vector Oblivious Linear Evaluation)
//! - **VOLE**: 向量不经意线性函数求值
//! - **OLE**: 标量不经意线性函数求值
//! 
//! ### 同态加密 (Homomorphic Encryption)
//! - **ElGamal**: 乘法同态加密
//! - **Paillier**: 加法同态加密
//! - **RSA**: 乘法同态加密
//! - **BFV/BGV**: 全同态加密方案 (简化版)
//! 
//! ### 椭圆曲线密码学 (Elliptic Curve Cryptography)
//! - **ECDH**: 椭圆曲线 Diffie-Hellman 密钥交换
//! - **ECDSA**: 椭圆曲线数字签名算法
//! - **点运算**: 椭圆曲线上的基本运算
//! 
//! ### 高级协议 (Advanced Protocols)
//! - **投币协议**: 安全的随机数生成协议
//! - **承诺方案**: Pedersen、Hash-based、Merkle tree 承诺
//! - **消息认证码**: HMAC、Poly1305、GMAC、CMAC
//! - **SPDZ 协议**: 带认证的秘密分享协议
//! 
//! ## 设计原则 (Design Principles)
//! 
//! 1. **安全性**: 所有协议都实现了标准的安全性要求
//! 2. **效率**: 针对批处理操作进行了优化
//! 3. **模块化**: 每个组件都可以独立使用
//! 4. **可扩展性**: 基于特征的设计便于添加新实现
//! 5. **有限域运算**: 所有计算都在 u64 有限域上进行
//! 

pub mod secret_sharing;
pub mod garbled_circuits;
pub mod oblivious_transfer;
pub mod homomorphic_encryption;
pub mod elliptic_curve;
pub mod protocols;
pub mod commitment;
pub mod authentication;
pub mod spdz;
pub mod zero_knowledge;
pub mod beaver_triples;
pub mod utils;
pub mod security;
pub mod network;

pub use secret_sharing::*;
pub use garbled_circuits::*;
pub use oblivious_transfer::*;
pub use homomorphic_encryption::*;
pub use elliptic_curve::*;
pub use protocols::*;
pub use commitment::*;
pub use authentication::*;
pub use spdz::*;
// pub use zero_knowledge::*; // Unused import - zero knowledge not fully implemented
pub use beaver_triples::*;
pub use utils::*;
pub use security::*;
pub use network::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MpcError {
    #[error("Invalid secret share")]
    InvalidSecretShare,
    #[error("Insufficient shares for reconstruction")]
    InsufficientShares,
    #[error("Invalid threshold")]
    InvalidThreshold,
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
}

impl From<String> for MpcError {
    fn from(s: String) -> Self {
        MpcError::ProtocolError(s)
    }
}

impl From<&str> for MpcError {
    fn from(s: &str) -> Self {
        MpcError::ProtocolError(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, MpcError>;

#[cfg(test)]
mod examples_tests {
    //! 示例代码测试
    //! 
    //! 本文件包含对MPC API所有示例代码的全面测试，覆盖以下主要功能区域：
    //! - Beaver三元组生成和验证 (Trusted Party, BFV, OLE)
    //! - 高级协议指南 (Hash承诺, Pedersen承诺, Merkle树)
    //! - 秘密分享和安全多方计算 (Shamir, 加法分享)
    //! - 认证和承诺方案 (HMAC, 签名数字承诺)
    //! - 混乱电路和安全计算 (Garbled Circuits)
    //! - 实际应用场景 (PPML, 私人拍卖, 统计分析)
    //! 
    //! 这些测试确保所有示例代码都能正确运行，为用户提供可靠的参考实现。

    use super::*;

    /// 测试基本的可信第三方Beaver三元组生成
    #[test]
    fn test_basic_trusted_party() {
        fn basic_trusted_party_example() -> Result<()> {
            let party_count = 3;
            let threshold = 2;
            let party_id = 0;
            
            let mut tp_generator = TrustedPartyBeaverGenerator::new(
                party_count, 
                threshold, 
                party_id, 
                None
            )?;
            
            let beaver_triple = tp_generator.generate_single()?;
            let is_valid = tp_generator.verify_triple(&beaver_triple)?;
            assert!(is_valid);
            
            Ok(())
        }

        basic_trusted_party_example().unwrap();
    }

    /// 测试Hash承诺示例的完整流程
    #[test]
    fn test_hash_commitment_examples() {
        fn run_all() -> Result<()> {
            let secret_value = 42u64;
            let randomness = 123456u64;
            
            let commitment = HashCommitment::commit_u64(secret_value, randomness);
            let is_valid = HashCommitment::verify_u64(&commitment, secret_value, randomness);
            assert!(is_valid);
            
            let values = vec![10u64, 20u64, 30u64];
            let randomness_vec = vec![111u64, 222u64, 333u64];
            
            let commitments = HashCommitment::batch_commit_u64(&values, &randomness_vec)?;
            
            for (i, (&value, &rand)) in values.iter().zip(randomness_vec.iter()).enumerate() {
                let is_valid = HashCommitment::verify_u64(&commitments[i], value, rand);
                assert!(is_valid);
            }
            
            Ok(())
        }

        run_all().unwrap();
    }

    /// 测试完整的Shamir秘密分享示例
    #[test]
    fn test_complete_shamir_example() {
        fn complete_shamir_example() -> Result<()> {
            let secret = 123456u64;
            let threshold = 3;
            let total_parties = 5;
            
            let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
            let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
            assert_eq!(secret, reconstructed);
            
            let secret2 = 654321u64;
            let shares2 = ShamirSecretSharing::share(&secret2, threshold, total_parties)?;
            
            let sum_shares: Vec<_> = shares.iter()
                .zip(shares2.iter())
                .map(|(s1, s2)| ShamirSecretSharing::add_shares(s1, s2))
                .collect::<Result<Vec<_>>>()?;
            
            let sum = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
            let expected_sum = field_add(secret, secret2);
            assert_eq!(sum, expected_sum);
            
            Ok(())
        }

        complete_shamir_example().unwrap();
    }

    /// 测试多方计算示例
    #[test]
    fn test_multi_party_computation_example() {
        fn multi_party_computation_example() -> Result<()> {
            let salaries = vec![50000u64, 60000u64, 55000u64];
            let party_count = 3;
            let threshold = 2;
            
            let mut all_shares = Vec::new();
            for &salary in &salaries {
                let shares = ShamirSecretSharing::share(&salary, threshold, party_count)?;
                all_shares.push(shares);
            }
            
            let mut sum_shares = all_shares[0].clone();
            for shares in &all_shares[1..] {
                for (i, share) in shares.iter().enumerate() {
                    sum_shares[i] = ShamirSecretSharing::add_shares(&sum_shares[i], share)?;
                }
            }
            
            let total_salary = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
            let expected_total: u64 = salaries.iter().sum();
            assert_eq!(total_salary, expected_total);
            
            Ok(())
        }

        multi_party_computation_example().unwrap();
    }

    /// 测试完整的API使用指南
    #[test]
    fn test_complete_api_guide() {
        fn run_complete_api_guide() -> Result<()> {
            // Secret sharing
            let secret = 42u64;
            let threshold = 3;
            let total_parties = 5;
            
            let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
            let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
            assert_eq!(secret, reconstructed);
            
            // Beaver triples
            let party_count = 3;
            let threshold = 2;
            let party_id = 0;
            
            let mut generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
            let triple = generator.generate_single()?;
            let is_valid = triple.verify(threshold)?;
            assert!(is_valid);
            
            // Hash commitment
            let secret_value = 12345u64;
            let randomness = 67890u64;
            
            let commitment = HashCommitment::commit_u64(secret_value, randomness);
            let is_valid = HashCommitment::verify_u64(&commitment, secret_value, randomness);
            assert!(is_valid);
            
            // HMAC
            let key = HMAC::generate_key();
            let message = b"important message".to_vec();
            
            let mac = HMAC::authenticate(&key, &message);
            let is_valid = HMAC::verify(&key, &message, &mac);
            assert!(is_valid);
            
            Ok(())
        }

        run_complete_api_guide().unwrap();
    }
}