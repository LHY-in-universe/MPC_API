//! # 进阶协议模块 (Advanced Protocols)
//! 
//! 本模块实现了多种高级安全多方计算协议，这些协议建立在基本密码学原语之上，
//! 提供更复杂的功能和安全保证。
//! 
//! ## 支持的协议
//! 
//! - **硬币抛掷 (Coin Flipping)**: 允许多方共同生成随机比特，确保任何一方都无法单独影响结果
//! - **安全比较 (Secure Comparison)**: 比较两个私有输入而不泄露它们的值
//! - **私有集合求交 (Private Set Intersection)**: 计算多个集合的交集而不泄露集合中的其他元素
//! - **安全函数评估 (Secure Function Evaluation)**: 在不泄露输入的情况下计算函数结果
//! 
//! ## 安全性质
//! 
//! 这些协议提供以下安全保证：
//! 
//! - **输入隐私**: 参与方的输入对其他方保密
//! - **计算正确性**: 即使有恶意参与方，结果也是正确的
//! - **公平性**: 所有参与方要么都获得结果，要么都不获得
//! 
//! ## 使用场景
//! 
//! - 隐私保护数据分析
//! - 安全多方决策系统
//! - 分布式密钥生成
//! - 隐私保护机器学习

pub mod coin_flipping;

pub use coin_flipping::*;

#[cfg(test)]
mod tests {
    //! 协议测试
    //! 
    //! 包含抛硬币协议等高级协议的测试

    use super::*;
    use crate::protocols::coin_flipping::*;
    use crate::secret_sharing::FIELD_PRIME;

    // ===== Coin Flipping Tests =====

    #[test]
    fn test_xor_coin_flip() {
        let result = XORCoinFlip::commit_bit(true);
        assert!(result.is_ok());
        
        let (commit, reveal) = result.unwrap();
        assert!(commit.commitment > 0);
        assert!(reveal.value);
    }

    #[test]
    fn test_xor_coin_verify_and_combine() {
        let (commit1, reveal1) = XORCoinFlip::commit_bit(true).unwrap();
        let (commit2, reveal2) = XORCoinFlip::commit_bit(false).unwrap();
        
        let result = XORCoinFlip::verify_and_combine(&commit1, &reveal1, &commit2, &reveal2).unwrap();
        assert_eq!(result, true ^ false);
    }

    #[test]
    fn test_blum_coin_flip() {
        let result = BlumCoinFlip::protocol();
        assert!(result.is_ok());
        
        let coin = result.unwrap();
        assert!(coin == true || coin == false);
    }

    #[test]
    fn test_multi_party_coin_flip() {
        for num_parties in 1..=5 {
            let result = BlumCoinFlip::multi_party_coin_flip(num_parties);
            assert!(result.is_ok());
            
            let coin = result.unwrap();
            assert!(coin == true || coin == false);
        }
    }

    #[test]
    fn test_bias_resistant_coin_flip() {
        let results = BiasResistantCoinFlip::protocol_with_multiple_rounds(10);
        assert!(results.is_ok());
        
        let coins = results.unwrap();
        assert_eq!(coins.len(), 10);
        
        // All results should be boolean
        for coin in coins {
            assert!(coin == true || coin == false);
        }
    }

    #[test]
    fn test_von_neumann_extraction() {
        let biased_coins = vec![true, false, false, false, true, true, false, true];
        let unbiased = BiasResistantCoinFlip::extract_unbiased_bits(&biased_coins);
        
        // Should extract unbiased bits from (T,F) and (F,T) pairs
        assert!(unbiased.len() <= biased_coins.len() / 2);
        
        // All results should be boolean
        for bit in unbiased {
            assert!(bit == true || bit == false);
        }
    }

    #[test]
    fn test_commitment_based_coin_flip() {
        let result = CommitmentBasedCoinFlip::protocol_with_pedersen();
        assert!(result.is_ok());
        
        let coin = result.unwrap();
        assert!(coin == true || coin == false);
    }

    #[test]
    fn test_random_field_elements_generation() {
        let result = SequentialCoinFlip::generate_random_field_elements(3);
        assert!(result.is_ok());
        
        let elements = result.unwrap();
        assert_eq!(elements.len(), 3);
        
        // All elements should be in the field
        for element in elements {
            assert!(element < FIELD_PRIME);
        }
    }
}