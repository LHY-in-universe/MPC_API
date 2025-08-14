//! 协议测试
//! 
//! 包含抛硬币协议等高级协议的测试

use mpc_api::protocols::coin_flipping::*;
use mpc_api::secret_sharing::FIELD_PRIME;

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