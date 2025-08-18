//! Integration tests for MPC API
//! 
//! These tests verify that different components of the MPC API work together correctly
//! and provide comprehensive test coverage for real-world usage scenarios.

use mpc_api::*;

/// Test integration between secret sharing and Beaver triples
#[test]
fn test_secret_sharing_with_beaver_triples() -> Result<()> {
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    
    // Generate Beaver triples
    let mut generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
    let triple = generator.generate_single()?;
    
    // Verify the triple is valid
    assert!(triple.verify(threshold)?);
    
    // Test that we can extract shares from the triple
    assert!(triple.shares.len() >= threshold);
    
    // If original values are available, verify the relationship
    if let Some((a, b, c)) = triple.original_values {
        let expected_c = field_mul(a, b);
        assert_eq!(c, expected_c);
    }
    
    Ok(())
}

/// Test secret sharing homomorphic properties
#[test]
fn test_secret_sharing_homomorphic_properties() -> Result<()> {
    let threshold = 3;
    let total_parties = 5;
    
    // Test values
    let value1 = 100u64;
    let value2 = 200u64;
    
    // Share the values using Shamir secret sharing
    let shares1 = ShamirSecretSharing::share(&value1, threshold, total_parties)?;
    let shares2 = ShamirSecretSharing::share(&value2, threshold, total_parties)?;
    
    // Test additive homomorphism: shares of (a + b) = shares of a + shares of b
    let sum_shares: Result<Vec<_>> = shares1.iter()
        .zip(shares2.iter())
        .map(|(s1, s2)| ShamirSecretSharing::add_shares(s1, s2))
        .collect();
    let sum_shares = sum_shares?;
    
    // Reconstruct the sum and verify
    let reconstructed_sum = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
    let expected_sum = field_add(value1, value2);
    assert_eq!(reconstructed_sum, expected_sum);
    
    // Test scalar multiplication homomorphism
    let scalar = 3u64;
    let scalar_shares: Result<Vec<_>> = shares1.iter()
        .map(|share| ShamirSecretSharing::scalar_mul(share, &scalar))
        .collect();
    let scalar_shares = scalar_shares?;
    
    let reconstructed_scalar = ShamirSecretSharing::reconstruct(&scalar_shares[0..threshold], threshold)?;
    let expected_scalar = field_mul(value1, scalar);
    assert_eq!(reconstructed_scalar, expected_scalar);
    
    Ok(())
}

/// Test comprehensive MPC protocol workflow
#[test]
fn test_complete_mpc_workflow() -> Result<()> {
    // Simulate a complete MPC workflow for computing sum of private inputs
    let party_count = 4;
    let threshold = 3;
    
    // Private inputs from each party
    let inputs = vec![100u64, 250u64, 300u64, 150u64];
    
    // Step 1: Each party shares their input
    let mut all_shares = Vec::new();
    for &input in &inputs {
        let shares = ShamirSecretSharing::share(&input, threshold, party_count)?;
        all_shares.push(shares);
    }
    
    // Step 2: Compute sum using additive homomorphism of secret sharing
    let mut sum_shares = all_shares[0].clone();
    for shares in &all_shares[1..] {
        for (i, share) in shares.iter().enumerate() {
            sum_shares[i] = ShamirSecretSharing::add_shares(&sum_shares[i], share)?;
        }
    }
    
    // Step 3: Reconstruct the result
    let result = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
    let expected_sum: u64 = inputs.iter().sum();
    
    assert_eq!(result, expected_sum);
    
    // Step 4: Verify using commitment scheme
    let randomness = 12345u64;
    let commitment = HashCommitment::commit_u64(result, randomness);
    let is_valid = HashCommitment::verify_u64(&commitment, result, randomness);
    assert!(is_valid);
    
    Ok(())
}

/// Test basic oblivious transfer setup  
#[test]
fn test_oblivious_transfer_setup() -> Result<()> {
    // Test basic OT setup and initialization
    let mut ot = BasicOT::new();
    
    // Test sender phase with dummy messages
    let msg0 = vec![1, 2, 3, 4];
    let msg1 = vec![5, 6, 7, 8];
    
    let sender_public = ot.sender_phase1(msg0.clone(), msg1.clone())?;
    assert!(sender_public > 0);
    
    // Test receiver phase with choice bit
    let choice = true; // Choose message 1
    let receiver_public = ot.receiver_phase1(choice, sender_public)?;
    assert!(receiver_public > 0);
    
    Ok(())
}

/// Test authentication integration with message protocols
#[test]
fn test_authentication_integration() -> Result<()> {
    // Test HMAC with message authentication
    let key = HMAC::generate_key();
    let message = b"Important MPC computation result: 42".to_vec();
    
    // Authenticate the message
    let mac = HMAC::authenticate(&key, &message);
    
    // Verify authentication
    let is_valid = HMAC::verify(&key, &message, &mac);
    assert!(is_valid);
    
    // Test that authentication fails with wrong message
    let wrong_message = b"Tampered message: 99".to_vec();
    let is_invalid = HMAC::verify(&key, &wrong_message, &mac);
    assert!(!is_invalid);
    
    // Test that authentication fails with wrong key
    let wrong_key = HMAC::generate_key();
    let is_invalid_key = HMAC::verify(&wrong_key, &message, &mac);
    assert!(!is_invalid_key);
    
    Ok(())
}

/// Test commitment scheme integration with verification protocols
#[test]
fn test_commitment_integration() -> Result<()> {
    // Test multiple commitment schemes
    let secret_value = 42u64;
    let randomness = 123456u64;
    
    // Hash commitment
    let hash_commitment = HashCommitment::commit_u64(secret_value, randomness);
    assert!(HashCommitment::verify_u64(&hash_commitment, secret_value, randomness));
    
    // Pedersen commitment (elliptic curve based)
    let pedersen_commitment = PedersenCommitment::commit(secret_value, randomness);
    let is_valid = PedersenCommitment::verify(pedersen_commitment, secret_value, randomness);
    assert!(is_valid);
    
    // Batch commitment test
    let values = vec![10u64, 20u64, 30u64, 40u64];
    let randomness_vec = vec![111u64, 222u64, 333u64, 444u64];
    
    let batch_commitments = HashCommitment::batch_commit_u64(&values, &randomness_vec)?;
    
    for (i, (&value, &rand)) in values.iter().zip(randomness_vec.iter()).enumerate() {
        let is_valid = HashCommitment::verify_u64(&batch_commitments[i], value, rand);
        assert!(is_valid);
    }
    
    Ok(())
}

/// Test error handling and edge cases
#[test]
fn test_error_handling_integration() -> Result<()> {
    // Test insufficient shares for reconstruction
    let secret = 42u64;
    let threshold = 3;
    let total_parties = 5;
    
    let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
    
    // Try to reconstruct with too few shares
    let insufficient_shares = &shares[0..threshold-1];
    let result = ShamirSecretSharing::reconstruct(insufficient_shares, threshold);
    assert!(result.is_err());
    
    // Test invalid threshold
    let invalid_result = ShamirSecretSharing::share(&secret, 0, total_parties);
    assert!(invalid_result.is_err());
    
    let invalid_result = ShamirSecretSharing::share(&secret, total_parties + 1, total_parties);
    assert!(invalid_result.is_err());
    
    Ok(())
}

/// Test performance and scalability characteristics  
#[test]
fn test_scalability_integration() -> Result<()> {
    // Test with larger parameters to ensure scalability
    let party_count = 10;
    let threshold = 7;
    let secret = 123456789u64;
    
    // Share the secret among many parties
    let shares = ShamirSecretSharing::share(&secret, threshold, party_count)?;
    assert_eq!(shares.len(), party_count);
    
    // Reconstruct using exactly threshold shares
    let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
    assert_eq!(reconstructed, secret);
    
    // Test batch operations
    let batch_size = 100;
    let secrets: Vec<u64> = (1..=batch_size).collect();
    
    // Share all secrets
    let mut all_shares = Vec::new();
    for &secret in &secrets {
        let shares = ShamirSecretSharing::share(&secret, threshold, party_count)?;
        all_shares.push(shares);
    }
    
    // Reconstruct all secrets
    for (i, shares) in all_shares.iter().enumerate() {
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
        assert_eq!(reconstructed, secrets[i]);
    }
    
    Ok(())
}

/// Test cross-component compatibility
#[test]
fn test_cross_component_compatibility() -> Result<()> {
    // Test that different cryptographic components work together seamlessly
    let value = 999u64;
    let threshold = 2;
    let parties = 3;
    
    // 1. Share the value
    let shares = ShamirSecretSharing::share(&value, threshold, parties)?;
    
    // 2. Commit to each share
    let mut commitments = Vec::new();
    let mut randomness_values = Vec::new();
    
    for share in &shares {
        let randomness = 54321u64;
        let commitment = HashCommitment::commit_u64(share.y, randomness); // Use share.y (the value)
        commitments.push(commitment);
        randomness_values.push(randomness);
    }
    
    // 3. Generate Beaver triple for the same parameters
    let mut generator = TrustedPartyBeaverGenerator::new(parties, threshold, 0, None)?;
    let triple = generator.generate_single()?;
    
    // 4. Verify everything is consistent
    assert!(triple.verify(threshold)?);
    
    // 5. Verify all commitments
    for (i, share) in shares.iter().enumerate() {
        let is_valid = HashCommitment::verify_u64(&commitments[i], share.y, randomness_values[i]);
        assert!(is_valid);
    }
    
    // 6. Reconstruct original value
    let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
    assert_eq!(reconstructed, value);
    
    Ok(())
}

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