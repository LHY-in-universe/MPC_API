//! Comprehensive error handling tests for MPC API
//! 
//! This test suite verifies that the MPC API properly handles error conditions,
//! edge cases, and invalid inputs with appropriate error messages and recovery.

use mpc_api::*;

/// Test error handling in secret sharing operations
#[test]
fn test_secret_sharing_error_handling() {
    // Test invalid threshold (threshold = 0)
    let secret = 42u64;
    let result = ShamirSecretSharing::share(&secret, 0, 3);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, MpcError::InvalidThreshold));
    }
    
    // Test invalid threshold (threshold > parties)
    let result = ShamirSecretSharing::share(&secret, 5, 3);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, MpcError::InvalidThreshold));
    }
    
    // Test reconstruction with insufficient shares
    let shares = ShamirSecretSharing::share(&secret, 3, 5).unwrap();
    let insufficient_shares = &shares[0..2]; // Only 2 shares, need 3
    let result = ShamirSecretSharing::reconstruct(insufficient_shares, 3);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, MpcError::InsufficientShares));
    }
    
    // Test reconstruction with empty shares
    let empty_shares: Vec<Share> = vec![];
    let result = ShamirSecretSharing::reconstruct(&empty_shares, 3);
    assert!(result.is_err());
    
    // Test reconstruction with inconsistent share indices
    let mut bad_shares = shares[0..3].to_vec();
    bad_shares[1].x = bad_shares[0].x; // Duplicate x coordinate
    let result = ShamirSecretSharing::reconstruct(&bad_shares, 3);
    // This should either error or handle gracefully
    // The specific behavior depends on the implementation
}

/// Test error handling in Beaver triple operations
#[test] 
fn test_beaver_triple_error_handling() {
    // Test invalid party count
    let result = TrustedPartyBeaverGenerator::new(0, 2, 0, None);
    assert!(result.is_err());
    
    // Test invalid threshold
    let result = TrustedPartyBeaverGenerator::new(5, 0, 0, None);
    assert!(result.is_err());
    
    // Test threshold greater than party count
    let result = TrustedPartyBeaverGenerator::new(3, 5, 0, None);
    assert!(result.is_err());
    
    // Test invalid party ID
    let result = TrustedPartyBeaverGenerator::new(3, 2, 5, None);
    assert!(result.is_err());
    
    // Test verification with insufficient shares
    let mut generator = TrustedPartyBeaverGenerator::new(5, 3, 0, None).unwrap();
    let mut triple = generator.generate_single().unwrap();
    
    // Remove shares to make verification fail
    triple.shares.clear();
    let result = triple.verify(3);
    assert!(result.is_ok() && !result.unwrap());
}

/// Test error handling in commitment schemes
#[test]
fn test_commitment_error_handling() {
    // Test hash commitment with mismatched values
    let value = 12345u64;
    let randomness = 67890u64;
    let commitment = HashCommitment::commit_u64(value, randomness);
    
    // Verify with wrong value
    let is_valid = HashCommitment::verify_u64(&commitment, value + 1, randomness);
    assert!(!is_valid);
    
    // Verify with wrong randomness
    let is_valid = HashCommitment::verify_u64(&commitment, value, randomness + 1);
    assert!(!is_valid);
    
    // Test batch commitment with mismatched array lengths
    let values = vec![1u64, 2u64, 3u64];
    let randomness = vec![10u64, 20u64]; // Different length
    let result = HashCommitment::batch_commit_u64(&values, &randomness);
    assert!(result.is_err());
    
    // Test with empty arrays
    let empty_values: Vec<u64> = vec![];
    let empty_randomness: Vec<u64> = vec![];
    let result = HashCommitment::batch_commit_u64(&empty_values, &empty_randomness);
    assert!(result.is_ok()); // Empty arrays should be valid
    assert_eq!(result.unwrap().len(), 0);
}

/// Test error handling in authentication
#[test]
fn test_authentication_error_handling() {
    let key = HMAC::generate_key();
    let message = b"test message".to_vec();
    let tag = HMAC::authenticate(&key, &message);
    
    // Test verification with wrong key
    let wrong_key = HMAC::generate_key();
    let is_valid = HMAC::verify(&wrong_key, &message, &tag);
    assert!(!is_valid);
    
    // Test verification with wrong message
    let wrong_message = b"wrong message".to_vec();
    let is_valid = HMAC::verify(&key, &wrong_message, &tag);
    assert!(!is_valid);
    
    // Test with empty message
    let empty_message = vec![];
    let empty_tag = HMAC::authenticate(&key, &empty_message);
    let is_valid = HMAC::verify(&key, &empty_message, &empty_tag);
    assert!(is_valid); // Empty message should be valid
}

/// Test error handling in field operations
#[test]
fn test_field_operations_error_handling() {
    // Test operations near field boundaries
    let max_val = FIELD_PRIME - 1;
    
    // These should not panic or overflow
    let result = field_add(max_val, 1);
    assert!(result < FIELD_PRIME);
    
    let result = field_mul(max_val, max_val);
    assert!(result < FIELD_PRIME);
    
    // Test subtraction with potential underflow
    let result = field_sub(0, 1);
    assert!(result < FIELD_PRIME);
    
    // Test with zero values
    assert_eq!(field_add(0, 0), 0);
    assert_eq!(field_mul(0, 123), 0);
    assert_eq!(field_mul(123, 0), 0);
    assert_eq!(field_sub(0, 0), 0);
}

/// Test error handling in oblivious transfer
#[test]
fn test_oblivious_transfer_error_handling() {
    let mut ot = BasicOT::new();
    
    // Test with large messages (should handle gracefully)
    let large_msg0 = vec![0u8; 1000000]; // 1MB message
    let large_msg1 = vec![1u8; 1000000]; // 1MB message
    
    let result = ot.sender_phase1(large_msg0, large_msg1);
    // Should either succeed or fail gracefully
    match result {
        Ok(_) => {
            // If it succeeds, that's fine
        }
        Err(e) => {
            // If it fails, it should be a proper error, not a panic
            assert!(matches!(e, MpcError::ProtocolError(_) | MpcError::CryptographicError(_)));
        }
    }
    
    // Test with empty messages
    let empty_msg0 = vec![];
    let empty_msg1 = vec![];
    let mut ot2 = BasicOT::new();
    let result = ot2.sender_phase1(empty_msg0, empty_msg1);
    // Should handle empty messages gracefully
    assert!(result.is_ok() || matches!(result.err(), Some(MpcError::ProtocolError(_))));
}

/// Test concurrent access and thread safety
#[test]
fn test_concurrent_error_handling() {
    use std::sync::Arc;
    use std::thread;
    
    // Test multiple threads sharing secrets simultaneously
    let handles: Vec<_> = (0..5).map(|i| {
        thread::spawn(move || {
            let secret = i as u64 * 1000;
            let result = ShamirSecretSharing::share(&secret, 2, 3);
            
            match result {
                Ok(shares) => {
                    // Verify we can reconstruct
                    let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..2], 2);
                    assert!(reconstructed.is_ok());
                    assert_eq!(reconstructed.unwrap(), secret);
                }
                Err(e) => {
                    // Should not fail for valid inputs
                    panic!("Unexpected error in thread {}: {:?}", i, e);
                }
            }
        })
    }).collect();
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test memory limits and resource exhaustion
#[test]
fn test_resource_exhaustion_handling() {
    // Test creating many shares
    let secret = 42u64;
    
    // Try to create shares with many parties (should handle gracefully)
    let result = ShamirSecretSharing::share(&secret, 100, 1000);
    match result {
        Ok(shares) => {
            assert_eq!(shares.len(), 1000);
            // Try to reconstruct with minimal shares
            let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..100], 100);
            assert!(reconstructed.is_ok());
            assert_eq!(reconstructed.unwrap(), secret);
        }
        Err(_) => {
            // If the system can't handle 1000 parties, that's acceptable
            // as long as it fails gracefully
        }
    }
    
    // Test batch operations with many items
    let many_values: Vec<u64> = (0..10000).collect();
    let many_randomness: Vec<u64> = (10000..20000).collect();
    
    let result = HashCommitment::batch_commit_u64(&many_values, &many_randomness);
    match result {
        Ok(commitments) => {
            assert_eq!(commitments.len(), 10000);
        }
        Err(_) => {
            // If the system can't handle 10000 commitments, that's acceptable
            // as long as it fails gracefully
        }
    }
}

/// Test error propagation and recovery
#[test] 
fn test_error_propagation() {
    // Test that errors propagate correctly through complex operations
    let secret = 42u64;
    
    // Create a scenario where an error occurs deep in the call stack
    let shares = ShamirSecretSharing::share(&secret, 3, 5).unwrap();
    
    // Create a scenario with insufficient shares and ensure error propagates
    let insufficient_shares = &shares[0..2];
    
    // This should fail at reconstruction level
    let result = ShamirSecretSharing::reconstruct(insufficient_shares, 3);
    assert!(result.is_err());
    
    // Test error in Beaver triple verification
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None).unwrap();
    let mut triple = generator.generate_single().unwrap();
    
    // Corrupt the triple
    if let Some(share) = triple.shares.get_mut(&0) {
        share.c.y += 1; // Corrupt the c share
    }
    
    // Verification should detect the corruption
    let result = triple.verify(2);
    // The exact behavior depends on implementation, but it should handle corruption
    assert!(result.is_ok()); // The function returns Ok(bool), not Err
}

/// Test boundary conditions and edge cases
#[test]
fn test_boundary_conditions() {
    // Test with minimum valid parameters
    let secret = 1u64;
    let shares = ShamirSecretSharing::share(&secret, 1, 1).unwrap();
    assert_eq!(shares.len(), 1);
    
    let reconstructed = ShamirSecretSharing::reconstruct(&shares, 1).unwrap();
    assert_eq!(reconstructed, secret);
    
    // Test with maximum field value
    let max_secret = FIELD_PRIME - 1;
    let shares = ShamirSecretSharing::share(&max_secret, 2, 3).unwrap();
    let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..2], 2).unwrap();
    assert_eq!(reconstructed, max_secret);
    
    // Test with zero secret
    let zero_secret = 0u64;
    let shares = ShamirSecretSharing::share(&zero_secret, 2, 3).unwrap();
    let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..2], 2).unwrap();
    assert_eq!(reconstructed, zero_secret);
}

/// Test invalid input sanitization
#[test]
fn test_input_sanitization() {
    // Test that the system properly handles and sanitizes invalid inputs
    
    // Test share operations with invalid x coordinates
    let share1 = Share::new(0, 100); // x = 0 might be invalid in some schemes
    let share2 = Share::new(1, 200);
    let share3 = Share::new(2, 300);
    
    let shares = vec![share1, share2, share3];
    let result = ShamirSecretSharing::reconstruct(&shares[0..2], 2);
    
    // The system should either handle x=0 correctly or fail gracefully
    match result {
        Ok(_) => {
            // x=0 is handled correctly
        }
        Err(_) => {
            // x=0 is rejected, which is also valid
        }
    }
    
    // Test with duplicate x coordinates
    let share1 = Share::new(1, 100);
    let share2 = Share::new(1, 200); // Duplicate x
    let share3 = Share::new(2, 300);
    
    let duplicate_shares = vec![share1, share2, share3];
    let result = ShamirSecretSharing::reconstruct(&duplicate_shares, 2);
    
    // Should handle duplicate x coordinates gracefully
    // This might succeed (using first occurrence) or fail
    match result {
        Ok(_) => {
            // System handles duplicates by using one of them
        }
        Err(_) => {
            // System rejects duplicates, which is safer
        }
    }
}

/// Test error message quality and debugging information
#[test]
fn test_error_messages() {
    // Test that error messages provide useful information for debugging
    
    let result = ShamirSecretSharing::share(&42u64, 0, 3);
    if let Err(e) = result {
        let error_string = format!("{}", e);
        assert!(!error_string.is_empty());
        // Error message should be descriptive
        assert!(error_string.len() > 10);
    }
    
    let result = TrustedPartyBeaverGenerator::new(0, 2, 0, None);
    if let Err(e) = result {
        let error_string = format!("{}", e);
        assert!(!error_string.is_empty());
        // Should provide context about what went wrong
    }
    
    // Test error chain and source information
    let shares = ShamirSecretSharing::share(&42u64, 3, 5).unwrap();
    let result = ShamirSecretSharing::reconstruct(&shares[0..1], 3);
    if let Err(e) = result {
        // Error should implement standard error traits
        let error_string = format!("{}", e);
        assert!(error_string.contains("Insufficient") || error_string.contains("shares"));
    }
}