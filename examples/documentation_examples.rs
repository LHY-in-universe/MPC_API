//! Documentation Examples for MPC API
//! 
//! ## Bash 测试代码
//! 
//! ```bash
//! # 编译检查
//! cargo check --example documentation_examples
//! 
//! # 运行文档示例
//! cargo run --example documentation_examples
//! 
//! # 运行所有测试
//! cargo test --example documentation_examples
//! 
//! # 运行特定文档示例测试
//! cargo test test_basic_secret_sharing
//! cargo test test_homomorphic_operations
//! cargo test test_commitment_schemes
//! cargo test test_beaver_triples
//! cargo test test_message_authentication
//! cargo test test_complete_mpc_protocol
//! cargo test test_error_handling
//! 
//! # 文档示例性能基准测试
//! cargo bench --bench mpc_benchmarks -- documentation
//! 
//! # 生成文档示例文档
//! cargo doc --example documentation_examples --open
//! ```
//! 
//! This file contains well-documented examples that demonstrate the core features
//! of the MPC API. These examples are designed to be included in the library's
//! documentation and serve as a reference for users.

use mpc_api::*;

/// # Basic Secret Sharing Example
/// 
/// This example demonstrates the fundamental concepts of secret sharing using
/// Shamir's Secret Sharing scheme.
/// 
/// ## What this example shows:
/// - How to share a secret among multiple parties
/// - How to reconstruct the secret from shares
/// - The threshold property (any k shares can reconstruct, but k-1 cannot)
/// 
/// ```rust
/// use mpc_api::*;
/// 
/// # fn main() -> Result<()> {
/// // Step 1: Define the secret and sharing parameters
/// let secret = 123456u64;          // The secret value to share
/// let threshold = 3;               // Minimum shares needed for reconstruction
/// let total_parties = 5;           // Total number of parties receiving shares
/// 
/// // Step 2: Create secret shares
/// let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
/// 
/// // Each party receives one share
/// println!("Party 1 receives share: ({}, {})", shares[0].x, shares[0].y);
/// println!("Party 2 receives share: ({}, {})", shares[1].x, shares[1].y);
/// // ... and so on for all parties
/// 
/// // Step 3: Reconstruct the secret using threshold shares
/// let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
/// assert_eq!(reconstructed, secret);
/// 
/// // Step 4: Demonstrate that fewer than threshold shares cannot reconstruct
/// let insufficient_shares = &shares[0..threshold-1];
/// let result = ShamirSecretSharing::reconstruct(insufficient_shares, threshold);
/// assert!(result.is_err()); // This will fail as expected
/// 
/// println!("✓ Secret sharing completed successfully!");
/// # Ok(())
/// # }
/// ```
fn basic_secret_sharing_example() -> Result<()> {
    let secret = 123456u64;
    let threshold = 3;
    let total_parties = 5;
    
    let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
    println!("Created {} shares for secret {}", shares.len(), secret);
    
    let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
    assert_eq!(reconstructed, secret);
    println!("✓ Secret reconstructed successfully: {}", reconstructed);
    
    Ok(())
}

/// # Homomorphic Operations Example
/// 
/// This example demonstrates how secret sharing provides homomorphic properties,
/// allowing computation on encrypted/shared data without revealing the underlying values.
/// 
/// ## What this example shows:
/// - Additive homomorphism: shares of (a + b) = shares of a + shares of b
/// - Scalar multiplication: shares of (k * a) = k * shares of a
/// - How to perform secure computations on shared data
/// 
/// ```rust
/// use mpc_api::*;
/// 
/// # fn main() -> Result<()> {
/// // Two secret values that we want to add securely
/// let secret_a = 100u64;
/// let secret_b = 200u64;
/// let threshold = 2;
/// let parties = 3;
/// 
/// // Share both secrets
/// let shares_a = ShamirSecretSharing::share(&secret_a, threshold, parties)?;
/// let shares_b = ShamirSecretSharing::share(&secret_b, threshold, parties)?;
/// 
/// // Perform homomorphic addition on the shares
/// let sum_shares: Result<Vec<_>> = shares_a.iter()
///     .zip(shares_b.iter())
///     .map(|(share_a, share_b)| ShamirSecretSharing::add_shares(share_a, share_b))
///     .collect();
/// let sum_shares = sum_shares?;
/// 
/// // Reconstruct the sum
/// let sum_result = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
/// 
/// // Verify the result
/// let expected_sum = field_add(secret_a, secret_b);
/// assert_eq!(sum_result, expected_sum);
/// 
/// println!("Secure addition: {} + {} = {}", secret_a, secret_b, sum_result);
/// 
/// // Demonstrate scalar multiplication
/// let scalar = 3u64;
/// let scalar_shares: Result<Vec<_>> = shares_a.iter()
///     .map(|share| ShamirSecretSharing::scalar_mul(share, &scalar))
///     .collect();
/// let scalar_shares = scalar_shares?;
/// 
/// let scalar_result = ShamirSecretSharing::reconstruct(&scalar_shares[0..threshold], threshold)?;
/// let expected_scalar = field_mul(secret_a, scalar);
/// assert_eq!(scalar_result, expected_scalar);
/// 
/// println!("Scalar multiplication: {} * {} = {}", secret_a, scalar, scalar_result);
/// # Ok(())
/// # }
/// ```
fn homomorphic_operations_example() -> Result<()> {
    let secret_a = 100u64;
    let secret_b = 200u64;
    let threshold = 2;
    let parties = 3;
    
    let shares_a = ShamirSecretSharing::share(&secret_a, threshold, parties)?;
    let shares_b = ShamirSecretSharing::share(&secret_b, threshold, parties)?;
    
    // Homomorphic addition
    let sum_shares: Result<Vec<_>> = shares_a.iter()
        .zip(shares_b.iter())
        .map(|(share_a, share_b)| ShamirSecretSharing::add_shares(share_a, share_b))
        .collect();
    let sum_shares = sum_shares?;
    
    let sum_result = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
    let expected_sum = field_add(secret_a, secret_b);
    assert_eq!(sum_result, expected_sum);
    
    println!("✓ Homomorphic addition: {} + {} = {}", secret_a, secret_b, sum_result);
    
    Ok(())
}

/// # Commitment Schemes Example
/// 
/// This example demonstrates how to use commitment schemes to ensure data integrity
/// and enable non-interactive verification protocols.
/// 
/// ## What this example shows:
/// - Hash-based commitments for simple values
/// - Pedersen commitments using elliptic curves
/// - Batch commitment operations
/// - Commitment verification
/// 
/// ```rust
/// use mpc_api::*;
/// 
/// # fn main() -> Result<()> {
/// // Commit to a secret value
/// let secret_value = 42u64;
/// let randomness = 12345u64;
/// 
/// // Create hash commitment
/// let hash_commitment = HashCommitment::commit_u64(secret_value, randomness);
/// 
/// // Later, reveal and verify the commitment
/// let is_valid = HashCommitment::verify_u64(&hash_commitment, secret_value, randomness);
/// assert!(is_valid);
/// 
/// // Try to verify with wrong value (should fail)
/// let is_invalid = HashCommitment::verify_u64(&hash_commitment, secret_value + 1, randomness);
/// assert!(!is_invalid);
/// 
/// println!("✓ Hash commitment verified successfully");
/// 
/// // Create Pedersen commitment (more advanced, allows homomorphic operations)
/// let pedersen_commitment = PedersenCommitment::commit(secret_value, randomness);
/// let is_valid = PedersenCommitment::verify(pedersen_commitment, secret_value, randomness);
/// assert!(is_valid);
/// 
/// println!("✓ Pedersen commitment verified successfully");
/// 
/// // Batch commitments for multiple values
/// let values = vec![10u64, 20u64, 30u64];
/// let randomness_values = vec![100u64, 200u64, 300u64];
/// 
/// let batch_commitments = HashCommitment::batch_commit_u64(&values, &randomness_values)?;
/// 
/// // Verify each commitment in the batch
/// for (i, (&value, &rand)) in values.iter().zip(randomness_values.iter()).enumerate() {
///     let is_valid = HashCommitment::verify_u64(&batch_commitments[i], value, rand);
///     assert!(is_valid);
/// }
/// 
/// println!("✓ Batch commitments verified successfully");
/// # Ok(())
/// # }
/// ```
fn commitment_schemes_example() -> Result<()> {
    let secret_value = 42u64;
    let randomness = 12345u64;
    
    // Hash commitment
    let hash_commitment = HashCommitment::commit_u64(secret_value, randomness);
    let is_valid = HashCommitment::verify_u64(&hash_commitment, secret_value, randomness);
    assert!(is_valid);
    println!("✓ Hash commitment created and verified");
    
    // Pedersen commitment
    let pedersen_commitment = PedersenCommitment::commit(secret_value, randomness);
    let is_valid = PedersenCommitment::verify(pedersen_commitment, secret_value, randomness);
    assert!(is_valid);
    println!("✓ Pedersen commitment created and verified");
    
    Ok(())
}

/// # Beaver Triples Example
/// 
/// This example demonstrates how to generate and use Beaver triples for secure
/// multiplication in multi-party computation protocols.
/// 
/// ## What this example shows:
/// - Trusted party generation of Beaver triples
/// - Triple verification
/// - How triples enable secure multiplication
/// 
/// ```rust
/// use mpc_api::*;
/// 
/// # fn main() -> Result<()> {
/// // Setup parameters for Beaver triple generation
/// let party_count = 3;
/// let threshold = 2;
/// let party_id = 0;
/// 
/// // Create a trusted party generator
/// let mut generator = TrustedPartyBeaverGenerator::new(
///     party_count, 
///     threshold, 
///     party_id, 
///     None
/// )?;
/// 
/// // Generate a single Beaver triple
/// let triple = generator.generate_single()?;
/// 
/// // Verify the triple is valid
/// let is_valid = triple.verify(threshold)?;
/// assert!(is_valid);
/// 
/// println!("✓ Beaver triple generated and verified");
/// 
/// // Generate multiple triples in batch for efficiency
/// let batch_size = 10;
/// let triples = generator.generate_batch(batch_size)?;
/// 
/// // Verify all triples in the batch
/// for (i, triple) in triples.iter().enumerate() {
///     let is_valid = triple.verify(threshold)?;
///     assert!(is_valid);
///     println!("✓ Triple {} verified", i + 1);
/// }
/// 
/// println!("✓ All {} triples generated and verified successfully", batch_size);
/// # Ok(())
/// # }
/// ```
fn beaver_triples_example() -> Result<()> {
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    
    let mut generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
    let triple = generator.generate_single()?;
    
    let is_valid = triple.verify(threshold)?;
    assert!(is_valid);
    println!("✓ Beaver triple generated and verified");
    
    Ok(())
}

/// # Message Authentication Example
/// 
/// This example demonstrates how to use HMAC for message authentication
/// in secure communication protocols.
/// 
/// ## What this example shows:
/// - HMAC key generation
/// - Message authentication
/// - Authentication verification
/// - Security against tampering
/// 
/// ```rust
/// use mpc_api::*;
/// 
/// # fn main() -> Result<()> {
/// // Generate a random HMAC key
/// let key = HMAC::generate_key();
/// 
/// // Message to authenticate
/// let message = b"Important MPC protocol message".to_vec();
/// 
/// // Create authentication tag
/// let auth_tag = HMAC::authenticate(&key, &message);
/// 
/// // Verify the message and tag
/// let is_authentic = HMAC::verify(&key, &message, &auth_tag);
/// assert!(is_authentic);
/// 
/// println!("✓ Message authenticated successfully");
/// 
/// // Demonstrate security: tampering detection
/// let tampered_message = b"Tampered MPC protocol message".to_vec();
/// let is_tampered = HMAC::verify(&key, &tampered_message, &auth_tag);
/// assert!(!is_tampered); // Should detect tampering
/// 
/// println!("✓ Message tampering detected successfully");
/// 
/// // Demonstrate that wrong key fails verification
/// let wrong_key = HMAC::generate_key();
/// let wrong_key_result = HMAC::verify(&wrong_key, &message, &auth_tag);
/// assert!(!wrong_key_result); // Should fail with wrong key
/// 
/// println!("✓ Wrong key detection working correctly");
/// # Ok(())
/// # }
/// ```
fn message_authentication_example() -> Result<()> {
    let key = HMAC::generate_key();
    let message = b"Important MPC protocol message".to_vec();
    
    let auth_tag = HMAC::authenticate(&key, &message);
    let is_authentic = HMAC::verify(&key, &message, &auth_tag);
    assert!(is_authentic);
    
    println!("✓ Message authentication working correctly");
    
    Ok(())
}

/// # Complete MPC Protocol Example
/// 
/// This example demonstrates a complete multi-party computation protocol
/// combining multiple components of the MPC API.
/// 
/// ## What this example shows:
/// - End-to-end MPC workflow
/// - Integration of multiple MPC components
/// - Secure computation with verification
/// - Real-world usage patterns
/// 
/// ```rust
/// use mpc_api::*;
/// 
/// # fn main() -> Result<()> {
/// // Scenario: Three parties want to compute the sum of their private inputs
/// // without revealing individual values
/// 
/// let party_inputs = vec![100u64, 250u64, 150u64];
/// let threshold = 2; // Any 2 parties can reconstruct
/// let num_parties = 3;
/// 
/// println!("Starting secure multi-party computation...");
/// 
/// // Step 1: Each party shares their input
/// let mut all_shares = Vec::new();
/// for (party_id, &input) in party_inputs.iter().enumerate() {
///     let shares = ShamirSecretSharing::share(&input, threshold, num_parties)?;
///     all_shares.push(shares);
///     println!("Party {} shared their input securely", party_id + 1);
/// }
/// 
/// // Step 2: Compute the sum homomorphically (without revealing individual values)
/// let mut sum_shares = all_shares[0].clone();
/// for shares in &all_shares[1..] {
///     for (i, share) in shares.iter().enumerate() {
///         sum_shares[i] = ShamirSecretSharing::add_shares(&sum_shares[i], share)?;
///     }
/// }
/// 
/// // Step 3: Reconstruct the final result
/// let secure_sum = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
/// 
/// // Step 4: Verify the result (in a real protocol, this verification would be done differently)
/// let expected_sum: u64 = party_inputs.iter().sum();
/// assert_eq!(secure_sum, expected_sum);
/// 
/// println!("✓ Secure computation completed!");
/// println!("Sum of private inputs: {}", secure_sum);
/// 
/// // Step 5: Create a commitment to the result for non-repudiation
/// let commitment_randomness = 98765u64;
/// let result_commitment = HashCommitment::commit_u64(secure_sum, commitment_randomness);
/// 
/// // Step 6: Generate authentication for the protocol transcript
/// let auth_key = HMAC::generate_key();
/// let protocol_transcript = format!("MPC_SUM_RESULT_{}", secure_sum);
/// let auth_tag = HMAC::authenticate(&auth_key, &protocol_transcript.into_bytes());
/// 
/// println!("✓ Result committed and authenticated");
/// println!("Protocol completed successfully!");
/// 
/// # Ok(())
/// # }
/// ```
fn complete_mpc_protocol_example() -> Result<()> {
    let party_inputs = vec![100u64, 250u64, 150u64];
    let threshold = 2;
    let num_parties = 3;
    
    println!("Starting secure multi-party computation...");
    
    // Share all inputs
    let mut all_shares = Vec::new();
    for (party_id, &input) in party_inputs.iter().enumerate() {
        let shares = ShamirSecretSharing::share(&input, threshold, num_parties)?;
        all_shares.push(shares);
        println!("Party {} shared their input securely", party_id + 1);
    }
    
    // Compute sum homomorphically
    let mut sum_shares = all_shares[0].clone();
    for shares in &all_shares[1..] {
        for (i, share) in shares.iter().enumerate() {
            sum_shares[i] = ShamirSecretSharing::add_shares(&sum_shares[i], share)?;
        }
    }
    
    // Reconstruct result
    let secure_sum = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
    let expected_sum: u64 = party_inputs.iter().sum();
    assert_eq!(secure_sum, expected_sum);
    
    println!("✓ Secure computation completed! Sum: {}", secure_sum);
    
    Ok(())
}

/// # Error Handling Example
/// 
/// This example demonstrates proper error handling in MPC protocols.
/// 
/// ## What this example shows:
/// - Common error conditions
/// - Proper error handling patterns
/// - Recovery strategies
/// - Defensive programming practices
/// 
/// ```rust
/// use mpc_api::*;
/// 
/// # fn main() -> Result<()> {
/// // Example 1: Handle invalid threshold
/// let secret = 42u64;
/// 
/// match ShamirSecretSharing::share(&secret, 0, 3) {
///     Ok(_) => println!("Unexpected success"),
///     Err(MpcError::InvalidThreshold) => {
///         println!("✓ Correctly detected invalid threshold");
///     }
///     Err(e) => println!("Unexpected error: {:?}", e),
/// }
/// 
/// // Example 2: Handle insufficient shares for reconstruction
/// let shares = ShamirSecretSharing::share(&secret, 3, 5)?;
/// let insufficient_shares = &shares[0..2]; // Need 3, only have 2
/// 
/// match ShamirSecretSharing::reconstruct(insufficient_shares, 3) {
///     Ok(_) => println!("Unexpected success"),
///     Err(MpcError::InsufficientShares) => {
///         println!("✓ Correctly detected insufficient shares");
///     }
///     Err(e) => println!("Unexpected error: {:?}", e),
/// }
/// 
/// // Example 3: Handle Beaver triple generation errors
/// match TrustedPartyBeaverGenerator::new(0, 2, 0, None) {
///     Ok(_) => println!("Unexpected success"),
///     Err(e) => {
///         println!("✓ Correctly detected invalid party configuration: {}", e);
///     }
/// }
/// 
/// // Example 4: Handle commitment verification failures gracefully
/// let value = 123u64;
/// let randomness = 456u64;
/// let commitment = HashCommitment::commit_u64(value, randomness);
/// 
/// // Verify with correct values
/// if HashCommitment::verify_u64(&commitment, value, randomness) {
///     println!("✓ Commitment verified correctly");
/// } else {
///     println!("❌ Commitment verification failed unexpectedly");
/// }
/// 
/// // Verify with incorrect values (should fail)
/// if !HashCommitment::verify_u64(&commitment, value + 1, randomness) {
///     println!("✓ Correctly detected invalid commitment");
/// } else {
///     println!("❌ Failed to detect invalid commitment");
/// }
/// 
/// println!("Error handling examples completed successfully");
/// # Ok(())
/// # }
/// ```
fn error_handling_example() -> Result<()> {
    println!("Demonstrating error handling patterns...");
    
    // Test invalid threshold
    let secret = 42u64;
    match ShamirSecretSharing::share(&secret, 0, 3) {
        Ok(_) => println!("Unexpected success"),
        Err(MpcError::InvalidThreshold) => {
            println!("✓ Correctly detected invalid threshold");
        }
        Err(e) => println!("Unexpected error: {:?}", e),
    }
    
    // Test insufficient shares
    let shares = ShamirSecretSharing::share(&secret, 3, 5)?;
    let insufficient_shares = &shares[0..2];
    
    match ShamirSecretSharing::reconstruct(insufficient_shares, 3) {
        Ok(_) => println!("Unexpected success"),
        Err(MpcError::InsufficientShares) => {
            println!("✓ Correctly detected insufficient shares");
        }
        Err(e) => println!("Unexpected error: {:?}", e),
    }
    
    println!("✓ Error handling examples completed");
    
    Ok(())
}

/// Main function to run all documentation examples
fn main() -> Result<()> {
    println!("🔐 MPC API Documentation Examples\n");
    
    println!("1. Basic Secret Sharing:");
    basic_secret_sharing_example()?;
    println!();
    
    println!("2. Homomorphic Operations:");
    homomorphic_operations_example()?;
    println!();
    
    println!("3. Commitment Schemes:");
    commitment_schemes_example()?;
    println!();
    
    println!("4. Beaver Triples:");
    beaver_triples_example()?;
    println!();
    
    println!("5. Message Authentication:");
    message_authentication_example()?;
    println!();
    
    println!("6. Complete MPC Protocol:");
    complete_mpc_protocol_example()?;
    println!();
    
    println!("7. Error Handling:");
    error_handling_example()?;
    println!();
    
    println!("🎉 All documentation examples completed successfully!");
    println!("\nThese examples demonstrate:");
    println!("• Secret sharing fundamentals");
    println!("• Homomorphic computations");
    println!("• Cryptographic commitments");
    println!("• Beaver triple generation");
    println!("• Message authentication");
    println!("• Complete MPC workflows");
    println!("• Proper error handling");
    
    Ok(())
}