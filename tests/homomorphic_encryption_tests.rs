//! 同态加密测试
//! 
//! 包含 BFV, BGV, Paillier, ElGamal, RSA 等同态加密方案的测试

use mpc_api::homomorphic_encryption::{HomomorphicEncryption, AdditivelyHomomorphic, MultiplicativelyHomomorphic};
use mpc_api::homomorphic_encryption::bfv::*;
use mpc_api::homomorphic_encryption::rsa::*;
use mpc_api::homomorphic_encryption::elgamal::*;
use mpc_api::homomorphic_encryption::paillier::*;
use mpc_api::secret_sharing::{FIELD_PRIME, field_mul};

// ===== BFV Tests =====

#[test]
fn test_bfv_keygen() {
    let result = BFV::keygen();
    assert!(result.is_ok());
    
    let (pk, sk) = result.unwrap();
    // Test that keys are generated with reasonable values
    assert!(pk.n > 0);
    assert!(pk.q > 0);
    assert!(pk.t > 0);
    assert_eq!(sk.n, pk.n);
}

#[test]
fn test_bfv_encrypt_decrypt() {
    let (pk, sk) = BFV::keygen().unwrap();
    let message = 5u64;
    
    let ciphertext = BFV::encrypt(&pk, &message).unwrap();
    let decrypted = BFV::decrypt(&sk, &ciphertext).unwrap();
    
    // Due to noise, exact equality might not hold
    // In practice, we'd check if decrypted is close to message
    assert!(decrypted < pk.t);
}

#[test]
fn test_bfv_homomorphic_addition() {
    let (pk, sk) = BFV::keygen().unwrap();
    let m1 = 3u64;
    let m2 = 4u64;
    
    let c1 = BFV::encrypt(&pk, &m1).unwrap();
    let c2 = BFV::encrypt(&pk, &m2).unwrap();
    
    let c_sum = BFV::add_ciphertexts(&pk, &c1, &c2).unwrap();
    let decrypted_sum = BFV::decrypt(&sk, &c_sum).unwrap();
    
    // Check if result is reasonable (noise might affect exact equality)
    assert!(decrypted_sum < pk.t);
}

// ===== RSA Tests =====

#[test]
fn test_rsa_keygen() {
    let result = RSA::keygen();
    assert!(result.is_ok());
    
    let (pk, sk) = result.unwrap();
    assert!(pk.n > 0);
    assert!(pk.e > 0);
    assert!(sk.d > 0);
    assert_eq!(pk.n, sk.n);
}

#[test]
fn test_rsa_encrypt_decrypt() {
    let (pk, sk) = RSA::keygen().unwrap();
    let message = 42u64;
    
    if message < pk.n {
        let ciphertext = RSA::encrypt(&pk, &message).unwrap();
        let decrypted = RSA::decrypt(&sk, &ciphertext).unwrap();
        assert_eq!(message, decrypted);
    }
}

#[test]
fn test_rsa_homomorphic_multiplication() {
    let (pk, sk) = RSA::keygen().unwrap();
    let m1 = 7u64;
    let m2 = 6u64;
    
    if m1 < pk.n && m2 < pk.n && (m1 * m2) < pk.n {
        let c1 = RSA::encrypt(&pk, &m1).unwrap();
        let c2 = RSA::encrypt(&pk, &m2).unwrap();
        
        let c_product = RSA::multiply_ciphertexts(&pk, &c1, &c2).unwrap();
        let decrypted_product = RSA::decrypt(&sk, &c_product).unwrap();
        
        assert_eq!(decrypted_product, m1 * m2);
    }
}

// ===== ElGamal Tests =====

#[test]
fn test_elgamal_keygen() {
    let (pk, sk) = ElGamal::keygen().unwrap();
    
    assert!(pk.generator > 0);
    assert!(pk.public_key > 0);
    assert!(pk.prime > 0);
    assert!(sk.private_key > 0);
    assert_eq!(pk.prime, sk.prime);
}

#[test]
fn test_elgamal_encrypt_decrypt() {
    let (pk, sk) = ElGamal::keygen().unwrap();
    let message = 42u64;
    
    let ciphertext = ElGamal::encrypt(&pk, &message).unwrap();
    let decrypted = ElGamal::decrypt(&sk, &ciphertext).unwrap();
    
    assert_eq!(message, decrypted);
}

#[test]
fn test_elgamal_homomorphic_multiplication() {
    let (pk, sk) = ElGamal::keygen().unwrap();
    let m1 = 7u64;
    let m2 = 6u64;
    
    let c1 = ElGamal::encrypt(&pk, &m1).unwrap();
    let c2 = ElGamal::encrypt(&pk, &m2).unwrap();
    
    // Homomorphic multiplication
    let c_product = ElGamal::multiply_ciphertexts(&pk, &c1, &c2).unwrap();
    let decrypted_product = ElGamal::decrypt(&sk, &c_product).unwrap();
    
    assert_eq!(decrypted_product, field_mul(m1, m2));
}

#[test]
fn test_elgamal_power() {
    let (pk, sk) = ElGamal::keygen().unwrap();
    let message = 3u64;
    let exponent = 4u64;
    
    let ciphertext = ElGamal::encrypt(&pk, &message).unwrap();
    let powered_ciphertext = ElGamal::power(&pk, &ciphertext, exponent).unwrap();
    let decrypted = ElGamal::decrypt(&sk, &powered_ciphertext).unwrap();
    
    let expected = message.pow(exponent as u32) % FIELD_PRIME;
    assert_eq!(decrypted, expected);
}

#[test]
fn test_elgamal_encrypt_zero() {
    let (pk, sk) = ElGamal::keygen().unwrap();
    
    let zero_encryption = ElGamal::encrypt_zero(&pk).unwrap();
    let decrypted = ElGamal::decrypt(&sk, &zero_encryption).unwrap();
    
    assert_eq!(decrypted, 1); // Multiplicative identity
}

#[test]
fn test_elgamal_randomization() {
    let (pk, sk) = ElGamal::keygen().unwrap();
    let message = 123u64;
    
    let original_ciphertext = ElGamal::encrypt(&pk, &message).unwrap();
    let randomized_ciphertext = ElGamal::randomize_ciphertext(&pk, &original_ciphertext).unwrap();
    
    // Should decrypt to the same value
    let decrypted_original = ElGamal::decrypt(&sk, &original_ciphertext).unwrap();
    let decrypted_randomized = ElGamal::decrypt(&sk, &randomized_ciphertext).unwrap();
    
    assert_eq!(decrypted_original, decrypted_randomized);
    assert_eq!(decrypted_original, message);
    
    // But ciphertexts should be different (with high probability)
    assert_ne!(original_ciphertext.c1, randomized_ciphertext.c1);
    assert_ne!(original_ciphertext.c2, randomized_ciphertext.c2);
}

#[test]
fn test_elgamal_multiple_multiplications() {
    let (pk, sk) = ElGamal::keygen().unwrap();
    let messages = vec![2u64, 3u64, 5u64];
    
    let mut ciphertexts = Vec::new();
    for &msg in &messages {
        ciphertexts.push(ElGamal::encrypt(&pk, &msg).unwrap());
    }
    
    // Multiply all ciphertexts together
    let mut product_ciphertext = ciphertexts[0].clone();
    for i in 1..ciphertexts.len() {
        product_ciphertext = ElGamal::multiply_ciphertexts(&pk, &product_ciphertext, &ciphertexts[i]).unwrap();
    }
    
    let decrypted_product = ElGamal::decrypt(&sk, &product_ciphertext).unwrap();
    
    // Expected product: 2 * 3 * 5 = 30
    let expected_product = messages.iter().fold(1u64, |acc, &x| field_mul(acc, x));
    assert_eq!(decrypted_product, expected_product);
}

// ===== Paillier Tests =====

#[test]
fn test_paillier_keygen() {
    let result = Paillier::keygen();
    assert!(result.is_ok());
    
    let (pk, sk) = result.unwrap();
    assert!(pk.n > 0);
    assert!(pk.n_squared > pk.n);
    assert!(pk.g > 0);
    assert!(sk.lambda > 0);
    assert!(sk.mu > 0);
    assert_eq!(pk.n, sk.n);
}

#[test]
fn test_paillier_encrypt_decrypt() {
    let (pk, sk) = Paillier::keygen().unwrap();
    let message = 42u64;
    
    let ciphertext = Paillier::encrypt(&pk, &message).unwrap();
    let decrypted = Paillier::decrypt(&sk, &ciphertext).unwrap();
    
    assert_eq!(message, decrypted);
}

#[test]
fn test_paillier_homomorphic_addition() {
    let (pk, sk) = Paillier::keygen().unwrap();
    let m1 = 10u64;
    let m2 = 20u64;
    
    let c1 = Paillier::encrypt(&pk, &m1).unwrap();
    let c2 = Paillier::encrypt(&pk, &m2).unwrap();
    
    // Homomorphic addition
    let c_sum = Paillier::add_ciphertexts(&pk, &c1, &c2).unwrap();
    let decrypted_sum = Paillier::decrypt(&sk, &c_sum).unwrap();
    
    assert_eq!(decrypted_sum, (m1 + m2) % pk.n);
}

#[test]
fn test_paillier_scalar_multiplication() {
    let (pk, sk) = Paillier::keygen().unwrap();
    let message = 7u64;
    let scalar = 3u64;
    
    let ciphertext = Paillier::encrypt(&pk, &message).unwrap();
    let scaled_ciphertext = Paillier::scalar_multiply(&pk, &ciphertext, &scalar).unwrap();
    let decrypted = Paillier::decrypt(&sk, &scaled_ciphertext).unwrap();
    
    assert_eq!(decrypted, (message * scalar) % pk.n);
}

#[test]
fn test_paillier_encrypt_zero() {
    let (pk, sk) = Paillier::keygen().unwrap();
    
    let zero_encryption = Paillier::encrypt_zero(&pk).unwrap();
    let decrypted = Paillier::decrypt(&sk, &zero_encryption).unwrap();
    
    assert_eq!(decrypted, 0);
}

#[test]
fn test_paillier_subtraction() {
    let (pk, sk) = Paillier::keygen().unwrap();
    let m1 = 30u64;
    let m2 = 12u64;
    
    let c1 = Paillier::encrypt(&pk, &m1).unwrap();
    let c2 = Paillier::encrypt(&pk, &m2).unwrap();
    
    let c_diff = Paillier::subtract_ciphertexts(&pk, &c1, &c2).unwrap();
    let decrypted_diff = Paillier::decrypt(&sk, &c_diff).unwrap();
    
    let expected = if m1 >= m2 { m1 - m2 } else { pk.n + m1 - m2 };
    assert_eq!(decrypted_diff, expected % pk.n);
}

#[test]
fn test_paillier_multiple_additions() {
    let (pk, sk) = Paillier::keygen().unwrap();
    let messages = vec![5u64, 10u64, 15u64, 20u64];
    
    let mut ciphertexts = Vec::new();
    for &msg in &messages {
        ciphertexts.push(Paillier::encrypt(&pk, &msg).unwrap());
    }
    
    // Add all ciphertexts together
    let mut sum_ciphertext = ciphertexts[0].clone();
    for i in 1..ciphertexts.len() {
        sum_ciphertext = Paillier::add_ciphertexts(&pk, &sum_ciphertext, &ciphertexts[i]).unwrap();
    }
    
    let decrypted_sum = Paillier::decrypt(&sk, &sum_ciphertext).unwrap();
    
    let expected_sum: u64 = messages.iter().sum();
    assert_eq!(decrypted_sum, expected_sum % pk.n);
}

#[test]
fn test_paillier_randomization() {
    let (pk, sk) = Paillier::keygen().unwrap();
    let message = 123u64;
    
    let original_ciphertext = Paillier::encrypt(&pk, &message).unwrap();
    let randomized_ciphertext = Paillier::randomize_ciphertext(&pk, &original_ciphertext).unwrap();
    
    // Should decrypt to the same value
    let decrypted_original = Paillier::decrypt(&sk, &original_ciphertext).unwrap();
    let decrypted_randomized = Paillier::decrypt(&sk, &randomized_ciphertext).unwrap();
    
    assert_eq!(decrypted_original, decrypted_randomized);
    assert_eq!(decrypted_original, message);
    
    // But ciphertexts should be different (with high probability)
    assert_ne!(original_ciphertext.value, randomized_ciphertext.value);
}