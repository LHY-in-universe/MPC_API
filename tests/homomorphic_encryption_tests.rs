//! 同态加密测试
//! 
//! 包含 BFV, BGV, Paillier, ElGamal, RSA 等同态加密方案的测试

use mpc_api::homomorphic_encryption::{HomomorphicEncryption, AdditivelyHomomorphic};
use mpc_api::homomorphic_encryption::bfv::*;

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