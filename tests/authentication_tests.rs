//! 认证模块测试
//! 
//! 包含 HMAC, CMAC, GMAC, Poly1305 等认证算法的测试

use mpc_api::authentication::{MessageAuthenticationCode, HMAC, HmacTag, HmacKey, CMAC, CmacTag, CmacKey, GMAC, GmacTag, GmacKey, Poly1305, Poly1305Tag, Poly1305Key};

// ===== HMAC Tests =====

#[test]
fn test_hmac_generate_key() {
    let key1 = HMAC::generate_key();
    let key2 = HMAC::generate_key();
    
    assert_ne!(key1.key, key2.key);
}

#[test]
fn test_hmac_authenticate_and_verify() {
    let key = HMAC::generate_key();
    let message = b"Hello, HMAC!".to_vec();
    
    let tag = HMAC::authenticate(&key, &message);
    let verification = HMAC::verify(&key, &message, &tag);
    
    assert!(verification);
}

#[test]
fn test_hmac_wrong_key() {
    let key1 = HMAC::generate_key();
    let key2 = HMAC::generate_key();
    let message = b"Hello, HMAC!".to_vec();
    
    let tag = HMAC::authenticate(&key1, &message);
    let verification = HMAC::verify(&key2, &message, &tag);
    
    assert!(!verification);
}

#[test]
fn test_hmac_wrong_message() {
    let key = HMAC::generate_key();
    let message1 = b"Hello, HMAC!".to_vec();
    let message2 = b"Hello, MAC!".to_vec();
    
    let tag = HMAC::authenticate(&key, &message1);
    let verification = HMAC::verify(&key, &message2, &tag);
    
    assert!(!verification);
}

#[test]
fn test_hmac_u64() {
    let key = HMAC::generate_key();
    let value = 12345u64;
    
    let tag_bytes = HMAC::compute_hmac_u64(&key.key, value);
    let tag = HmacTag { tag: tag_bytes };
    let verification = HMAC::verify_u64(&key, value, &tag);
    
    assert!(verification);
}

#[test]
fn test_hmac_batch_operations() {
    let key = HMAC::generate_key();
    let messages = vec![
        b"message1".to_vec(),
        b"message2".to_vec(),
        b"message3".to_vec(),
    ];
    
    let tags = HMAC::batch_authenticate(&key, &messages);
    assert_eq!(tags.len(), 3);
    
    let verification = HMAC::batch_verify(&key, &messages, &tags).unwrap();
    assert!(verification);
}

#[test]
fn test_hmac_authenticate_share() {
    let key = HMAC::generate_key();
    let share_value = 123u64;
    let share_index = 0usize;
    
    let tag = HMAC::authenticate_share(&key, share_value, share_index);
    let verification = HMAC::verify_share(&key, share_value, share_index, &tag);
    
    assert!(verification);
}

#[test]
fn test_hmac_key_derivation() {
    let master_key = b"master_secret_key";
    let info = b"application_context";
    let length = 32;
    
    let derived_key1 = HMAC::derive_key(master_key, info, length);
    let derived_key2 = HMAC::derive_key(master_key, info, length);
    
    assert_eq!(derived_key1, derived_key2);
    assert_eq!(derived_key1.len(), length);
}

#[test]
fn test_hmac_key_stretching() {
    let password = b"weak_password";
    let salt = b"random_salt";
    let iterations = 1000;
    
    let stretched_key1 = HMAC::stretch_key(password, salt, iterations);
    let stretched_key2 = HMAC::stretch_key(password, salt, iterations);
    
    assert_eq!(stretched_key1.key, stretched_key2.key);
    
    // Different salt should produce different key
    let different_salt = b"different_salt";
    let stretched_key3 = HMAC::stretch_key(password, different_salt, iterations);
    assert_ne!(stretched_key1.key, stretched_key3.key);
}

#[test]
fn test_hmac_secure_compare() {
    let a = [1, 2, 3, 4, 5];
    let b = [1, 2, 3, 4, 5];
    let c = [1, 2, 3, 4, 6];
    
    assert!(HMAC::secure_compare(&a, &b));
    assert!(!HMAC::secure_compare(&a, &c));
    assert!(!HMAC::secure_compare(&a, &[1, 2, 3, 4])); // Different lengths
}

#[test]
fn test_hmac_test_vectors() {
    // RFC 2202 test vectors (simplified)
    let key = b"Jefe";
    let message = b"what do ya want for nothing?";
    
    let tag = HMAC::compute_hmac(key, message);
    assert_eq!(tag.len(), 32);
    
    // The tag should be deterministic
    let tag2 = HMAC::compute_hmac(key, message);
    assert_eq!(tag, tag2);
}

// ===== CMAC Tests =====

#[test]
fn test_cmac_generate_key() {
    let key1 = CMAC::generate_key();
    let key2 = CMAC::generate_key();
    
    assert_ne!(key1.key, key2.key);
}

#[test]
fn test_cmac_authenticate_and_verify() {
    let key = CMAC::generate_key();
    let message = b"Hello, CMAC!".to_vec();
    
    let tag = CMAC::authenticate(&key, &message);
    let verification = CMAC::verify(&key, &message, &tag);
    
    assert!(verification);
}

#[test]
fn test_cmac_wrong_key() {
    let key1 = CMAC::generate_key();
    let key2 = CMAC::generate_key();
    let message = b"Hello, CMAC!".to_vec();
    
    let tag = CMAC::authenticate(&key1, &message);
    let verification = CMAC::verify(&key2, &message, &tag);
    
    assert!(!verification);
}

#[test]
fn test_cmac_wrong_message() {
    let key = CMAC::generate_key();
    let message1 = b"Hello, CMAC!".to_vec();
    let message2 = b"Hello, MAC!".to_vec();
    
    let tag = CMAC::authenticate(&key, &message1);
    let verification = CMAC::verify(&key, &message2, &tag);
    
    assert!(!verification);
}

#[test]
fn test_cmac_empty_message() {
    let key = CMAC::generate_key();
    let empty_message = Vec::new();
    
    let tag = CMAC::authenticate(&key, &empty_message);
    let verification = CMAC::verify(&key, &empty_message, &tag);
    
    assert!(verification);
}

#[test]
fn test_cmac_field_element() {
    let key = CMAC::generate_key();
    let value = 12345u64;
    
    let tag = CMAC::authenticate_field_element(&key, value);
    let verification = CMAC::verify_field_element(&key, value, &tag);
    
    assert!(verification);
}

#[test]
fn test_cmac_batch_operations() {
    let key = CMAC::generate_key();
    let messages = vec![
        b"message1".to_vec(),
        b"message2".to_vec(),
        b"message3".to_vec(),
    ];
    
    let tags = CMAC::batch_authenticate(&key, &messages);
    assert_eq!(tags.len(), 3);
    
    let verification = CMAC::batch_verify(&key, &messages, &tags).unwrap();
    assert!(verification);
}

#[test]
fn test_cmac_subkey_generation() {
    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    
    let (k1, k2) = CMAC::generate_subkeys(&key);
    
    // Subkeys should be different from the original key
    assert_ne!(k1, key);
    assert_ne!(k2, key);
    assert_ne!(k1, k2);
}

#[test]
fn test_cmac_left_shift() {
    let input = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    
    let shifted = CMAC::left_shift(&input);
    
    // MSB was 1, so result should have been XORed with 0x87
    assert_eq!(shifted[15], 0x87);
}

#[test]
fn test_cmac_incremental() {
    let key = CMAC::generate_key();
    let data1 = b"Hello, ";
    let data2 = b"CMAC ";
    let data3 = b"world!";
    
    let mut state = CMAC::start_incremental(&key.key);
    CMAC::incremental_update(&mut state, data1);
    CMAC::incremental_update(&mut state, data2);
    CMAC::incremental_update(&mut state, data3);
    let incremental_tag = CMAC::incremental_finalize(&state);
    
    // Compare with direct computation
    let mut combined = Vec::new();
    combined.extend_from_slice(data1);
    combined.extend_from_slice(data2);
    combined.extend_from_slice(data3);
    let direct_tag = CMAC::authenticate(&key, &combined);
    
    assert_eq!(incremental_tag.tag, direct_tag.tag);
}

#[test]
fn test_cmac_deterministic() {
    let key = CMAC::generate_key();
    let message = b"Test message for determinism".to_vec();
    
    let tag1 = CMAC::authenticate(&key, &message);
    let tag2 = CMAC::authenticate(&key, &message);
    
    assert_eq!(tag1.tag, tag2.tag);
}

#[test]
fn test_omac() {
    let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let message = b"Test OMAC";
    
    let tag = CMAC::compute_omac(&key, message);
    assert_eq!(tag.len(), 16); // CMAC_TAG_SIZE
}

#[test]
fn test_cmac_different_length_messages() {
    let key = CMAC::generate_key();
    
    // Test messages of different lengths
    let messages = vec![
        Vec::new(),                    // Empty
        b"a".to_vec(),                // 1 byte
        b"ab".to_vec(),               // 2 bytes
        b"abcdefghijklmnop".to_vec(), // Exactly one block (16 bytes)
        b"abcdefghijklmnopq".to_vec(),// One block + 1 byte
        b"The quick brown fox jumps over the lazy dog".to_vec(), // Multiple blocks
    ];
    
    for message in messages {
        let tag = CMAC::authenticate(&key, &message);
        let verification = CMAC::verify(&key, &message, &tag);
        assert!(verification, "Failed for message length: {}", message.len());
    }
}

// ===== GMAC Tests =====

#[test]
fn test_gmac_generate_key() {
    let key1 = GMAC::generate_key();
    let key2 = GMAC::generate_key();
    
    assert_ne!(key1.h, key2.h);
    assert_ne!(key1.k, key2.k);
}

#[test]
fn test_gmac_authenticate_and_verify() {
    let key = GMAC::generate_key();
    let message = b"Hello, GMAC!".to_vec();
    
    let tag = GMAC::authenticate(&key, &message);
    let verification = GMAC::verify(&key, &message, &tag);
    
    assert!(verification);
}

#[test]
fn test_gmac_wrong_key() {
    let key1 = GMAC::generate_key();
    let key2 = GMAC::generate_key();
    let message = b"Hello, GMAC!".to_vec();
    
    let tag = GMAC::authenticate(&key1, &message);
    let verification = GMAC::verify(&key2, &message, &tag);
    
    assert!(!verification);
}

#[test]
fn test_gmac_wrong_message() {
    let key = GMAC::generate_key();
    let message1 = b"Hello, GMAC!".to_vec();
    let message2 = b"Hello, MAC!".to_vec();
    
    let tag = GMAC::authenticate(&key, &message1);
    let verification = GMAC::verify(&key, &message2, &tag);
    
    assert!(!verification);
}

#[test]
fn test_gf128_multiplication() {
    let a = 0x123456789abcdef0fedcba9876543210u128;
    let b = 0xfedcba9876543210123456789abcdef0u128;
    
    let result = GMAC::gf128_mul(a, b);
    
    // Multiplication should be commutative
    let result2 = GMAC::gf128_mul(b, a);
    assert_eq!(result, result2);
    
    // Multiplication by 1 should be identity
    let identity = GMAC::gf128_mul(a, 1);
    assert_eq!(identity, a);
    
    // Multiplication by 0 should be 0
    let zero = GMAC::gf128_mul(a, 0);
    assert_eq!(zero, 0);
}

#[test]
fn test_gmac_field_element() {
    let key = GMAC::generate_key();
    let value = 12345u64;
    
    let tag = GMAC::authenticate_field_element(&key, value);
    let verification = GMAC::verify_field_element(&key, value, &tag);
    
    assert!(verification);
}

#[test]
fn test_gmac_batch_operations() {
    let key = GMAC::generate_key();
    let messages = vec![
        b"message1".to_vec(),
        b"message2".to_vec(),
        b"message3".to_vec(),
    ];
    
    let tags = GMAC::batch_authenticate(&key, &messages);
    assert_eq!(tags.len(), 3);
    
    let verification = GMAC::batch_verify(&key, &messages, &tags).unwrap();
    assert!(verification);
}

#[test]
fn test_gmac_incremental() {
    let key = GMAC::generate_key();
    let data1 = b"Hello, ";
    let data2 = b"GMAC ";
    let data3 = b"world!";
    
    let mut state = GMAC::start_incremental(&key.h);
    GMAC::incremental_update(&mut state, data1);
    GMAC::incremental_update(&mut state, data2);
    GMAC::incremental_update(&mut state, data3);
    let incremental_tag = GMAC::incremental_finalize(&state, &key.k);
    
    // Compare with direct computation
    let mut combined = Vec::new();
    combined.extend_from_slice(data1);
    combined.extend_from_slice(data2);
    combined.extend_from_slice(data3);
    let direct_tag = GMAC::authenticate(&key, &combined);
    
    assert_eq!(incremental_tag.tag, direct_tag.tag);
}

#[test]
fn test_ghash() {
    let h = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let data = b"Test data for GHASH";
    
    let hash1 = GMAC::ghash(&h, data);
    let hash2 = GMAC::ghash(&h, data);
    
    // Should be deterministic
    assert_eq!(hash1, hash2);
}

#[test]
fn test_gmac_polynomial_eval() {
    let h = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let blocks = vec![
        b"block1".to_vec(),
        b"block2".to_vec(),
        b"block3".to_vec(),
    ];
    
    let tag = GMAC::polynomial_eval(&h, &blocks);
    assert_eq!(tag.tag.len(), 16); // GMAC_TAG_SIZE
}

#[test]
fn test_gmac_empty_message() {
    let key = GMAC::generate_key();
    let empty_message = Vec::new();
    
    let tag = GMAC::authenticate(&key, &empty_message);
    let verification = GMAC::verify(&key, &empty_message, &tag);
    
    assert!(verification);
}

#[test]
fn test_bytes_to_gf128_conversion() {
    let bytes = [0xFF; 16];
    let gf_value = GMAC::bytes_to_gf128(&bytes);
    let converted_back = GMAC::gf128_to_bytes(gf_value);
    
    assert_eq!(bytes, converted_back);
}

// ===== Poly1305 Tests =====

#[test]
fn test_poly1305_generate_key() {
    let key1 = Poly1305::generate_key();
    let key2 = Poly1305::generate_key();
    
    assert_ne!(key1.r, key2.r);
    assert_ne!(key1.s, key2.s);
}

#[test]
fn test_poly1305_authenticate_and_verify() {
    let key = Poly1305::generate_key();
    let message = b"Hello, Poly1305!".to_vec();
    
    let tag = Poly1305::authenticate(&key, &message);
    let verification = Poly1305::verify(&key, &message, &tag);
    
    assert!(verification);
}

#[test]
fn test_poly1305_wrong_key() {
    let key1 = Poly1305::generate_key();
    let key2 = Poly1305::generate_key();
    let message = b"Hello, Poly1305!".to_vec();
    
    let tag = Poly1305::authenticate(&key1, &message);
    let verification = Poly1305::verify(&key2, &message, &tag);
    
    assert!(!verification);
}

#[test]
fn test_poly1305_wrong_message() {
    let key = Poly1305::generate_key();
    let message1 = b"Hello, Poly1305!".to_vec();
    let message2 = b"Hello, MAC!".to_vec();
    
    let tag = Poly1305::authenticate(&key, &message1);
    let verification = Poly1305::verify(&key, &message2, &tag);
    
    assert!(!verification);
}

#[test]
fn test_poly1305_field_element() {
    let key = Poly1305::generate_key();
    let value = 12345u64;
    
    let tag = Poly1305::authenticate_field_element(&key, value);
    let verification = Poly1305::verify_field_element(&key, value, &tag);
    
    assert!(verification);
}

#[test]
fn test_poly1305_batch_operations() {
    let key = Poly1305::generate_key();
    let messages = vec![
        b"message1".to_vec(),
        b"message2".to_vec(),
        b"message3".to_vec(),
    ];
    
    let tags = Poly1305::batch_authenticate(&key, &messages);
    assert_eq!(tags.len(), 3);
    
    let verification = Poly1305::batch_verify(&key, &messages, &tags).unwrap();
    assert!(verification);
}

#[test]
fn test_poly1305_incremental() {
    let key = Poly1305::generate_key();
    let chunks = vec![
        b"chunk1".to_vec(),
        b"chunk2".to_vec(),
        b"chunk3".to_vec(),
    ];
    
    let incremental_tag = Poly1305::incremental_authenticate(&key, &chunks);
    
    // Verify against concatenated message
    let mut combined = Vec::new();
    for chunk in &chunks {
        combined.extend_from_slice(chunk);
    }
    let direct_tag = Poly1305::authenticate(&key, &combined);
    
    assert_eq!(incremental_tag.tag, direct_tag.tag);
}

#[test]
fn test_poly1305_one_time_key() {
    let master_key = b"0123456789abcdef0123456789abcdef";
    let nonce = b"nonce1234567890";
    
    let key1 = Poly1305::generate_one_time_key(master_key, nonce).unwrap();
    let key2 = Poly1305::generate_one_time_key(master_key, nonce).unwrap();
    
    // Same master key and nonce should produce same one-time key
    assert_eq!(key1.r, key2.r);
    assert_eq!(key1.s, key2.s);
    
    // Different nonce should produce different key
    let different_nonce = b"different_nonce!";
    let key3 = Poly1305::generate_one_time_key(master_key, different_nonce).unwrap();
    assert_ne!(key1.r, key3.r);
}

#[test]
fn test_poly1305_authenticated_encryption() {
    let key = Poly1305::generate_key();
    let plaintext = b"Secret message";
    let additional_data = b"public_header";
    
    let (ciphertext, tag) = Poly1305::authenticated_encrypt(&key, plaintext, additional_data);
    
    assert_ne!(ciphertext, plaintext.to_vec());
    
    let decrypted = Poly1305::authenticated_decrypt(&key, &ciphertext, additional_data, &tag).unwrap();
    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn test_poly1305_authenticated_decryption_failure() {
    let key = Poly1305::generate_key();
    let plaintext = b"Secret message";
    let additional_data = b"public_header";
    let wrong_additional_data = b"wrong_header";
    
    let (ciphertext, tag) = Poly1305::authenticated_encrypt(&key, plaintext, additional_data);
    
    // Should fail with wrong additional data
    let result = Poly1305::authenticated_decrypt(&key, &ciphertext, wrong_additional_data, &tag);
    assert!(result.is_err());
}

#[test]
fn test_poly1305_empty_message() {
    let key = Poly1305::generate_key();
    let empty_message = Vec::new();
    
    let tag = Poly1305::authenticate(&key, &empty_message);
    let verification = Poly1305::verify(&key, &empty_message, &tag);
    
    assert!(verification);
}

#[test]
fn test_poly1305_large_message() {
    let key = Poly1305::generate_key();
    let large_message = vec![0u8; 1000]; // 1KB message
    
    let tag = Poly1305::authenticate(&key, &large_message);
    let verification = Poly1305::verify(&key, &large_message, &tag);
    
    assert!(verification);
}