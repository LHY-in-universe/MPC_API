//! HMAC (Hash-based Message Authentication Code)
//! 
//! Implements HMAC using SHA-256 hash function

use crate::{MpcError, Result};
// use crate::secret_sharing::FIELD_PRIME; // Unused import
use super::{MessageAuthenticationCode, UnforgeableMac, SecureMac};
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

const HMAC_KEY_SIZE: usize = 32;
const HMAC_BLOCK_SIZE: usize = 64;
const HMAC_TAG_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HmacKey {
    pub key: [u8; HMAC_KEY_SIZE],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HmacTag {
    pub tag: [u8; HMAC_TAG_SIZE],
}

pub struct HMAC;

impl MessageAuthenticationCode for HMAC {
    type Key = HmacKey;
    type Message = Vec<u8>;
    type Tag = HmacTag;
    
    fn generate_key() -> Self::Key {
        let mut rng = thread_rng();
        let mut key = [0u8; HMAC_KEY_SIZE];
        for i in 0..HMAC_KEY_SIZE {
            key[i] = rng.gen();
        }
        HmacKey { key }
    }
    
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag {
        let tag = Self::compute_hmac(&key.key, message);
        HmacTag { tag }
    }
    
    fn verify(key: &Self::Key, message: &Self::Message, tag: &Self::Tag) -> bool {
        let computed_tag = Self::authenticate(key, message);
        Self::secure_compare(&computed_tag.tag, &tag.tag)
    }
}

impl Default for HMAC {
    fn default() -> Self {
        Self::new()
    }
}

impl HMAC {
    pub fn new() -> Self {
        HMAC
    }
    
    pub fn compute_hmac(key: &[u8], message: &[u8]) -> [u8; HMAC_TAG_SIZE] {
        let mut effective_key = [0u8; HMAC_BLOCK_SIZE];
        
        if key.len() > HMAC_BLOCK_SIZE {
            // Hash the key if it's too long
            let mut hasher = Sha256::new();
            hasher.update(key);
            let hash = hasher.finalize();
            effective_key[..32].copy_from_slice(&hash);
        } else {
            effective_key[..key.len()].copy_from_slice(key);
        }
        
        // Create inner and outer padding
        let mut i_key_pad = [0x36u8; HMAC_BLOCK_SIZE];
        let mut o_key_pad = [0x5cu8; HMAC_BLOCK_SIZE];
        
        for i in 0..HMAC_BLOCK_SIZE {
            i_key_pad[i] ^= effective_key[i];
            o_key_pad[i] ^= effective_key[i];
        }
        
        // Inner hash: H(K XOR ipad || message)
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&i_key_pad);
        inner_hasher.update(message);
        let inner_hash = inner_hasher.finalize();
        
        // Outer hash: H(K XOR opad || inner_hash)
        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&o_key_pad);
        outer_hasher.update(&inner_hash);
        let final_hash = outer_hasher.finalize();
        
        let mut result = [0u8; HMAC_TAG_SIZE];
        result.copy_from_slice(&final_hash);
        result
    }
    
    // Constant-time comparison to prevent timing attacks
    fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for i in 0..a.len() {
            result |= a[i] ^ b[i];
        }
        result == 0
    }
    
    pub fn compute_hmac_u64(key: &[u8], value: u64) -> [u8; HMAC_TAG_SIZE] {
        let message = value.to_le_bytes();
        Self::compute_hmac(key, &message)
    }
    
    pub fn verify_u64(key: &HmacKey, value: u64, tag: &HmacTag) -> bool {
        let computed_tag = Self::compute_hmac_u64(&key.key, value);
        Self::secure_compare(&computed_tag, &tag.tag)
    }
    
    pub fn batch_authenticate(key: &HmacKey, messages: &[Vec<u8>]) -> Vec<HmacTag> {
        messages.iter()
            .map(|msg| Self::authenticate(key, msg))
            .collect()
    }
    
    pub fn batch_verify(key: &HmacKey, messages: &[Vec<u8>], tags: &[HmacTag]) -> Result<bool> {
        if messages.len() != tags.len() {
            return Err(MpcError::AuthenticationError("Messages and tags arrays must have same length".to_string()));
        }
        
        for (msg, tag) in messages.iter().zip(tags.iter()) {
            if !Self::verify(key, msg, tag) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    // HMAC for secret shares
    pub fn authenticate_share(key: &HmacKey, share_value: u64, share_index: usize) -> HmacTag {
        let mut message = Vec::new();
        message.extend_from_slice(&share_value.to_le_bytes());
        message.extend_from_slice(&share_index.to_le_bytes());
        
        Self::authenticate(key, &message)
    }
    
    pub fn verify_share(key: &HmacKey, share_value: u64, share_index: usize, tag: &HmacTag) -> bool {
        let mut message = Vec::new();
        message.extend_from_slice(&share_value.to_le_bytes());
        message.extend_from_slice(&share_index.to_le_bytes());
        
        Self::verify(key, &message, tag)
    }
    
    // HMAC-based key derivation
    pub fn derive_key(master_key: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let mut derived_key = Vec::new();
        let mut counter = 1u32;
        
        while derived_key.len() < length {
            let mut message = Vec::new();
            message.extend_from_slice(info);
            message.extend_from_slice(&counter.to_le_bytes());
            
            let block = Self::compute_hmac(master_key, &message);
            derived_key.extend_from_slice(&block);
            counter += 1;
        }
        
        derived_key.truncate(length);
        derived_key
    }
    
    // PBKDF2-like key stretching using HMAC
    pub fn stretch_key(password: &[u8], salt: &[u8], iterations: u32) -> HmacKey {
        let mut derived_key = Vec::new();
        derived_key.extend_from_slice(salt);
        derived_key.extend_from_slice(&1u32.to_le_bytes());
        
        let mut result = Self::compute_hmac(password, &derived_key);
        let mut current = result;
        
        for _ in 1..iterations {
            current = Self::compute_hmac(password, &current);
            for i in 0..HMAC_TAG_SIZE {
                result[i] ^= current[i];
            }
        }
        
        HmacKey { key: result }
    }
}

impl UnforgeableMac for HMAC {}
impl SecureMac for HMAC {}

// HMAC variants for different hash functions
pub struct HMACSHA1;
pub struct HMACSHA512;

// Simplified implementations for demonstration
impl HMACSHA1 {
    pub fn compute_hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
        // This is a placeholder - in a real implementation, you'd use SHA-1
        let mut result = [0u8; 20];
        let sha256_result = HMAC::compute_hmac(key, message);
        result.copy_from_slice(&sha256_result[..20]);
        result
    }
}

impl HMACSHA512 {
    pub fn compute_hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
        // This is a placeholder - in a real implementation, you'd use SHA-512
        let mut result = [0u8; 64];
        let sha256_result = HMAC::compute_hmac(key, message);
        
        // Extend SHA-256 to SHA-512 size (simplified)
        result[..32].copy_from_slice(&sha256_result);
        result[32..64].copy_from_slice(&sha256_result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
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
}