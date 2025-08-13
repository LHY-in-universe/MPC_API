//! Poly1305 Message Authentication Code
//! 
//! Implements the Poly1305 MAC algorithm using finite field arithmetic

use crate::{MpcError, Result};
use crate::secret_sharing::FIELD_PRIME;
use super::{MessageAuthenticationCode, MacTag, UnforgeableMac, SecureMac};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

const POLY1305_KEY_SIZE: usize = 32;
const POLY1305_TAG_SIZE: usize = 16;
const POLY1305_BLOCK_SIZE: usize = 16;

// Poly1305 uses the prime 2^130 - 5, but we'll use a simplified version with our field
const POLY1305_PRIME: u128 = (1u128 << 127) - 1; // Simplified prime for demonstration

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Poly1305Key {
    pub r: [u8; 16], // Random key component
    pub s: [u8; 16], // Secret key component
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Poly1305Tag {
    pub tag: [u8; POLY1305_TAG_SIZE],
}

pub struct Poly1305;

impl MessageAuthenticationCode for Poly1305 {
    type Key = Poly1305Key;
    type Message = Vec<u8>;
    type Tag = Poly1305Tag;
    
    fn generate_key() -> Self::Key {
        let mut rng = thread_rng();
        let mut r = [0u8; 16];
        let mut s = [0u8; 16];
        
        for i in 0..16 {
            r[i] = rng.gen();
            s[i] = rng.gen();
        }
        
        // Clamp r according to Poly1305 specification (simplified)
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;
        
        Poly1305Key { r, s }
    }
    
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag {
        let tag = Self::compute_poly1305(&key.r, &key.s, message);
        Poly1305Tag { tag }
    }
    
    fn verify(key: &Self::Key, message: &Self::Message, tag: &Self::Tag) -> bool {
        let computed_tag = Self::authenticate(key, message);
        Self::secure_compare(&computed_tag.tag, &tag.tag)
    }
}

impl Poly1305 {
    pub fn new() -> Self {
        Poly1305
    }
    
    // Simplified Poly1305 computation
    pub fn compute_poly1305(r: &[u8; 16], s: &[u8; 16], message: &[u8]) -> [u8; POLY1305_TAG_SIZE] {
        let r_value = Self::bytes_to_u128(r);
        let s_value = Self::bytes_to_u128(s);
        
        let mut accumulator = 0u128;
        
        // Process message in 16-byte blocks
        for chunk in message.chunks(POLY1305_BLOCK_SIZE) {
            let mut block = [0u8; 17]; // 16 bytes + 1 for padding
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 1; // Add padding bit
            
            let block_value = Self::bytes_to_u128(&block[..16]);
            
            // Add to accumulator and multiply by r
            accumulator = ((accumulator + block_value) % POLY1305_PRIME * r_value) % POLY1305_PRIME;
        }
        
        // Add s and reduce to get final tag  
        let final_value = (accumulator + s_value) % (u128::MAX);
        Self::u128_to_bytes(final_value)
    }
    
    fn bytes_to_u128(bytes: &[u8]) -> u128 {
        let mut result = 0u128;
        for (i, &byte) in bytes.iter().take(16).enumerate() {
            result |= (byte as u128) << (i * 8);
        }
        result
    }
    
    fn u128_to_bytes(value: u128) -> [u8; POLY1305_TAG_SIZE] {
        let mut bytes = [0u8; POLY1305_TAG_SIZE];
        for i in 0..POLY1305_TAG_SIZE {
            bytes[i] = (value >> (i * 8)) as u8;
        }
        bytes
    }
    
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
    
    // Poly1305 for field elements
    pub fn authenticate_field_element(key: &Poly1305Key, value: u64) -> Poly1305Tag {
        let message = value.to_le_bytes().to_vec();
        Self::authenticate(key, &message)
    }
    
    pub fn verify_field_element(key: &Poly1305Key, value: u64, tag: &Poly1305Tag) -> bool {
        let message = value.to_le_bytes().to_vec();
        Self::verify(key, &message, tag)
    }
    
    // Batch authentication
    pub fn batch_authenticate(key: &Poly1305Key, messages: &[Vec<u8>]) -> Vec<Poly1305Tag> {
        messages.iter()
            .map(|msg| Self::authenticate(key, msg))
            .collect()
    }
    
    pub fn batch_verify(key: &Poly1305Key, messages: &[Vec<u8>], tags: &[Poly1305Tag]) -> Result<bool> {
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
    
    // Incremental authentication for streaming data
    pub fn incremental_authenticate(key: &Poly1305Key, chunks: &[Vec<u8>]) -> Poly1305Tag {
        let mut combined_message = Vec::new();
        for chunk in chunks {
            combined_message.extend_from_slice(chunk);
        }
        Self::authenticate(key, &combined_message)
    }
    
    // One-time key generation for Poly1305
    pub fn generate_one_time_key(master_key: &[u8], nonce: &[u8]) -> Result<Poly1305Key> {
        if nonce.len() != 16 {
            return Err(MpcError::AuthenticationError("Nonce must be 16 bytes".to_string()));
        }
        
        // In practice, you'd use ChaCha20 or similar to generate the one-time key
        // This is a simplified version using XOR with master key
        let mut r = [0u8; 16];
        let mut s = [0u8; 16];
        
        for i in 0..16 {
            r[i] = master_key.get(i).unwrap_or(&0) ^ nonce[i];
            s[i] = master_key.get(i + 16).unwrap_or(&0) ^ nonce[i];
        }
        
        // Apply clamping to r
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;
        
        Ok(Poly1305Key { r, s })
    }
    
    // Authenticated encryption using Poly1305 (simplified)
    pub fn authenticated_encrypt(
        key: &Poly1305Key, 
        plaintext: &[u8], 
        additional_data: &[u8]
    ) -> (Vec<u8>, Poly1305Tag) {
        // In practice, you'd use ChaCha20-Poly1305 or similar
        // This is a simplified version that just XORs with key
        let mut ciphertext = Vec::new();
        let key_stream = Self::generate_key_stream(&key.r, plaintext.len());
        
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ key_stream[i % key_stream.len()]);
        }
        
        // Authenticate ciphertext + additional data
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&ciphertext);
        auth_data.extend_from_slice(additional_data);
        
        let tag = Self::authenticate(key, &auth_data);
        
        (ciphertext, tag)
    }
    
    pub fn authenticated_decrypt(
        key: &Poly1305Key,
        ciphertext: &[u8],
        additional_data: &[u8],
        tag: &Poly1305Tag,
    ) -> Result<Vec<u8>> {
        // Verify authentication tag first
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(ciphertext);
        auth_data.extend_from_slice(additional_data);
        
        if !Self::verify(key, &auth_data, tag) {
            return Err(MpcError::AuthenticationError("Authentication failed".to_string()));
        }
        
        // Decrypt (XOR with same key stream)
        let mut plaintext = Vec::new();
        let key_stream = Self::generate_key_stream(&key.r, ciphertext.len());
        
        for (i, &byte) in ciphertext.iter().enumerate() {
            plaintext.push(byte ^ key_stream[i % key_stream.len()]);
        }
        
        Ok(plaintext)
    }
    
    fn generate_key_stream(key: &[u8; 16], length: usize) -> Vec<u8> {
        // Simplified key stream generation (in practice, use ChaCha20)
        let mut stream = Vec::new();
        let key_value = Self::bytes_to_u128(key);
        
        for i in 0..length {
            let byte_val = ((key_value.wrapping_mul(i as u128 + 1)) >> (i % 64)) as u8;
            stream.push(byte_val);
        }
        
        stream
    }
}

impl UnforgeableMac for Poly1305 {}
impl SecureMac for Poly1305 {}

#[cfg(test)]
mod tests {
    use super::*;
    
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
}