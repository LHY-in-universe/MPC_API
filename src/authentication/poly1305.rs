//! Poly1305 Message Authentication Code
//! 
//! Implements the Poly1305 MAC algorithm using finite field arithmetic

use crate::{MpcError, Result};
// use crate::secret_sharing::FIELD_PRIME; // Unused import
use super::{MessageAuthenticationCode, UnforgeableMac, SecureMac};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

const _POLY1305_KEY_SIZE: usize = 32; // Prefix with underscore to avoid unused warning
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

impl Default for Poly1305 {
    fn default() -> Self {
        Self::new()
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
            
            // Add to accumulator and multiply by r (avoid overflow)
            accumulator = (accumulator + block_value) % POLY1305_PRIME;
            accumulator = (accumulator as u128).wrapping_mul(r_value as u128) % POLY1305_PRIME;
        }
        
        // Add s and reduce to get final tag (avoid overflow)
        let final_value = accumulator.wrapping_add(s_value) % (u128::MAX);
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

// Tests moved to tests/authentication_tests.rs