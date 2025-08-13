//! GMAC (Galois Message Authentication Code)
//! 
//! Implements GMAC using Galois field arithmetic

use crate::{MpcError, Result};
use super::{MessageAuthenticationCode, UnforgeableMac, SecureMac};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

const GMAC_KEY_SIZE: usize = 16;
const GMAC_TAG_SIZE: usize = 16;
const GMAC_BLOCK_SIZE: usize = 16;

// GF(2^128) irreducible polynomial: x^128 + x^7 + x^2 + x + 1
const GF128_POLYNOMIAL: u128 = 0x87;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GmacKey {
    pub h: [u8; GMAC_KEY_SIZE], // Authentication subkey
    pub k: [u8; GMAC_KEY_SIZE], // Encryption key for final step
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GmacTag {
    pub tag: [u8; GMAC_TAG_SIZE],
}

pub struct GMAC;

// Incremental GMAC computation state
pub struct IncrementalGMAC {
    h: u128,
    y: u128,
    buffer: Vec<u8>,
}

impl MessageAuthenticationCode for GMAC {
    type Key = GmacKey;
    type Message = Vec<u8>;
    type Tag = GmacTag;
    
    fn generate_key() -> Self::Key {
        let mut rng = thread_rng();
        let mut h = [0u8; GMAC_KEY_SIZE];
        let mut k = [0u8; GMAC_KEY_SIZE];
        
        for i in 0..GMAC_KEY_SIZE {
            h[i] = rng.gen();
            k[i] = rng.gen();
        }
        
        GmacKey { h, k }
    }
    
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag {
        let tag = Self::compute_gmac(&key.h, &key.k, message);
        GmacTag { tag }
    }
    
    fn verify(key: &Self::Key, message: &Self::Message, tag: &Self::Tag) -> bool {
        let computed_tag = Self::authenticate(key, message);
        Self::secure_compare(&computed_tag.tag, &tag.tag)
    }
}

impl Default for GMAC {
    fn default() -> Self {
        Self::new()
    }
}

impl GMAC {
    pub fn new() -> Self {
        GMAC
    }
    
    // Compute GMAC tag
    pub fn compute_gmac(h: &[u8; GMAC_KEY_SIZE], k: &[u8; GMAC_KEY_SIZE], message: &[u8]) -> [u8; GMAC_TAG_SIZE] {
        let h_value = Self::bytes_to_gf128(h);
        
        let mut y = 0u128;
        
        // Process message in 16-byte blocks
        for chunk in message.chunks(GMAC_BLOCK_SIZE) {
            let mut block = [0u8; GMAC_BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            
            let x = Self::bytes_to_gf128(&block);
            y = Self::gf128_mul(y ^ x, h_value);
        }
        
        // Apply final encryption with key k (simplified)
        let k_value = Self::bytes_to_gf128(k);
        let final_tag = y ^ k_value;
        
        Self::gf128_to_bytes(final_tag)
    }
    
    // Convert bytes to GF(2^128) element
    fn bytes_to_gf128(bytes: &[u8]) -> u128 {
        let mut result = 0u128;
        for (i, &byte) in bytes.iter().enumerate().take(16) {
            result |= (byte as u128) << ((15 - i) * 8);
        }
        result
    }
    
    // Convert GF(2^128) element to bytes
    fn gf128_to_bytes(value: u128) -> [u8; GMAC_TAG_SIZE] {
        let mut bytes = [0u8; GMAC_TAG_SIZE];
        for i in 0..GMAC_TAG_SIZE {
            bytes[i] = (value >> ((15 - i) * 8)) as u8;
        }
        bytes
    }
    
    // Multiplication in GF(2^128)
    fn gf128_mul(a: u128, b: u128) -> u128 {
        let mut result = 0u128;
        let mut temp_a = a;
        let mut temp_b = b;
        
        for _ in 0..128 {
            if temp_b & 1 != 0 {
                result ^= temp_a;
            }
            
            let overflow = temp_a & (1u128 << 127) != 0;
            temp_a <<= 1;
            
            if overflow {
                temp_a ^= GF128_POLYNOMIAL;
            }
            
            temp_b >>= 1;
            
            if temp_b == 0 {
                break;
            }
        }
        
        result
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
    
    // GMAC for field elements
    pub fn authenticate_field_element(key: &GmacKey, value: u64) -> GmacTag {
        let message = value.to_le_bytes().to_vec();
        Self::authenticate(key, &message)
    }
    
    pub fn verify_field_element(key: &GmacKey, value: u64, tag: &GmacTag) -> bool {
        let message = value.to_le_bytes().to_vec();
        Self::verify(key, &message, tag)
    }
    
    // Batch authentication
    pub fn batch_authenticate(key: &GmacKey, messages: &[Vec<u8>]) -> Vec<GmacTag> {
        messages.iter()
            .map(|msg| Self::authenticate(key, msg))
            .collect()
    }
    
    pub fn batch_verify(key: &GmacKey, messages: &[Vec<u8>], tags: &[GmacTag]) -> Result<bool> {
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
    
    pub fn start_incremental(h: &[u8; GMAC_KEY_SIZE]) -> IncrementalGMAC {
        IncrementalGMAC {
            h: Self::bytes_to_gf128(h),
            y: 0,
            buffer: Vec::new(),
        }
    }
}

impl GMAC {
    pub fn incremental_update(state: &mut IncrementalGMAC, data: &[u8]) {
        state.buffer.extend_from_slice(data);
        
        while state.buffer.len() >= GMAC_BLOCK_SIZE {
            let mut block = [0u8; GMAC_BLOCK_SIZE];
            block.copy_from_slice(&state.buffer[..GMAC_BLOCK_SIZE]);
            state.buffer.drain(..GMAC_BLOCK_SIZE);
            
            let x = Self::bytes_to_gf128(&block);
            state.y = Self::gf128_mul(state.y ^ x, state.h);
        }
    }
    
    pub fn incremental_finalize(state: &IncrementalGMAC, k: &[u8; GMAC_KEY_SIZE]) -> GmacTag {
        let mut final_y = state.y;
        
        // Process remaining buffer
        if !state.buffer.is_empty() {
            let mut block = [0u8; GMAC_BLOCK_SIZE];
            block[..state.buffer.len()].copy_from_slice(&state.buffer);
            
            let x = Self::bytes_to_gf128(&block);
            final_y = Self::gf128_mul(final_y ^ x, state.h);
        }
        
        // Apply final key
        let k_value = Self::bytes_to_gf128(k);
        let final_tag = final_y ^ k_value;
        
        GmacTag { tag: Self::gf128_to_bytes(final_tag) }
    }
    
    // GHASH (the core of GMAC without final encryption)
    pub fn ghash(h: &[u8; GMAC_KEY_SIZE], data: &[u8]) -> [u8; GMAC_TAG_SIZE] {
        let h_value = Self::bytes_to_gf128(h);
        let mut y = 0u128;
        
        for chunk in data.chunks(GMAC_BLOCK_SIZE) {
            let mut block = [0u8; GMAC_BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            
            let x = Self::bytes_to_gf128(&block);
            y = Self::gf128_mul(y ^ x, h_value);
        }
        
        Self::gf128_to_bytes(y)
    }
    
    // Polynomial evaluation for multiple data blocks
    pub fn polynomial_eval(h: &[u8; GMAC_KEY_SIZE], blocks: &[Vec<u8>]) -> GmacTag {
        let h_value = Self::bytes_to_gf128(h);
        let mut result = 0u128;
        let mut h_power = 1u128;
        
        for block_data in blocks.iter() {
            for chunk in block_data.chunks(GMAC_BLOCK_SIZE) {
                let mut block = [0u8; GMAC_BLOCK_SIZE];
                block[..chunk.len()].copy_from_slice(chunk);
                
                let x = Self::bytes_to_gf128(&block);
                result ^= Self::gf128_mul(x, h_power);
                h_power = Self::gf128_mul(h_power, h_value);
            }
        }
        
        GmacTag { tag: Self::gf128_to_bytes(result) }
    }
}

impl UnforgeableMac for GMAC {}
impl SecureMac for GMAC {}

#[cfg(test)]
mod tests {
    use super::*;
    
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
        assert_eq!(tag.tag.len(), GMAC_TAG_SIZE);
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
}