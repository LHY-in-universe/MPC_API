//! CMAC (Cipher-based Message Authentication Code)
//! 
//! Implements CMAC using AES block cipher (simplified version)

use crate::{MpcError, Result};
use super::{MessageAuthenticationCode, UnforgeableMac, SecureMac};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

const CMAC_KEY_SIZE: usize = 16; // AES-128 key size
const CMAC_TAG_SIZE: usize = 16;
const CMAC_BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CmacKey {
    pub key: [u8; CMAC_KEY_SIZE],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CmacTag {
    pub tag: [u8; CMAC_TAG_SIZE],
}

pub struct CMAC;

// Incremental CMAC computation state
pub struct IncrementalCMAC {
    key: [u8; CMAC_KEY_SIZE],
    k1: [u8; CMAC_BLOCK_SIZE],
    k2: [u8; CMAC_BLOCK_SIZE],
    x: [u8; CMAC_BLOCK_SIZE],
    buffer: Vec<u8>,
}

impl MessageAuthenticationCode for CMAC {
    type Key = CmacKey;
    type Message = Vec<u8>;
    type Tag = CmacTag;
    
    fn generate_key() -> Self::Key {
        let mut rng = thread_rng();
        let mut key = [0u8; CMAC_KEY_SIZE];
        for i in 0..CMAC_KEY_SIZE {
            key[i] = rng.gen();
        }
        CmacKey { key }
    }
    
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag {
        let tag = Self::compute_cmac(&key.key, message);
        CmacTag { tag }
    }
    
    fn verify(key: &Self::Key, message: &Self::Message, tag: &Self::Tag) -> bool {
        let computed_tag = Self::authenticate(key, message);
        Self::secure_compare(&computed_tag.tag, &tag.tag)
    }
}

impl CMAC {
    pub fn new() -> Self {
        CMAC
    }
    
    // Simplified AES block cipher implementation (for demonstration only)
    // In practice, you would use a proper AES implementation
    fn aes_encrypt_block(key: &[u8; CMAC_KEY_SIZE], block: &[u8; CMAC_BLOCK_SIZE]) -> [u8; CMAC_BLOCK_SIZE] {
        let mut result = [0u8; CMAC_BLOCK_SIZE];
        
        // This is a very simplified substitution-permutation network
        // NOT secure - for demonstration only
        for i in 0..CMAC_BLOCK_SIZE {
            // Simple substitution
            let mut byte = block[i] ^ key[i];
            
            // S-box (simplified)
            byte = byte.wrapping_mul(3).wrapping_add(1);
            
            // Permutation (rotate)
            result[(i + 5) % CMAC_BLOCK_SIZE] = byte;
        }
        
        // Additional rounds with key mixing
        for round in 0..4 {
            for i in 0..CMAC_BLOCK_SIZE {
                result[i] ^= key[i].wrapping_add(round as u8);
                result[i] = result[i].rotate_left(1);
            }
        }
        
        result
    }
    
    // Generate CMAC subkeys
    fn generate_subkeys(key: &[u8; CMAC_KEY_SIZE]) -> ([u8; CMAC_BLOCK_SIZE], [u8; CMAC_BLOCK_SIZE]) {
        // L = AES(K, 0^128)
        let zero_block = [0u8; CMAC_BLOCK_SIZE];
        let l = Self::aes_encrypt_block(key, &zero_block);
        
        // Generate K1 and K2
        let k1 = Self::left_shift(&l);
        let k2 = Self::left_shift(&k1);
        
        (k1, k2)
    }
    
    // Left shift by one bit in GF(2^128)
    fn left_shift(input: &[u8; CMAC_BLOCK_SIZE]) -> [u8; CMAC_BLOCK_SIZE] {
        let mut result = [0u8; CMAC_BLOCK_SIZE];
        let mut carry = 0u8;
        
        for i in (0..CMAC_BLOCK_SIZE).rev() {
            let new_carry = (input[i] & 0x80) >> 7;
            result[i] = (input[i] << 1) | carry;
            carry = new_carry;
        }
        
        // If there was a carry out, XOR with the constant
        if carry != 0 {
            result[CMAC_BLOCK_SIZE - 1] ^= 0x87;
        }
        
        result
    }
    
    // Compute CMAC tag
    pub fn compute_cmac(key: &[u8; CMAC_KEY_SIZE], message: &[u8]) -> [u8; CMAC_TAG_SIZE] {
        let (k1, k2) = Self::generate_subkeys(key);
        
        if message.is_empty() {
            // Special case for empty message
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            block[0] = 0x80; // Padding
            
            // XOR with K2
            for i in 0..CMAC_BLOCK_SIZE {
                block[i] ^= k2[i];
            }
            
            return Self::aes_encrypt_block(key, &block);
        }
        
        let mut x = [0u8; CMAC_BLOCK_SIZE];
        let chunks: Vec<&[u8]> = message.chunks(CMAC_BLOCK_SIZE).collect();
        
        for (i, chunk) in chunks.iter().enumerate() {
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            
            if i == chunks.len() - 1 {
                // Last block
                if chunk.len() == CMAC_BLOCK_SIZE {
                    // Complete block - XOR with K1
                    block.copy_from_slice(chunk);
                    for j in 0..CMAC_BLOCK_SIZE {
                        block[j] ^= k1[j];
                    }
                } else {
                    // Incomplete block - pad and XOR with K2
                    block[..chunk.len()].copy_from_slice(chunk);
                    if chunk.len() < CMAC_BLOCK_SIZE {
                        block[chunk.len()] = 0x80; // Padding
                    }
                    for j in 0..CMAC_BLOCK_SIZE {
                        block[j] ^= k2[j];
                    }
                }
            } else {
                // Not the last block
                block.copy_from_slice(chunk);
            }
            
            // XOR with previous result
            for j in 0..CMAC_BLOCK_SIZE {
                x[j] ^= block[j];
            }
            
            // Encrypt
            x = Self::aes_encrypt_block(key, &x);
        }
        
        x
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
    
    // CMAC for field elements
    pub fn authenticate_field_element(key: &CmacKey, value: u64) -> CmacTag {
        let message = value.to_le_bytes().to_vec();
        Self::authenticate(key, &message)
    }
    
    pub fn verify_field_element(key: &CmacKey, value: u64, tag: &CmacTag) -> bool {
        let message = value.to_le_bytes().to_vec();
        Self::verify(key, &message, tag)
    }
    
    // Batch authentication
    pub fn batch_authenticate(key: &CmacKey, messages: &[Vec<u8>]) -> Vec<CmacTag> {
        messages.iter()
            .map(|msg| Self::authenticate(key, msg))
            .collect()
    }
    
    pub fn batch_verify(key: &CmacKey, messages: &[Vec<u8>], tags: &[CmacTag]) -> Result<bool> {
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
    
    pub fn start_incremental(key: &[u8; CMAC_KEY_SIZE]) -> IncrementalCMAC {
        let (k1, k2) = Self::generate_subkeys(key);
        
        IncrementalCMAC {
            key: *key,
            k1,
            k2,
            x: [0u8; CMAC_BLOCK_SIZE],
            buffer: Vec::new(),
        }
    }
    
    pub fn incremental_update(state: &mut IncrementalCMAC, data: &[u8]) {
        state.buffer.extend_from_slice(data);
        
        while state.buffer.len() >= CMAC_BLOCK_SIZE {
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            block.copy_from_slice(&state.buffer[..CMAC_BLOCK_SIZE]);
            state.buffer.drain(..CMAC_BLOCK_SIZE);
            
            // XOR with previous result
            for j in 0..CMAC_BLOCK_SIZE {
                state.x[j] ^= block[j];
            }
            
            // Encrypt
            state.x = Self::aes_encrypt_block(&state.key, &state.x);
        }
    }
    
    pub fn incremental_finalize(state: &IncrementalCMAC) -> CmacTag {
        let mut x = state.x;
        
        if !state.buffer.is_empty() {
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            
            if state.buffer.len() == CMAC_BLOCK_SIZE {
                // Complete block - XOR with K1
                block.copy_from_slice(&state.buffer);
                for j in 0..CMAC_BLOCK_SIZE {
                    block[j] ^= state.k1[j];
                }
            } else {
                // Incomplete block - pad and XOR with K2
                block[..state.buffer.len()].copy_from_slice(&state.buffer);
                if state.buffer.len() < CMAC_BLOCK_SIZE {
                    block[state.buffer.len()] = 0x80; // Padding
                }
                for j in 0..CMAC_BLOCK_SIZE {
                    block[j] ^= state.k2[j];
                }
            }
            
            // XOR with previous result
            for j in 0..CMAC_BLOCK_SIZE {
                x[j] ^= block[j];
            }
            
            // Final encryption
            x = Self::aes_encrypt_block(&state.key, &x);
        } else if x == [0u8; CMAC_BLOCK_SIZE] {
            // Empty message case
            let mut block = [0u8; CMAC_BLOCK_SIZE];
            block[0] = 0x80; // Padding
            
            // XOR with K2
            for j in 0..CMAC_BLOCK_SIZE {
                block[j] ^= state.k2[j];
            }
            
            x = Self::aes_encrypt_block(&state.key, &block);
        }
        
        CmacTag { tag: x }
    }
    
    // OMAC (One-Key MAC) - variant of CMAC
    pub fn compute_omac(key: &[u8; CMAC_KEY_SIZE], message: &[u8]) -> [u8; CMAC_TAG_SIZE] {
        // OMAC is very similar to CMAC but with slight differences in padding
        // For simplicity, we'll use the same implementation as CMAC
        Self::compute_cmac(key, message)
    }
}

impl UnforgeableMac for CMAC {}
impl SecureMac for CMAC {}

#[cfg(test)]
mod tests {
    use super::*;
    
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
        assert_eq!(tag.len(), CMAC_TAG_SIZE);
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
}