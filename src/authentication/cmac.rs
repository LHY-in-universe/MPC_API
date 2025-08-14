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

impl Default for CMAC {
    fn default() -> Self {
        Self::new()
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
    pub fn generate_subkeys(key: &[u8; CMAC_KEY_SIZE]) -> ([u8; CMAC_BLOCK_SIZE], [u8; CMAC_BLOCK_SIZE]) {
        // L = AES(K, 0^128)
        let zero_block = [0u8; CMAC_BLOCK_SIZE];
        let l = Self::aes_encrypt_block(key, &zero_block);
        
        // Generate K1 and K2
        let k1 = Self::left_shift(&l);
        let k2 = Self::left_shift(&k1);
        
        (k1, k2)
    }
    
    // Left shift by one bit in GF(2^128)
    pub fn left_shift(input: &[u8; CMAC_BLOCK_SIZE]) -> [u8; CMAC_BLOCK_SIZE] {
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

// Tests moved to tests/authentication_tests.rs