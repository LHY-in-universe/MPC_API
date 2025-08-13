//! Oblivious Transfer (不经意传输) protocols
//! 
//! This module implements various oblivious transfer protocols including:
//! - Basic 1-out-of-2 OT (不经意传输)
//! - Correlated OT (相关不经意传输) 
//! - Random OT (随机不经意传输)
//! - 1-out-of-N OT extensions

pub mod basic_ot;
pub mod correlated_ot;
pub mod random_ot;
pub mod ot_extension;
pub mod naor_pinkas;
pub mod vole;
pub mod ole;

pub use basic_ot::*;
pub use correlated_ot::*;
pub use random_ot::*;
pub use ot_extension::*;
pub use naor_pinkas::*;
pub use vole::*;
pub use ole::*;

use crate::{MpcError, Result};
use crate::secret_sharing::{FIELD_PRIME, field_add, field_mul, field_sub};
use serde::{Deserialize, Serialize};
use rand::{Rng, RngCore};

pub type OTMessage = Vec<u8>;
pub type ChoiceBit = bool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTSenderOutput {
    pub message0: OTMessage,
    pub message1: OTMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTReceiverInput {
    pub choice_bit: ChoiceBit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTReceiverOutput {
    pub chosen_message: OTMessage,
}

// Diffie-Hellman based OT using u64 field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHOTSetup {
    pub generator: u64,
    pub prime: u64,
    pub sender_private: u64,
    pub receiver_private: u64,
}

impl DHOTSetup {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            generator: 3, // Simple generator for our field
            prime: FIELD_PRIME,
            sender_private: rng.gen_range(1..FIELD_PRIME),
            receiver_private: rng.gen_range(1..FIELD_PRIME),
        }
    }
    
    pub fn pow_mod(&self, base: u64, exp: u64) -> u64 {
        if exp == 0 {
            return 1;
        }
        
        let mut result = 1u64;
        let mut base = base % self.prime;
        let mut exp = exp;
        
        while exp > 0 {
            if exp % 2 == 1 {
                result = field_mul(result, base);
            }
            exp = exp >> 1;
            base = field_mul(base, base);
        }
        
        result
    }
}

impl Default for DHOTSetup {
    fn default() -> Self {
        Self::new()
    }
}

pub trait ObliviousTransfer {
    type SenderInput;
    type ReceiverInput;
    type SenderOutput;
    type ReceiverOutput;
    
    fn sender_setup(&mut self) -> Result<Self::SenderOutput>;
    fn receiver_setup(&mut self, input: Self::ReceiverInput) -> Result<Self::ReceiverOutput>;
}

// Helper functions for OT protocols
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

pub fn hash_to_bytes(input: u64) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.to_le_bytes());
    hasher.finalize().to_vec()
}