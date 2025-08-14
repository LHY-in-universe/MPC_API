//! Coin Flipping Protocol (投币协议)
//! 
//! Implements secure coin flipping protocols for generating shared randomness

use crate::{MpcError, Result};
use crate::secret_sharing::{FIELD_PRIME, field_add};
use crate::commitment::{PedersenCommitment, CommitmentScheme};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinFlipCommit {
    pub commitment: u64,
    pub randomness: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinFlipReveal {
    pub value: bool,
    pub randomness: u64,
}

pub trait CoinFlipping {
    fn commit_bit(bit: bool) -> Result<(CoinFlipCommit, CoinFlipReveal)>;
    fn verify_and_combine(
        commit1: &CoinFlipCommit,
        reveal1: &CoinFlipReveal,
        commit2: &CoinFlipCommit, 
        reveal2: &CoinFlipReveal,
    ) -> Result<bool>;
}

// Simple XOR-based coin flipping
pub struct XORCoinFlip;

impl CoinFlipping for XORCoinFlip {
    fn commit_bit(bit: bool) -> Result<(CoinFlipCommit, CoinFlipReveal)> {
        let mut rng = thread_rng();
        let randomness = rng.gen_range(0..FIELD_PRIME);
        
        // Simple commitment: hash(bit || randomness)
        let bit_value = if bit { 1u64 } else { 0u64 };
        let commitment = Self::hash_commit(bit_value, randomness);
        
        let commit = CoinFlipCommit { commitment, randomness };
        let reveal = CoinFlipReveal { value: bit, randomness };
        
        Ok((commit, reveal))
    }
    
    fn verify_and_combine(
        commit1: &CoinFlipCommit,
        reveal1: &CoinFlipReveal,
        commit2: &CoinFlipCommit,
        reveal2: &CoinFlipReveal,
    ) -> Result<bool> {
        // Verify commitments
        let bit1_value = if reveal1.value { 1u64 } else { 0u64 };
        let bit2_value = if reveal2.value { 1u64 } else { 0u64 };
        
        let expected_commit1 = Self::hash_commit(bit1_value, reveal1.randomness);
        let expected_commit2 = Self::hash_commit(bit2_value, reveal2.randomness);
        
        if commit1.commitment != expected_commit1 || commit2.commitment != expected_commit2 {
            return Err(MpcError::ProtocolError("Commitment verification failed".to_string()));
        }
        
        // XOR the revealed bits
        Ok(reveal1.value ^ reveal2.value)
    }
}

impl XORCoinFlip {
    fn hash_commit(bit: u64, randomness: u64) -> u64 {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(bit.to_le_bytes());
        hasher.update(randomness.to_le_bytes());
        let result = hasher.finalize();
        
        let mut commitment = 0u64;
        for (i, &byte) in result.iter().take(8).enumerate() {
            commitment |= (byte as u64) << (i * 8);
        }
        commitment % FIELD_PRIME
    }
}

// Blum's coin flipping protocol using bit commitments
pub struct BlumCoinFlip;

impl BlumCoinFlip {
    pub fn protocol() -> Result<bool> {
        // Alice commits to a random bit
        let mut rng = thread_rng();
        let alice_bit = rng.gen::<bool>();
        let (alice_commit, alice_reveal) = XORCoinFlip::commit_bit(alice_bit)?;
        
        // Bob chooses his bit after seeing Alice's commitment
        let bob_bit = rng.gen::<bool>();
        let (bob_commit, bob_reveal) = XORCoinFlip::commit_bit(bob_bit)?;
        
        // Both reveal and combine
        XORCoinFlip::verify_and_combine(&alice_commit, &alice_reveal, &bob_commit, &bob_reveal)
    }
    
    pub fn multi_party_coin_flip(num_parties: usize) -> Result<bool> {
        if num_parties == 0 {
            return Err(MpcError::ProtocolError("Need at least one party".to_string()));
        }
        
        let mut commits = Vec::new();
        let mut reveals = Vec::new();
        let mut rng = thread_rng();
        
        // Each party commits to a random bit
        for _ in 0..num_parties {
            let bit = rng.gen::<bool>();
            let (commit, reveal) = XORCoinFlip::commit_bit(bit)?;
            commits.push(commit);
            reveals.push(reveal);
        }
        
        // XOR all bits together
        let mut result = false;
        for i in 0..num_parties {
            // Verify commitment
            let bit_value = if reveals[i].value { 1u64 } else { 0u64 };
            let expected_commit = XORCoinFlip::hash_commit(bit_value, reveals[i].randomness);
            
            if commits[i].commitment != expected_commit {
                return Err(MpcError::ProtocolError("Multi-party commitment verification failed".to_string()));
            }
            
            result ^= reveals[i].value;
        }
        
        Ok(result)
    }
}

// Coin flipping with bias resistance
pub struct BiasResistantCoinFlip;

impl BiasResistantCoinFlip {
    pub fn protocol_with_multiple_rounds(num_rounds: usize) -> Result<Vec<bool>> {
        let mut results = Vec::new();
        
        for _ in 0..num_rounds {
            let coin = BlumCoinFlip::protocol()?;
            results.push(coin);
        }
        
        Ok(results)
    }
    
    pub fn generate_shared_randomness(num_bits: usize) -> Result<Vec<bool>> {
        Self::protocol_with_multiple_rounds(num_bits)
    }
    
    // Extract randomness using von Neumann technique
    pub fn extract_unbiased_bits(biased_coins: &[bool]) -> Vec<bool> {
        let mut unbiased = Vec::new();
        let mut i = 0;
        
        while i + 1 < biased_coins.len() {
            match (biased_coins[i], biased_coins[i + 1]) {
                (false, true) => unbiased.push(false),
                (true, false) => unbiased.push(true),
                _ => {}, // Skip (0,0) and (1,1) pairs
            }
            i += 2;
        }
        
        unbiased
    }
}

// Coin flipping using commitment schemes
pub struct CommitmentBasedCoinFlip;

impl CommitmentBasedCoinFlip {
    pub fn protocol_with_pedersen() -> Result<bool> {
        let mut rng = thread_rng();
        
        // Alice commits to a random value using Pedersen commitment
        let alice_value = rng.gen_range(0..FIELD_PRIME);
        let alice_randomness = rng.gen_range(0..FIELD_PRIME);
        let alice_commitment = PedersenCommitment::commit(alice_value, alice_randomness);
        
        // Bob commits to a random value
        let bob_value = rng.gen_range(0..FIELD_PRIME);
        let bob_randomness = rng.gen_range(0..FIELD_PRIME);
        let bob_commitment = PedersenCommitment::commit(bob_value, bob_randomness);
        
        // Both reveal
        let alice_valid = PedersenCommitment::verify(alice_commitment, alice_value, alice_randomness);
        let bob_valid = PedersenCommitment::verify(bob_commitment, bob_value, bob_randomness);
        
        if !alice_valid || !bob_valid {
            return Err(MpcError::ProtocolError("Pedersen commitment verification failed".to_string()));
        }
        
        // Combine values
        let combined = field_add(alice_value, bob_value);
        Ok((combined % 2) == 1)
    }
}

// Sequential coin flipping for generating random strings
pub struct SequentialCoinFlip;

impl SequentialCoinFlip {
    pub fn generate_random_string(length: usize) -> Result<String> {
        let mut result = String::new();
        
        for _ in 0..length {
            let bit = BlumCoinFlip::protocol()?;
            result.push(if bit { '1' } else { '0' });
        }
        
        Ok(result)
    }
    
    pub fn generate_random_bytes(num_bytes: usize) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        for _ in 0..num_bytes {
            let mut byte = 0u8;
            for bit_pos in 0..8 {
                let bit = BlumCoinFlip::protocol()?;
                if bit {
                    byte |= 1 << bit_pos;
                }
            }
            result.push(byte);
        }
        
        Ok(result)
    }
    
    pub fn generate_random_field_elements(count: usize) -> Result<Vec<u64>> {
        let mut result = Vec::new();
        
        for _ in 0..count {
            let mut element = 0u64;
            
            // Generate random bits to form a field element
            for bit_pos in 0..64 {
                let bit = BlumCoinFlip::protocol()?;
                if bit {
                    element |= 1 << bit_pos;
                }
            }
            
            result.push(element % FIELD_PRIME);
        }
        
        Ok(result)
    }
}

// Tests moved to tests/protocols_tests.rs
