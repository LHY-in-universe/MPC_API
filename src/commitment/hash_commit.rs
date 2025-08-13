//! Hash-based Commitment Scheme
//! 
//! Implements a simple hash-based commitment scheme using SHA-256

use crate::{MpcError, Result};
use crate::secret_sharing::FIELD_PRIME;
use super::CommitmentScheme;
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashCommitment {
    pub hash: [u8; 32],
}

impl CommitmentScheme for HashCommitment {
    type Commitment = [u8; 32];
    type Message = Vec<u8>;
    type Randomness = Vec<u8>;
    
    fn commit(message: Self::Message, randomness: Self::Randomness) -> Self::Commitment {
        let mut hasher = Sha256::new();
        hasher.update(&message);
        hasher.update(&randomness);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    fn verify(commitment: Self::Commitment, message: Self::Message, randomness: Self::Randomness) -> bool {
        let expected_commitment = Self::commit(message, randomness);
        commitment == expected_commitment
    }
}

impl HashCommitment {
    pub fn new(message: &[u8], randomness: &[u8]) -> Self {
        let hash = Self::commit(message.to_vec(), randomness.to_vec());
        HashCommitment { hash }
    }
    
    pub fn commit_u64(value: u64, randomness: u64) -> [u8; 32] {
        let message = value.to_le_bytes().to_vec();
        let rand_bytes = randomness.to_le_bytes().to_vec();
        Self::commit(message, rand_bytes)
    }
    
    pub fn verify_u64(commitment: &[u8; 32], value: u64, randomness: u64) -> bool {
        let expected = Self::commit_u64(value, randomness);
        *commitment == expected
    }
    
    pub fn commit_string(message: &str, randomness: &[u8]) -> [u8; 32] {
        Self::commit(message.as_bytes().to_vec(), randomness.to_vec())
    }
    
    pub fn verify_string(commitment: &[u8; 32], message: &str, randomness: &[u8]) -> bool {
        let expected = Self::commit_string(message, randomness);
        *commitment == expected
    }
    
    // Generate random nonce for commitment
    pub fn generate_randomness(length: usize) -> Vec<u8> {
        let mut rng = thread_rng();
        (0..length).map(|_| rng.gen()).collect()
    }
    
    // Commit to multiple values at once
    pub fn batch_commit_u64(values: &[u64], randomness: &[u64]) -> Result<Vec<[u8; 32]>> {
        if values.len() != randomness.len() {
            return Err(MpcError::ProtocolError("Values and randomness arrays must have same length".to_string()));
        }
        
        let mut commitments = Vec::new();
        for (value, rand) in values.iter().zip(randomness.iter()) {
            let commitment = Self::commit_u64(*value, *rand);
            commitments.push(commitment);
        }
        
        Ok(commitments)
    }
    
    // Commit to a vector of values with a single randomness
    pub fn vector_commit_u64(values: &[u64], randomness: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Add all values to the hash
        for value in values {
            hasher.update(value.to_le_bytes());
        }
        
        // Add randomness
        hasher.update(randomness.to_le_bytes());
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    pub fn verify_vector_u64(commitment: &[u8; 32], values: &[u64], randomness: u64) -> bool {
        let expected = Self::vector_commit_u64(values, randomness);
        *commitment == expected
    }
    
    // Merkle tree style commitment for large data
    pub fn merkle_commit(data: &[Vec<u8>]) -> Result<[u8; 32]> {
        if data.is_empty() {
            return Err(MpcError::ProtocolError("Cannot commit to empty data".to_string()));
        }
        
        if data.len() == 1 {
            let mut hasher = Sha256::new();
            hasher.update(&data[0]);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            return Ok(hash);
        }
        
        // Hash pairs of data
        let mut current_level: Vec<[u8; 32]> = data.iter().map(|item| {
            let mut hasher = Sha256::new();
            hasher.update(item);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        }).collect();
        
        // Build Merkle tree
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    // Odd number of elements, duplicate the last one
                    hasher.update(&chunk[0]);
                }
                
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                next_level.push(hash);
            }
            
            current_level = next_level;
        }
        
        Ok(current_level[0])
    }
    
    // Generate commitment with automatic randomness
    pub fn auto_commit_u64(value: u64) -> (u64, [u8; 32]) {
        let mut rng = thread_rng();
        let randomness = rng.gen_range(0..FIELD_PRIME);
        let commitment = Self::commit_u64(value, randomness);
        (randomness, commitment)
    }
    
    // Commit to a secret shared value
    pub fn commit_secret_share(share_value: u64, share_index: usize, randomness: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(share_value.to_le_bytes());
        hasher.update(share_index.to_le_bytes());
        hasher.update(randomness.to_le_bytes());
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    pub fn verify_secret_share(
        commitment: &[u8; 32],
        share_value: u64,
        share_index: usize,
        randomness: u64,
    ) -> bool {
        let expected = Self::commit_secret_share(share_value, share_index, randomness);
        *commitment == expected
    }
}

// Hash commitment is binding but not necessarily perfectly hiding
impl super::BindingCommitment for HashCommitment {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_commitment_basic() {
        let message = b"Hello, World!";
        let randomness = HashCommitment::generate_randomness(32);
        
        let commitment = HashCommitment::commit(message.to_vec(), randomness.clone());
        let verification = HashCommitment::verify(commitment, message.to_vec(), randomness);
        
        assert!(verification);
    }
    
    #[test]
    fn test_hash_commitment_u64() {
        let value = 12345u64;
        let randomness = 67890u64;
        
        let commitment = HashCommitment::commit_u64(value, randomness);
        let verification = HashCommitment::verify_u64(&commitment, value, randomness);
        
        assert!(verification);
    }
    
    #[test]
    fn test_hash_commitment_wrong_value() {
        let value = 12345u64;
        let wrong_value = 12346u64;
        let randomness = 67890u64;
        
        let commitment = HashCommitment::commit_u64(value, randomness);
        let verification = HashCommitment::verify_u64(&commitment, wrong_value, randomness);
        
        assert!(!verification);
    }
    
    #[test]
    fn test_hash_commitment_wrong_randomness() {
        let value = 12345u64;
        let randomness = 67890u64;
        let wrong_randomness = 67891u64;
        
        let commitment = HashCommitment::commit_u64(value, randomness);
        let verification = HashCommitment::verify_u64(&commitment, value, wrong_randomness);
        
        assert!(!verification);
    }
    
    #[test]
    fn test_hash_commitment_string() {
        let message = "Secret message";
        let randomness = HashCommitment::generate_randomness(16);
        
        let commitment = HashCommitment::commit_string(message, &randomness);
        let verification = HashCommitment::verify_string(&commitment, message, &randomness);
        
        assert!(verification);
    }
    
    #[test]
    fn test_hash_commitment_batch() {
        let values = vec![10u64, 20u64, 30u64];
        let randomness = vec![100u64, 200u64, 300u64];
        
        let commitments = HashCommitment::batch_commit_u64(&values, &randomness).unwrap();
        
        assert_eq!(commitments.len(), 3);
        
        // Verify each commitment
        for (i, (value, rand)) in values.iter().zip(randomness.iter()).enumerate() {
            let verification = HashCommitment::verify_u64(&commitments[i], *value, *rand);
            assert!(verification);
        }
    }
    
    #[test]
    fn test_hash_commitment_vector() {
        let values = vec![10u64, 20u64, 30u64];
        let randomness = 500u64;
        
        let commitment = HashCommitment::vector_commit_u64(&values, randomness);
        let verification = HashCommitment::verify_vector_u64(&commitment, &values, randomness);
        
        assert!(verification);
    }
    
    #[test]
    fn test_hash_commitment_merkle() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
        ];
        
        let commitment = HashCommitment::merkle_commit(&data).unwrap();
        assert_eq!(commitment.len(), 32);
    }
    
    #[test]
    fn test_hash_commitment_auto() {
        let value = 42u64;
        let (randomness, commitment) = HashCommitment::auto_commit_u64(value);
        
        let verification = HashCommitment::verify_u64(&commitment, value, randomness);
        assert!(verification);
    }
    
    #[test]
    fn test_hash_commitment_secret_share() {
        let share_value = 123u64;
        let share_index = 1usize;
        let randomness = 456u64;
        
        let commitment = HashCommitment::commit_secret_share(share_value, share_index, randomness);
        let verification = HashCommitment::verify_secret_share(&commitment, share_value, share_index, randomness);
        
        assert!(verification);
    }
    
    #[test]
    fn test_hash_commitment_different_messages() {
        let randomness = 12345u64;
        
        let commit1 = HashCommitment::commit_u64(100, randomness);
        let commit2 = HashCommitment::commit_u64(101, randomness);
        
        // Different messages should produce different commitments
        assert_ne!(commit1, commit2);
    }
    
    #[test]
    fn test_hash_commitment_same_message_different_randomness() {
        let value = 100u64;
        
        let commit1 = HashCommitment::commit_u64(value, 123);
        let commit2 = HashCommitment::commit_u64(value, 124);
        
        // Same message with different randomness should produce different commitments
        assert_ne!(commit1, commit2);
    }
}