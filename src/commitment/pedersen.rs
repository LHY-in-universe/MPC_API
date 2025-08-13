//! Pedersen Commitment Scheme
//! 
//! Implements the Pedersen commitment scheme using elliptic curve points

use crate::{MpcError, Result};
use crate::elliptic_curve::{ECPoint, SimpleEC, EllipticCurve};
use crate::secret_sharing::{FIELD_PRIME, field_add};
use super::CommitmentScheme;
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenParams {
    pub g: ECPoint,  // Generator point
    pub h: ECPoint,  // Another generator point
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub commitment: ECPoint,
}

impl PedersenParams {
    pub fn new() -> Result<Self> {
        let ec_params = SimpleEC::params();
        let g = ec_params.g.clone();
        
        // Generate a second generator h
        let mut rng = thread_rng();
        let random_scalar = rng.gen_range(1..ec_params.n);
        let h = SimpleEC::scalar_multiply(random_scalar, &g)?;
        
        Ok(PedersenParams { g, h })
    }
}

impl CommitmentScheme for PedersenCommitment {
    type Commitment = ECPoint;
    type Message = u64;
    type Randomness = u64;
    
    fn commit(message: Self::Message, randomness: Self::Randomness) -> Self::Commitment {
        let params = PedersenParams::new().unwrap();
        
        // Commitment = message * G + randomness * H
        let message_point = SimpleEC::scalar_multiply(message, &params.g).unwrap();
        let randomness_point = SimpleEC::scalar_multiply(randomness, &params.h).unwrap();
        
        SimpleEC::point_add(&message_point, &randomness_point).unwrap()
    }
    
    fn verify(commitment: Self::Commitment, message: Self::Message, randomness: Self::Randomness) -> bool {
        let expected_commitment = Self::commit(message, randomness);
        commitment == expected_commitment
    }
}

impl PedersenCommitment {
    pub fn new(message: u64, randomness: u64) -> Result<Self> {
        let commitment = Self::commit(message, randomness);
        Ok(PedersenCommitment { commitment })
    }
    
    pub fn commit_with_params(params: &PedersenParams, message: u64, randomness: u64) -> Result<ECPoint> {
        // Commitment = message * G + randomness * H
        let message_point = SimpleEC::scalar_multiply(message, &params.g)?;
        let randomness_point = SimpleEC::scalar_multiply(randomness, &params.h)?;
        
        SimpleEC::point_add(&message_point, &randomness_point)
    }
    
    pub fn verify_with_params(
        params: &PedersenParams,
        commitment: &ECPoint,
        message: u64,
        randomness: u64,
    ) -> Result<bool> {
        let expected_commitment = Self::commit_with_params(params, message, randomness)?;
        Ok(*commitment == expected_commitment)
    }
    
    // Homomorphic addition of commitments
    pub fn add_commitments(commit1: &ECPoint, commit2: &ECPoint) -> Result<ECPoint> {
        SimpleEC::point_add(commit1, commit2)
    }
    
    // Add a message to an existing commitment (requires adding randomness)
    pub fn add_message_to_commitment(
        params: &PedersenParams,
        commitment: &ECPoint,
        additional_message: u64,
        additional_randomness: u64,
    ) -> Result<ECPoint> {
        let additional_commit = Self::commit_with_params(params, additional_message, additional_randomness)?;
        Self::add_commitments(commitment, &additional_commit)
    }
    
    // Generate random commitment parameters
    pub fn generate_random_commitment() -> Result<(u64, u64, ECPoint)> {
        let mut rng = thread_rng();
        let message = rng.gen_range(0..FIELD_PRIME);
        let randomness = rng.gen_range(0..FIELD_PRIME);
        let commitment = Self::commit(message, randomness);
        
        Ok((message, randomness, commitment))
    }
    
    // Batch commit multiple messages
    pub fn batch_commit(params: &PedersenParams, messages: &[u64], randomness: &[u64]) -> Result<Vec<ECPoint>> {
        if messages.len() != randomness.len() {
            return Err(MpcError::ProtocolError("Messages and randomness arrays must have same length".to_string()));
        }
        
        let mut commitments = Vec::new();
        for (message, rand) in messages.iter().zip(randomness.iter()) {
            let commit = Self::commit_with_params(params, *message, *rand)?;
            commitments.push(commit);
        }
        
        Ok(commitments)
    }
    
    // Vector commitment for multiple messages with single randomness
    pub fn vector_commit(params: &PedersenParams, messages: &[u64], randomness: u64) -> Result<ECPoint> {
        if messages.is_empty() {
            return Err(MpcError::ProtocolError("Messages array cannot be empty".to_string()));
        }
        
        // Commit to sum of all messages
        let total_message = messages.iter().fold(0u64, |acc, &msg| field_add(acc, msg));
        Self::commit_with_params(params, total_message, randomness)
    }
}

// Pedersen commitment with binding and hiding properties
impl super::BindingCommitment for PedersenCommitment {}
impl super::HidingCommitment for PedersenCommitment {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pedersen_commitment_basic() {
        let message = 42u64;
        let randomness = 123u64;
        
        let commitment = PedersenCommitment::commit(message, randomness);
        let verification = PedersenCommitment::verify(commitment, message, randomness);
        
        assert!(verification);
    }
    
    #[test]
    fn test_pedersen_commitment_with_params() {
        let params = PedersenParams::new().unwrap();
        let message = 42u64;
        let randomness = 123u64;
        
        let commitment = PedersenCommitment::commit_with_params(&params, message, randomness).unwrap();
        let verification = PedersenCommitment::verify_with_params(&params, &commitment, message, randomness).unwrap();
        
        assert!(verification);
    }
    
    #[test]
    fn test_pedersen_commitment_wrong_message() {
        let params = PedersenParams::new().unwrap();
        let message = 42u64;
        let wrong_message = 43u64;
        let randomness = 123u64;
        
        let commitment = PedersenCommitment::commit_with_params(&params, message, randomness).unwrap();
        let verification = PedersenCommitment::verify_with_params(&params, &commitment, wrong_message, randomness).unwrap();
        
        assert!(!verification);
    }
    
    #[test]
    fn test_pedersen_commitment_wrong_randomness() {
        let params = PedersenParams::new().unwrap();
        let message = 42u64;
        let randomness = 123u64;
        let wrong_randomness = 124u64;
        
        let commitment = PedersenCommitment::commit_with_params(&params, message, randomness).unwrap();
        let verification = PedersenCommitment::verify_with_params(&params, &commitment, message, wrong_randomness).unwrap();
        
        assert!(!verification);
    }
    
    #[test]
    fn test_pedersen_commitment_homomorphic_addition() {
        let params = PedersenParams::new().unwrap();
        
        let message1 = 10u64;
        let randomness1 = 20u64;
        let commit1 = PedersenCommitment::commit_with_params(&params, message1, randomness1).unwrap();
        
        let message2 = 15u64;
        let randomness2 = 25u64;
        let commit2 = PedersenCommitment::commit_with_params(&params, message2, randomness2).unwrap();
        
        // Add commitments
        let combined_commit = PedersenCommitment::add_commitments(&commit1, &commit2).unwrap();
        
        // Verify combined commitment
        let combined_message = field_add(message1, message2);
        let combined_randomness = field_add(randomness1, randomness2);
        let expected_commit = PedersenCommitment::commit_with_params(&params, combined_message, combined_randomness).unwrap();
        
        assert_eq!(combined_commit, expected_commit);
    }
    
    #[test]
    fn test_pedersen_commitment_batch() {
        let params = PedersenParams::new().unwrap();
        let messages = vec![10u64, 20u64, 30u64];
        let randomness = vec![100u64, 200u64, 300u64];
        
        let commitments = PedersenCommitment::batch_commit(&params, &messages, &randomness).unwrap();
        
        assert_eq!(commitments.len(), 3);
        
        // Verify each commitment
        for (i, (msg, rand)) in messages.iter().zip(randomness.iter()).enumerate() {
            let verification = PedersenCommitment::verify_with_params(&params, &commitments[i], *msg, *rand).unwrap();
            assert!(verification);
        }
    }
    
    #[test]
    fn test_pedersen_commitment_vector() {
        let params = PedersenParams::new().unwrap();
        let messages = vec![10u64, 20u64, 30u64];
        let randomness = 500u64;
        
        let vector_commit = PedersenCommitment::vector_commit(&params, &messages, randomness).unwrap();
        
        // Verify vector commitment
        let total_message = messages.iter().fold(0u64, |acc, &msg| field_add(acc, msg));
        let expected_commit = PedersenCommitment::commit_with_params(&params, total_message, randomness).unwrap();
        
        assert_eq!(vector_commit, expected_commit);
    }
    
    #[test]
    fn test_pedersen_generate_random_commitment() {
        let (message, randomness, commitment) = PedersenCommitment::generate_random_commitment().unwrap();
        
        let verification = PedersenCommitment::verify(commitment, message, randomness);
        assert!(verification);
    }
    
    #[test]
    fn test_pedersen_add_message_to_commitment() {
        let params = PedersenParams::new().unwrap();
        
        let initial_message = 100u64;
        let initial_randomness = 200u64;
        let initial_commit = PedersenCommitment::commit_with_params(&params, initial_message, initial_randomness).unwrap();
        
        let additional_message = 50u64;
        let additional_randomness = 75u64;
        
        let updated_commit = PedersenCommitment::add_message_to_commitment(
            &params,
            &initial_commit,
            additional_message,
            additional_randomness,
        ).unwrap();
        
        // Verify updated commitment
        let total_message = field_add(initial_message, additional_message);
        let total_randomness = field_add(initial_randomness, additional_randomness);
        let verification = PedersenCommitment::verify_with_params(&params, &updated_commit, total_message, total_randomness).unwrap();
        
        assert!(verification);
    }
}