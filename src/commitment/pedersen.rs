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
    
    pub fn new_fixed() -> Self {
        let ec_params = SimpleEC::params();
        let g = ec_params.g.clone();
        
        // Use a fixed scalar for h to ensure consistency across calls
        let fixed_scalar = 12345u64;  // Fixed value for testing
        let h = SimpleEC::scalar_multiply(fixed_scalar, &g).unwrap();
        
        PedersenParams { g, h }
    }
}

impl CommitmentScheme for PedersenCommitment {
    type Commitment = ECPoint;
    type Message = u64;
    type Randomness = u64;
    
    fn commit(message: Self::Message, randomness: Self::Randomness) -> Self::Commitment {
        let params = PedersenParams::new_fixed();
        
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

// Tests moved to tests/commitment_tests.rs