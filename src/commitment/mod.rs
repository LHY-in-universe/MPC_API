//! Commitment Schemes (承诺方案)
//! 
//! This module implements various commitment schemes

pub mod pedersen;
pub mod hash_commit;
pub mod merkle_tree;

pub use pedersen::*;
pub use hash_commit::*;
pub use merkle_tree::*;

// use crate::Result; // Unused import
// use serde::{Deserialize, Serialize}; // Unused imports

pub trait CommitmentScheme {
    type Commitment;
    type Message;
    type Randomness;
    
    fn commit(message: Self::Message, randomness: Self::Randomness) -> Self::Commitment;
    fn verify(commitment: Self::Commitment, message: Self::Message, randomness: Self::Randomness) -> bool;
}

// Basic commitment properties
pub trait BindingCommitment: CommitmentScheme {
    fn is_binding() -> bool { true }
}

pub trait HidingCommitment: CommitmentScheme {
    fn is_hiding() -> bool { true }
}