//! MPC API - A comprehensive Multi-Party Computation library in Rust
//! 
//! This library provides implementations of various cryptographic primitives
//! and protocols for secure multi-party computation, including:
//! 
//! - Secret Sharing (Shamir's Secret Sharing)
//! - Garbled Circuits
//! - Oblivious Transfer protocols
//! - Homomorphic Encryption schemes
//! - Elliptic Curve Cryptography
//! - Advanced protocols (SPDZ, Zero-Knowledge Proofs, etc.)

pub mod secret_sharing;
pub mod garbled_circuits;
pub mod oblivious_transfer;
pub mod homomorphic_encryption;
pub mod elliptic_curve;
pub mod protocols;
pub mod commitment;
pub mod authentication;
pub mod spdz;
pub mod zero_knowledge;
pub mod beaver_triples;
pub mod utils;

pub use secret_sharing::*;
pub use garbled_circuits::*;
pub use oblivious_transfer::*;
pub use homomorphic_encryption::*;
pub use elliptic_curve::*;
pub use protocols::*;
pub use commitment::*;
pub use authentication::*;
pub use spdz::*;
pub use zero_knowledge::*;
pub use beaver_triples::*;
pub use utils::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MpcError {
    #[error("Invalid secret share")]
    InvalidSecretShare,
    #[error("Insufficient shares for reconstruction")]
    InsufficientShares,
    #[error("Invalid threshold")]
    InvalidThreshold,
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
}

pub type Result<T> = std::result::Result<T, MpcError>;