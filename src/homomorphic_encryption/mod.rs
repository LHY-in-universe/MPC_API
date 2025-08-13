//! Homomorphic Encryption schemes
//! 
//! This module implements various homomorphic encryption schemes:
//! - ElGamal (partially homomorphic - multiplicative)
//! - RSA (multiplicatively homomorphic)
//! - Paillier (additively homomorphic)
//! - BFV (fully homomorphic)
//! - BGV (fully homomorphic)

pub mod elgamal;
pub mod rsa;
pub mod paillier;
pub mod bfv;
pub mod bgv;

pub use elgamal::*;
pub use rsa::*;
pub use paillier::*;
pub use bfv::*;
pub use bgv::*;

use crate::{MpcError, Result};
use serde::{Deserialize, Serialize};

pub trait HomomorphicEncryption {
    type PlaintextSpace;
    type CiphertextSpace;
    type PublicKey;
    type PrivateKey;
    
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)>;
    fn encrypt(pk: &Self::PublicKey, plaintext: &Self::PlaintextSpace) -> Result<Self::CiphertextSpace>;
    fn decrypt(sk: &Self::PrivateKey, ciphertext: &Self::CiphertextSpace) -> Result<Self::PlaintextSpace>;
}

pub trait AdditivelyHomomorphic: HomomorphicEncryption {
    fn add_ciphertexts(
        pk: &Self::PublicKey,
        c1: &Self::CiphertextSpace,
        c2: &Self::CiphertextSpace,
    ) -> Result<Self::CiphertextSpace>;
    
    fn scalar_multiply(
        pk: &Self::PublicKey,
        ciphertext: &Self::CiphertextSpace,
        scalar: &Self::PlaintextSpace,
    ) -> Result<Self::CiphertextSpace>;
}

pub trait MultiplicativelyHomomorphic: HomomorphicEncryption {
    fn multiply_ciphertexts(
        pk: &Self::PublicKey,
        c1: &Self::CiphertextSpace,
        c2: &Self::CiphertextSpace,
    ) -> Result<Self::CiphertextSpace>;
    
    fn power(
        pk: &Self::PublicKey,
        ciphertext: &Self::CiphertextSpace,
        exponent: u64,
    ) -> Result<Self::CiphertextSpace>;
}

pub trait FullyHomomorphic: AdditivelyHomomorphic + MultiplicativelyHomomorphic {
    fn evaluate_circuit<F>(
        pk: &Self::PublicKey,
        circuit: F,
        inputs: &[Self::CiphertextSpace],
    ) -> Result<Self::CiphertextSpace>
    where
        F: Fn(&[Self::CiphertextSpace]) -> Result<Self::CiphertextSpace>;
}