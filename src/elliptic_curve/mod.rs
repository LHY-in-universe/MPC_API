//! Elliptic Curve Cryptography (椭圆曲线加密)
//! 
//! This module implements elliptic curve cryptographic primitives

pub mod curve25519;
pub mod secp256k1;
pub mod point;
pub mod scalar;
pub mod ecdh;
pub mod ecdsa;

pub use curve25519::*;
pub use secp256k1::*;
pub use point::*;
pub use scalar::*;
pub use ecdh::*;
pub use ecdsa::*;

use crate::{MpcError, Result};
use serde::{Deserialize, Serialize};

// Basic elliptic curve point representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ECPoint {
    pub x: u64,
    pub y: u64,
    pub is_infinity: bool,
}

impl ECPoint {
    pub fn new(x: u64, y: u64) -> Self {
        Self {
            x,
            y,
            is_infinity: false,
        }
    }
    
    pub fn infinity() -> Self {
        Self {
            x: 0,
            y: 0,
            is_infinity: true,
        }
    }
    
    pub fn is_infinity(&self) -> bool {
        self.is_infinity
    }
}

// Basic elliptic curve parameters for y^2 = x^3 + ax + b (mod p)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECParams {
    pub a: u64,        // curve parameter a
    pub b: u64,        // curve parameter b
    pub p: u64,        // prime modulus
    pub n: u64,        // order of the curve (number of points)
    pub g: ECPoint,    // generator point
}

pub trait EllipticCurve {
    fn params() -> ECParams;
    fn point_add(p1: &ECPoint, p2: &ECPoint) -> Result<ECPoint>;
    fn point_double(point: &ECPoint) -> Result<ECPoint>;
    fn scalar_multiply(scalar: u64, point: &ECPoint) -> Result<ECPoint>;
    fn is_on_curve(point: &ECPoint) -> bool;
}

pub trait ECDH {
    fn generate_keypair() -> Result<(u64, ECPoint)>; // (private_key, public_key)
    fn compute_shared_secret(private_key: u64, public_key: &ECPoint) -> Result<ECPoint>;
}

pub trait ECDSA {
    type Signature;
    
    fn sign(private_key: u64, message_hash: u64) -> Result<Self::Signature>;
    fn verify(public_key: &ECPoint, message_hash: u64, signature: &Self::Signature) -> Result<bool>;
}