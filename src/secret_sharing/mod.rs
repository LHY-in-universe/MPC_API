//! Secret Sharing implementations
//! 
//! This module provides implementations of secret sharing schemes,
//! primarily Shamir's Secret Sharing with support for additive operations.

pub mod shamir;
pub mod additive;

pub use shamir::*;
pub use additive::*;

use serde::{Deserialize, Serialize};
use crate::{MpcError, Result};

// Using u64 finite field operations
pub const FIELD_PRIME: u64 = 2305843009213693951; // 2^61 - 1, a large prime

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Share {
    pub x: u64,  // party index
    pub y: u64,  // share value
}

impl Share {
    pub fn new(x: u64, y: u64) -> Self {
        Self { x, y }
    }
}

pub fn field_add(a: u64, b: u64) -> u64 {
    let sum = (a as u128 + b as u128) % FIELD_PRIME as u128;
    sum as u64
}

pub fn field_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        FIELD_PRIME - (b - a)
    }
}

pub fn field_mul(a: u64, b: u64) -> u64 {
    let product = (a as u128 * b as u128) % FIELD_PRIME as u128;
    product as u64
}

pub fn field_inv(a: u64) -> Option<u64> {
    extended_gcd(a, FIELD_PRIME).map(|(inv, _)| inv)
}

fn extended_gcd(a: u64, b: u64) -> Option<(u64, u64)> {
    if a == 0 {
        return Some((0, 1));
    }
    
    let (mut old_r, mut r) = (a as i128, b as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    let (mut old_t, mut t) = (0i128, 1i128);
    
    while r != 0 {
        let quotient = old_r / r;
        
        let temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;
        
        let temp_s = s;
        s = old_s - quotient * s;
        old_s = temp_s;
        
        let temp_t = t;
        t = old_t - quotient * t;
        old_t = temp_t;
    }
    
    if old_r == 1 {
        let result = if old_s < 0 {
            (old_s + b as i128) as u64
        } else {
            old_s as u64
        };
        Some((result, old_t as u64))
    } else {
        None
    }
}

pub trait SecretSharing {
    type Secret;
    type Share;
    
    fn share(secret: &Self::Secret, threshold: usize, total_parties: usize) -> Result<Vec<Self::Share>>;
    fn reconstruct(shares: &[Self::Share], threshold: usize) -> Result<Self::Secret>;
}

pub trait AdditiveSecretSharing: SecretSharing {
    fn add_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share>;
    fn sub_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share>;
    fn scalar_mul(share: &Self::Share, scalar: &Self::Secret) -> Result<Self::Share>;
}