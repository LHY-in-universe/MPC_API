//! Shamir's Secret Sharing implementation
//! 
//! Implements the classic (t, n)-threshold secret sharing scheme where
//! any t shares can reconstruct the secret, but t-1 shares reveal nothing.
//! All operations are performed in u64 finite field.

use super::{Share, SecretSharing, AdditiveSecretSharing, FIELD_PRIME, field_add, field_sub, field_mul, field_inv};
use crate::{MpcError, Result};
use rand::Rng;
// use serde::{Deserialize, Serialize}; // Commented out unused imports

pub struct ShamirSecretSharing;

impl Default for ShamirSecretSharing {
    fn default() -> Self {
        Self::new()
    }
}

impl ShamirSecretSharing {
    pub fn new() -> Self {
        Self
    }
    
    fn evaluate_polynomial(&self, coefficients: &[u64], x: u64) -> u64 {
        let mut result = 0u64;
        let mut x_power = 1u64;
        
        for &coeff in coefficients {
            result = field_add(result, field_mul(coeff, x_power));
            x_power = field_mul(x_power, x);
        }
        
        result
    }
    
    fn lagrange_interpolation(&self, shares: &[Share]) -> Result<u64> {
        if shares.is_empty() {
            return Err(MpcError::InsufficientShares);
        }
        
        let mut result = 0u64;
        
        // 拉格朗日插值：计算在x=0处的多项式值
        for i in 0..shares.len() {
            let mut numerator = 1u64;
            let mut denominator = 1u64;
            
            // 计算拉格朗日基函数 L_i(0) = ∏(0-x_j)/(x_i-x_j) for j≠i
            for j in 0..shares.len() {
                if i != j {
                    // 分子：(0 - x_j) = (-x_j) = field_sub(0, x_j)
                    let neg_xj = field_sub(0, shares[j].x);
                    numerator = field_mul(numerator, neg_xj);
                    
                    // 分母：(x_i - x_j)
                    let diff = field_sub(shares[i].x, shares[j].x);
                    denominator = field_mul(denominator, diff);
                }
            }
            
            let denominator_inv = field_inv(denominator)
                .ok_or_else(|| MpcError::CryptographicError("No modular inverse exists".to_string()))?;
            let lagrange_coeff = field_mul(numerator, denominator_inv);
            
            result = field_add(result, field_mul(shares[i].y, lagrange_coeff));
        }
        
        Ok(result)
    }
}

impl SecretSharing for ShamirSecretSharing {
    type Secret = u64;
    type Share = Share;
    
    fn share(secret: &Self::Secret, threshold: usize, total_parties: usize) -> Result<Vec<Self::Share>> {
        if threshold == 0 || threshold > total_parties {
            return Err(MpcError::InvalidThreshold);
        }
        
        let sss = Self::new();
        let mut rng = rand::thread_rng();
        
        // Generate random coefficients for polynomial of degree (threshold - 1)
        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(*secret); // a_0 = secret
        
        for _ in 1..threshold {
            let coeff = rng.gen_range(0..FIELD_PRIME);
            coefficients.push(coeff);
        }
        
        // Evaluate polynomial at points 1, 2, ..., total_parties
        let mut shares = Vec::with_capacity(total_parties);
        for i in 1..=total_parties {
            let x = i as u64;
            let y = sss.evaluate_polynomial(&coefficients, x);
            shares.push(Share::new(x, y));
        }
        
        Ok(shares)
    }
    
    fn reconstruct(shares: &[Self::Share], threshold: usize) -> Result<Self::Secret> {
        if shares.len() < threshold {
            return Err(MpcError::InsufficientShares);
        }
        
        let sss = Self::new();
        let shares_subset = &shares[..threshold];
        sss.lagrange_interpolation(shares_subset)
    }
}

impl AdditiveSecretSharing for ShamirSecretSharing {
    fn add_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share> {
        if share1.x != share2.x {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let y = field_add(share1.y, share2.y);
        Ok(Share::new(share1.x, y))
    }
    
    fn sub_shares(share1: &Self::Share, share2: &Self::Share) -> Result<Self::Share> {
        if share1.x != share2.x {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let y = field_sub(share1.y, share2.y);
        Ok(Share::new(share1.x, y))
    }
    
    fn scalar_mul(share: &Self::Share, scalar: &Self::Secret) -> Result<Self::Share> {
        let y = field_mul(share.y, *scalar);
        Ok(Share::new(share.x, y))
    }
}

