//! Additive Secret Sharing implementation
//! 
//! Implements simple additive secret sharing where the secret is split
//! into n random shares that sum to the original secret.
//! All operations are performed in u64 finite field.

use super::{FIELD_PRIME, field_add, field_sub, field_mul};
use crate::{MpcError, Result};
use rand::Rng;

pub struct AdditiveShare {
    pub party_id: usize,
    pub value: u64,
}

impl AdditiveShare {
    pub fn new(party_id: usize, value: u64) -> Self {
        Self { party_id, value }
    }
}

pub struct AdditiveSecretSharingScheme;

impl Default for AdditiveSecretSharingScheme {
    fn default() -> Self {
        Self::new()
    }
}

impl AdditiveSecretSharingScheme {
    pub fn new() -> Self {
        Self
    }
    
    pub fn share_additive(&self, secret: &u64, num_parties: usize) -> Result<Vec<AdditiveShare>> {
        if num_parties == 0 {
            return Err(MpcError::InvalidThreshold);
        }
        
        let mut rng = rand::thread_rng();
        let mut shares = Vec::with_capacity(num_parties);
        let mut sum = 0u64;
        
        // Generate n-1 random shares
        for i in 0..num_parties - 1 {
            let share_value = rng.gen_range(0..FIELD_PRIME);
            sum = field_add(sum, share_value);
            shares.push(AdditiveShare::new(i, share_value));
        }
        
        // Last share = secret - sum (mod prime)
        let last_share = field_sub(*secret, sum);
        shares.push(AdditiveShare::new(num_parties - 1, last_share));
        
        Ok(shares)
    }
    
    pub fn reconstruct_additive(&self, shares: &[AdditiveShare]) -> Result<u64> {
        if shares.is_empty() {
            return Err(MpcError::InsufficientShares);
        }
        
        let mut sum = 0u64;
        for share in shares {
            sum = field_add(sum, share.value);
        }
        
        Ok(sum)
    }
    
    pub fn add_additive_shares(&self, share1: &AdditiveShare, share2: &AdditiveShare) -> Result<AdditiveShare> {
        if share1.party_id != share2.party_id {
            return Err(MpcError::InvalidSecretShare);
        }
        
        let sum = field_add(share1.value, share2.value);
        Ok(AdditiveShare::new(share1.party_id, sum))
    }
    
    pub fn scalar_mul_additive(&self, share: &AdditiveShare, scalar: &u64) -> Result<AdditiveShare> {
        let product = field_mul(share.value, *scalar);
        Ok(AdditiveShare::new(share.party_id, product))
    }
}

