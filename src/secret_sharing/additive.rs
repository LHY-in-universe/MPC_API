//! Additive Secret Sharing implementation
//! 
//! Implements simple additive secret sharing where the secret is split
//! into n random shares that sum to the original secret.
//! All operations are performed in u64 finite field.

use super::{Share, SecretSharing, AdditiveSecretSharing, FIELD_PRIME, field_add, field_sub, field_mul};
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_additive_secret_sharing() {
        let scheme = AdditiveSecretSharingScheme::new();
        let secret = 1000u64;
        let num_parties = 5;
        
        let shares = scheme.share_additive(&secret, num_parties).unwrap();
        assert_eq!(shares.len(), num_parties);
        
        let reconstructed = scheme.reconstruct_additive(&shares).unwrap();
        assert_eq!(secret, reconstructed);
    }
    
    #[test]
    fn test_additive_operations() {
        let scheme = AdditiveSecretSharingScheme::new();
        let secret1 = 100u64;
        let secret2 = 200u64;
        let num_parties = 3;
        
        let shares1 = scheme.share_additive(&secret1, num_parties).unwrap();
        let shares2 = scheme.share_additive(&secret2, num_parties).unwrap();
        
        // Test addition
        let mut sum_shares = Vec::new();
        for i in 0..num_parties {
            let sum_share = scheme.add_additive_shares(&shares1[i], &shares2[i]).unwrap();
            sum_shares.push(sum_share);
        }
        
        let sum_result = scheme.reconstruct_additive(&sum_shares).unwrap();
        assert_eq!(sum_result, field_add(secret1, secret2));
        
        // Test scalar multiplication
        let scalar = 3u64;
        let mut scaled_shares = Vec::new();
        for share in &shares1 {
            let scaled_share = scheme.scalar_mul_additive(share, &scalar).unwrap();
            scaled_shares.push(scaled_share);
        }
        
        let scaled_result = scheme.reconstruct_additive(&scaled_shares).unwrap();
        assert_eq!(scaled_result, field_mul(secret1, scalar));
    }
}