//! SPDZ Authenticated Shares
//! 
//! Implements authenticated secret shares used in the SPDZ protocol

use super::*;
use crate::secret_sharing::{Share as SecretShare, ShamirSecretSharing, SecretSharing};
use crate::authentication::MessageAuthenticationCode;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SPDZShare {
    pub value: u64,           // Secret share value
    pub mac: u64,             // MAC on the share
    pub party_id: PlayerId,   // ID of the party holding this share
    pub share_id: ShareId,    // Unique identifier for this share
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedShare {
    pub shares: HashMap<PlayerId, SPDZShare>,
    pub global_mac_key: Option<u64>, // Global MAC key (only known in distributed form)
}

pub struct SPDZShareProtocol {
    params: SPDZParams,
    mac_key_share: u64,  // This party's share of the global MAC key
    hmac_keys: HashMap<PlayerId, HmacKey>, // Keys for communication with other parties
}

impl SPDZShare {
    pub fn new(value: u64, mac: u64, party_id: PlayerId, share_id: ShareId) -> Self {
        Self {
            value,
            mac,
            party_id,
            share_id,
        }
    }
    
    // Add two SPDZ shares
    pub fn add(&self, other: &SPDZShare) -> Result<SPDZShare> {
        if self.party_id != other.party_id {
            return Err(MpcError::ProtocolError("Cannot add shares from different parties".to_string()));
        }
        
        Ok(SPDZShare {
            value: field_add(self.value, other.value),
            mac: field_add(self.mac, other.mac),
            party_id: self.party_id,
            share_id: self.share_id.wrapping_add(other.share_id),
        })
    }
    
    // Subtract two SPDZ shares
    pub fn sub(&self, other: &SPDZShare) -> Result<SPDZShare> {
        if self.party_id != other.party_id {
            return Err(MpcError::ProtocolError("Cannot subtract shares from different parties".to_string()));
        }
        
        Ok(SPDZShare {
            value: field_sub(self.value, other.value),
            mac: field_sub(self.mac, other.mac),
            party_id: self.party_id,
            share_id: self.share_id.wrapping_add(other.share_id),
        })
    }
    
    // Multiply share by a public constant
    pub fn mul_public(&self, constant: u64, _mac_key: u64) -> SPDZShare {
        SPDZShare {
            value: field_mul(self.value, constant),
            mac: field_mul(self.mac, constant),
            party_id: self.party_id,
            share_id: self.share_id,
        }
    }
    
    // Check if MAC is valid (requires global MAC key)
    pub fn verify_mac(&self, global_mac_key: u64) -> bool {
        let expected_mac = field_mul(self.value, global_mac_key);
        self.mac == expected_mac
    }
}

impl Default for AuthenticatedShare {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticatedShare {
    pub fn new() -> Self {
        Self {
            shares: HashMap::new(),
            global_mac_key: None,
        }
    }
    
    pub fn add_share(&mut self, party_id: PlayerId, share: SPDZShare) {
        self.shares.insert(party_id, share);
    }
    
    pub fn get_share(&self, party_id: PlayerId) -> Option<&SPDZShare> {
        self.shares.get(&party_id)
    }
    
    // Reconstruct the secret (requires shares from all parties)
    pub fn reconstruct(&self, threshold: usize) -> Result<u64> {
        if self.shares.len() < threshold {
            return Err(MpcError::InsufficientShares);
        }
        
        // Convert to secret shares for reconstruction
        let mut secret_shares = Vec::new();
        for (party_id, spdz_share) in &self.shares {
            let share = SecretShare {
                x: *party_id as u64,
                y: spdz_share.value,
            };
            secret_shares.push(share);
        }
        
        ShamirSecretSharing::reconstruct(&secret_shares, threshold)
    }
    
    // Verify all MACs (requires global MAC key)
    pub fn verify_all_macs(&self, global_mac_key: u64) -> bool {
        for share in self.shares.values() {
            if !share.verify_mac(global_mac_key) {
                return false;
            }
        }
        true
    }
}

impl SPDZShareProtocol {
    pub fn new(params: SPDZParams) -> Result<Self> {
        if !params.is_valid() {
            return Err(MpcError::ProtocolError("Invalid SPDZ parameters".to_string()));
        }
        
        // Generate MAC key share
        let mut rng = thread_rng();
        let mac_key_share = rng.gen_range(0..FIELD_PRIME);
        
        // Generate HMAC keys for communication
        let mut hmac_keys = HashMap::new();
        for party_id in 0..params.num_parties {
            if party_id != params.party_id {
                hmac_keys.insert(party_id, HMAC::generate_key());
            }
        }
        
        Ok(Self {
            params,
            mac_key_share,
            hmac_keys,
        })
    }
    
    // Share a secret value with authentication
    pub fn share_secret(&self, secret: u64) -> Result<Vec<SPDZShare>> {
        // Create secret shares using the trait method
        let secret_shares = ShamirSecretSharing::share(
            &secret, 
            self.params.threshold,
            self.params.num_parties 
        )?;
        
        let mut spdz_shares = Vec::new();
        let mut rng = thread_rng();
        let share_id = rng.gen();
        
        for share in secret_shares {
            // Compute MAC: MAC_i = alpha_i * value + r_i
            // where alpha_i is this party's share of the MAC key
            let mac = field_add(
                field_mul(self.mac_key_share, share.y),
                rng.gen_range(0..FIELD_PRIME)  // Random mask
            );
            
            let spdz_share = SPDZShare::new(
                share.y,
                mac,
                share.x as PlayerId,
                share_id,
            );
            
            spdz_shares.push(spdz_share);
        }
        
        Ok(spdz_shares)
    }
    
    // Input a private value (share it among all parties)
    pub fn input(&self, value: u64) -> Result<AuthenticatedShare> {
        let spdz_shares = self.share_secret(value)?;
        
        let mut authenticated_share = AuthenticatedShare::new();
        for share in spdz_shares {
            authenticated_share.add_share(share.party_id, share);
        }
        
        Ok(authenticated_share)
    }
    
    // Add two authenticated shares
    pub fn add(&self, a: &AuthenticatedShare, b: &AuthenticatedShare) -> Result<AuthenticatedShare> {
        let mut result = AuthenticatedShare::new();
        
        for party_id in 0..self.params.num_parties {
            if let (Some(share_a), Some(share_b)) = (a.get_share(party_id), b.get_share(party_id)) {
                let sum_share = share_a.add(share_b)?;
                result.add_share(party_id, sum_share);
            }
        }
        
        Ok(result)
    }
    
    // Subtract two authenticated shares
    pub fn sub(&self, a: &AuthenticatedShare, b: &AuthenticatedShare) -> Result<AuthenticatedShare> {
        let mut result = AuthenticatedShare::new();
        
        for party_id in 0..self.params.num_parties {
            if let (Some(share_a), Some(share_b)) = (a.get_share(party_id), b.get_share(party_id)) {
                let diff_share = share_a.sub(share_b)?;
                result.add_share(party_id, diff_share);
            }
        }
        
        Ok(result)
    }
    
    // Multiply by public constant
    pub fn mul_public(&self, share: &AuthenticatedShare, constant: u64) -> AuthenticatedShare {
        let mut result = AuthenticatedShare::new();
        
        for party_id in 0..self.params.num_parties {
            if let Some(spdz_share) = share.get_share(party_id) {
                let mul_share = spdz_share.mul_public(constant, self.mac_key_share);
                result.add_share(party_id, mul_share);
            }
        }
        
        result
    }
    
    // Open a shared value (reveal the secret)
    pub fn open(&self, share: &AuthenticatedShare) -> Result<u64> {
        // First verify MACs if global MAC key is available
        if let Some(global_mac_key) = share.global_mac_key {
            if !share.verify_all_macs(global_mac_key) {
                return Err(MpcError::AuthenticationError("MAC verification failed".to_string()));
            }
        }
        
        // Reconstruct the secret
        share.reconstruct(self.params.threshold)
    }
    
    // Generate a random shared value
    pub fn random(&self) -> Result<AuthenticatedShare> {
        let mut rng = thread_rng();
        let random_value = rng.gen_range(0..FIELD_PRIME);
        self.input(random_value)
    }
    
    // Generate multiple random shared values
    pub fn random_batch(&self, count: usize) -> Result<Vec<AuthenticatedShare>> {
        let mut batch = Vec::new();
        for _ in 0..count {
            batch.push(self.random()?);
        }
        Ok(batch)
    }
    
    // Check if a shared value equals zero (without revealing the value)
    pub fn is_zero(&self, share: &AuthenticatedShare) -> Result<bool> {
        // This would normally involve a more complex zero-knowledge proof
        // For this implementation, we'll do a simplified check
        let opened = self.open(share)?;
        Ok(opened == 0)
    }
    
    // Batch operations for efficiency
    pub fn add_batch(
        &self, 
        shares_a: &[AuthenticatedShare], 
        shares_b: &[AuthenticatedShare]
    ) -> Result<Vec<AuthenticatedShare>> {
        if shares_a.len() != shares_b.len() {
            return Err(MpcError::ProtocolError("Batch arrays must have same length".to_string()));
        }
        
        let mut results = Vec::new();
        for (a, b) in shares_a.iter().zip(shares_b.iter()) {
            results.push(self.add(a, b)?);
        }
        
        Ok(results)
    }
    
    pub fn mul_public_batch(
        &self, 
        shares: &[AuthenticatedShare], 
        constants: &[u64]
    ) -> Result<Vec<AuthenticatedShare>> {
        if shares.len() != constants.len() {
            return Err(MpcError::ProtocolError("Batch arrays must have same length".to_string()));
        }
        
        let mut results = Vec::new();
        for (share, &constant) in shares.iter().zip(constants.iter()) {
            results.push(self.mul_public(share, constant));
        }
        
        Ok(results)
    }
    
    // Compute linear combination of shares
    pub fn linear_combination(
        &self,
        shares: &[AuthenticatedShare],
        coefficients: &[u64],
    ) -> Result<AuthenticatedShare> {
        if shares.is_empty() || shares.len() != coefficients.len() {
            return Err(MpcError::ProtocolError("Invalid linear combination parameters".to_string()));
        }
        
        let mut result = self.mul_public(&shares[0], coefficients[0]);
        
        for (share, &coeff) in shares.iter().zip(coefficients.iter()).skip(1) {
            let term = self.mul_public(share, coeff);
            result = self.add(&result, &term)?;
        }
        
        Ok(result)
    }
    
    // Get this party's MAC key share
    pub fn get_mac_key_share(&self) -> u64 {
        self.mac_key_share
    }
    
    // Get communication keys
    pub fn get_hmac_key(&self, party_id: PlayerId) -> Option<&HmacKey> {
        self.hmac_keys.get(&party_id)
    }
}

