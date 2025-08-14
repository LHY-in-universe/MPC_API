//! Elliptic Curve Diffie-Hellman (ECDH) key exchange

use super::*;
use crate::secret_sharing::FIELD_PRIME;
use rand::{Rng, thread_rng};

pub struct ECDiffieHellman;

impl ECDH for ECDiffieHellman {
    fn generate_keypair() -> Result<(u64, ECPoint)> {
        let mut rng = thread_rng();
        let params = SimpleEC::params();
        
        // Generate random private key
        let private_key = rng.gen_range(1..params.n);
        
        // Compute public key = private_key * G
        let public_key = SimpleEC::scalar_multiply(private_key, &params.g)?;
        
        Ok((private_key, public_key))
    }
    
    fn compute_shared_secret(private_key: u64, public_key: &ECPoint) -> Result<ECPoint> {
        // Shared secret = private_key * public_key
        SimpleEC::scalar_multiply(private_key, public_key)
    }
}

// ECDH utility functions
impl ECDiffieHellman {
    pub fn perform_key_exchange(
        alice_private: u64,
        bob_private: u64,
    ) -> Result<(ECPoint, ECPoint, ECPoint)> {
        let params = SimpleEC::params();
        
        // Alice computes her public key
        let alice_public = SimpleEC::scalar_multiply(alice_private, &params.g)?;
        
        // Bob computes his public key
        let bob_public = SimpleEC::scalar_multiply(bob_private, &params.g)?;
        
        // Alice computes shared secret using Bob's public key
        let alice_shared = Self::compute_shared_secret(alice_private, &bob_public)?;
        
        // Bob computes shared secret using Alice's public key
        let bob_shared = Self::compute_shared_secret(bob_private, &alice_public)?;
        
        // The shared secrets should be equal
        if alice_shared != bob_shared {
            return Err(MpcError::CryptographicError("ECDH shared secrets don't match".to_string()));
        }
        
        Ok((alice_public, bob_public, alice_shared))
    }
    
    pub fn derive_key_from_shared_secret(shared_secret: &ECPoint) -> Result<[u8; 32]> {
        use sha2::{Sha256, Digest};
        
        if shared_secret.is_infinity() {
            return Err(MpcError::CryptographicError("Invalid shared secret".to_string()));
        }
        
        // Hash the x-coordinate of the shared secret point
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.x.to_le_bytes());
        hasher.update(shared_secret.y.to_le_bytes());
        
        Ok(hasher.finalize().into())
    }
    
    pub fn key_agreement_protocol() -> Result<([u8; 32], [u8; 32])> {
        // Generate keypairs for both parties
        let (alice_private, alice_public) = Self::generate_keypair()?;
        let (bob_private, bob_public) = Self::generate_keypair()?;
        
        // Compute shared secrets
        let alice_shared = Self::compute_shared_secret(alice_private, &bob_public)?;
        let bob_shared = Self::compute_shared_secret(bob_private, &alice_public)?;
        
        // Derive symmetric keys
        let alice_key = Self::derive_key_from_shared_secret(&alice_shared)?;
        let bob_key = Self::derive_key_from_shared_secret(&bob_shared)?;
        
        Ok((alice_key, bob_key))
    }
}

// ECDH for specific curve implementations
pub struct Curve25519ECDH;

impl Curve25519ECDH {
    // Simplified Curve25519 implementation (not cryptographically secure)
    pub fn generate_keypair_curve25519() -> Result<(u64, u64)> {
        let mut rng = thread_rng();
        let private_key = rng.gen_range(1..FIELD_PRIME);
        
        // In real Curve25519, this would be x25519(private_key, basepoint)
        // Here we use a simplified version
        let public_key = Self::curve25519_scalar_mult(private_key, 9)?; // 9 is the basepoint
        
        Ok((private_key, public_key))
    }
    
    pub fn compute_shared_secret_curve25519(private_key: u64, public_key: u64) -> Result<u64> {
        Self::curve25519_scalar_mult(private_key, public_key)
    }
    
    // Simplified scalar multiplication for Curve25519 (Montgomery form)
    fn curve25519_scalar_mult(scalar: u64, u_coordinate: u64) -> Result<u64> {
        // This is a highly simplified version
        // Real Curve25519 uses Montgomery ladder on the curve equation
        let mut result = 1u64;
        let mut base = u_coordinate;
        let mut k = scalar;
        
        while k > 0 {
            if k % 2 == 1 {
                result = ((result as u128 * base as u128) % FIELD_PRIME as u128) as u64;
            }
            base = ((base as u128 * base as u128) % FIELD_PRIME as u128) as u64;
            k /= 2;
        }
        
        Ok(result)
    }
}

// Tests moved to tests/elliptic_curve_tests.rs