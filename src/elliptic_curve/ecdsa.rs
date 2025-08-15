//! Elliptic Curve Digital Signature Algorithm (ECDSA)

use super::*;
use rand::{Rng, thread_rng};
use crate::secret_sharing::FIELD_PRIME;

#[derive(Debug, Clone, PartialEq)]
pub struct ECDSASignature {
    pub r: u64,
    pub s: u64,
}

pub struct ECDigitalSignature;

impl ECDSA for ECDigitalSignature {
    type Signature = ECDSASignature;
    
    fn sign(private_key: u64, message_hash: u64) -> Result<Self::Signature> {
        let mut rng = thread_rng();
        let params = SimpleEC::params();
        
        loop {
            // Generate random k
            let k = rng.gen_range(1..params.n);
            
            // Compute r = (k * G).x mod n
            let k_point = SimpleEC::scalar_multiply(k, &params.g)?;
            if k_point.is_infinity() {
                continue;
            }
            
            let r = k_point.x % params.n;
            if r == 0 {
                continue;
            }
            
            // Compute k^(-1) mod n
            let k_inv = match Self::mod_inverse(k, params.n) {
                Ok(inv) => inv,
                Err(_) => continue, // If no inverse exists, try with a new k
            };
            
            // Compute s = k^(-1) * (hash + r * private_key) mod n
            let temp = (message_hash as u128 + ((r as u128 * private_key as u128) % params.n as u128)) % params.n as u128;
            let s = ((k_inv as u128 * temp) % params.n as u128) as u64;
            
            if s == 0 {
                continue;
            }
            
            return Ok(ECDSASignature { r, s });
        }
    }
    
    fn verify(public_key: &ECPoint, message_hash: u64, signature: &Self::Signature) -> Result<bool> {
        let params = SimpleEC::params();
        
        // Check signature validity
        if signature.r == 0 || signature.r >= params.n || signature.s == 0 || signature.s >= params.n {
            return Ok(false);
        }
        
        // Check if public key is on curve
        if !SimpleEC::is_on_curve(public_key) || public_key.is_infinity() {
            return Ok(false);
        }
        
        // Compute w = s^(-1) mod n
        let w = match Self::mod_inverse(signature.s, params.n) {
            Ok(inv) => inv,
            Err(_) => return Ok(false), // If no inverse exists, signature is invalid
        };
        
        // Compute u1 = hash * w mod n and u2 = r * w mod n
        let u1 = ((message_hash as u128 * w as u128) % params.n as u128) as u64;
        let u2 = ((signature.r as u128 * w as u128) % params.n as u128) as u64;
        
        // Compute point = u1 * G + u2 * public_key
        let u1_g = SimpleEC::scalar_multiply(u1, &params.g)?;
        let u2_pk = SimpleEC::scalar_multiply(u2, public_key)?;
        let point = SimpleEC::point_add(&u1_g, &u2_pk)?;
        
        if point.is_infinity() {
            return Ok(false);
        }
        
        // Check if point.x mod n == r
        Ok((point.x % params.n) == signature.r)
    }
}

impl ECDigitalSignature {
    fn mod_inverse(a: u64, modulus: u64) -> Result<u64> {
        let mut old_r = a as i128;
        let mut r = modulus as i128;
        let mut old_s = 1i128;
        let mut s = 0i128;
        
        while r != 0 {
            let quotient = old_r / r;
            let temp_r = r;
            r = old_r - quotient * r;
            old_r = temp_r;
            
            let temp_s = s;
            s = old_s - quotient * s;
            old_s = temp_s;
        }
        
        if old_r == 1 {
            let result = if old_s < 0 {
                (old_s + modulus as i128) as u64
            } else {
                old_s as u64
            };
            Ok(result)
        } else {
            Err(MpcError::CryptographicError("No modular inverse exists".to_string()))
        }
    }
    
    pub fn generate_keypair() -> Result<(u64, ECPoint)> {
        let mut rng = thread_rng();
        let params = SimpleEC::params();
        
        let private_key = rng.gen_range(1..params.n);
        let public_key = SimpleEC::scalar_multiply(private_key, &params.g)?;
        
        Ok((private_key, public_key))
    }
    
    pub fn sign_message(message: &[u8], private_key: u64) -> Result<ECDSASignature> {
        use sha2::{Sha256, Digest};
        
        // Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash_bytes = hasher.finalize();
        
        // Convert hash to u64 (simplified)
        let mut hash_u64 = 0u64;
        for (i, &byte) in hash_bytes.iter().take(8).enumerate() {
            hash_u64 |= (byte as u64) << (i * 8);
        }
        
        Self::sign(private_key, hash_u64 % FIELD_PRIME)
    }
    
    pub fn verify_message(message: &[u8], public_key: &ECPoint, signature: &ECDSASignature) -> Result<bool> {
        use sha2::{Sha256, Digest};
        
        // Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash_bytes = hasher.finalize();
        
        // Convert hash to u64 (simplified)
        let mut hash_u64 = 0u64;
        for (i, &byte) in hash_bytes.iter().take(8).enumerate() {
            hash_u64 |= (byte as u64) << (i * 8);
        }
        
        Self::verify(public_key, hash_u64 % FIELD_PRIME, signature)
    }
}

// Tests moved to tests/elliptic_curve_tests.rs
