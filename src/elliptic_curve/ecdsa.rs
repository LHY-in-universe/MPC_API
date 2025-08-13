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
            let k_inv = Self::mod_inverse(k, params.n)?;
            
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
        let w = Self::mod_inverse(signature.s, params.n)?;
        
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ecdsa_signature_creation() {
        let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
        let message_hash = 12345u64;
        
        let signature = ECDigitalSignature::sign(private_key, message_hash).unwrap();
        
        assert!(signature.r > 0);
        assert!(signature.s > 0);
        
        let verification = ECDigitalSignature::verify(&public_key, message_hash, &signature).unwrap();
        assert!(verification);
    }
    
    #[test]
    fn test_ecdsa_message_signing() {
        let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
        let message = b"Hello, ECDSA!";
        
        let signature = ECDigitalSignature::sign_message(message, private_key).unwrap();
        let verification = ECDigitalSignature::verify_message(message, &public_key, &signature).unwrap();
        
        assert!(verification);
    }
    
    #[test]
    fn test_ecdsa_invalid_signature() {
        let (_, public_key) = ECDigitalSignature::generate_keypair().unwrap();
        let message_hash = 12345u64;
        
        // Create invalid signature
        let invalid_signature = ECDSASignature { r: 1, s: 1 };
        
        let verification = ECDigitalSignature::verify(&public_key, message_hash, &invalid_signature).unwrap();
        assert!(!verification);
    }
    
    #[test]
    fn test_ecdsa_different_message() {
        let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
        let message1 = b"Message 1";
        let message2 = b"Message 2";
        
        let signature1 = ECDigitalSignature::sign_message(message1, private_key).unwrap();
        
        // Signature for message1 should not verify for message2
        let verification = ECDigitalSignature::verify_message(message2, &public_key, &signature1).unwrap();
        assert!(!verification);
        
        // But should verify for message1
        let verification = ECDigitalSignature::verify_message(message1, &public_key, &signature1).unwrap();
        assert!(verification);
    }
    
    #[test]
    fn test_ecdsa_wrong_public_key() {
        let (private_key1, _) = ECDigitalSignature::generate_keypair().unwrap();
        let (_, public_key2) = ECDigitalSignature::generate_keypair().unwrap();
        let message_hash = 12345u64;
        
        let signature = ECDigitalSignature::sign(private_key1, message_hash).unwrap();
        
        // Signature from private_key1 should not verify with public_key2
        let verification = ECDigitalSignature::verify(&public_key2, message_hash, &signature).unwrap();
        assert!(!verification);
    }
}