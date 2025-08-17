//! ElGamal encryption scheme (multiplicatively homomorphic)

use super::*;
use crate::secret_sharing::{FIELD_PRIME, field_mul};
use rand::{Rng, thread_rng};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalPublicKey {
    pub generator: u64,  // g
    pub public_key: u64, // g^x where x is the private key
    pub prime: u64,      // prime modulus
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalPrivateKey {
    pub private_key: u64, // x
    pub prime: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    pub c1: u64, // g^r
    pub c2: u64, // m * h^r where h = g^x
}

pub struct ElGamal;

impl ElGamal {
    fn mod_pow(base: u64, exp: u64, modulus: u64) -> u64 {
        if exp == 0 {
            return 1;
        }
        
        let mut result = 1u64;
        let mut base = base % modulus;
        let mut exp = exp;
        
        while exp > 0 {
            if exp % 2 == 1 {
                result = field_mul(result, base);
            }
            exp >>= 1;
            base = field_mul(base, base);
        }
        
        result
    }
    
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
}

impl HomomorphicEncryption for ElGamal {
    type PlaintextSpace = u64;
    type CiphertextSpace = ElGamalCiphertext;
    type PublicKey = ElGamalPublicKey;
    type PrivateKey = ElGamalPrivateKey;
    
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)> {
        let mut rng = thread_rng();
        let prime = FIELD_PRIME;
        let generator = 3u64; // Simple generator
        
        // Generate private key
        let private_key = rng.gen_range(1..prime);
        
        // Compute public key: g^x mod p
        let public_key = Self::mod_pow(generator, private_key, prime);
        
        let pk = ElGamalPublicKey {
            generator,
            public_key,
            prime,
        };
        
        let sk = ElGamalPrivateKey {
            private_key,
            prime,
        };
        
        Ok((pk, sk))
    }
    
    fn encrypt(pk: &Self::PublicKey, plaintext: &Self::PlaintextSpace) -> Result<Self::CiphertextSpace> {
        let mut rng = thread_rng();
        
        // Generate random r
        let r = rng.gen_range(1..pk.prime);
        
        // Compute c1 = g^r mod p
        let c1 = Self::mod_pow(pk.generator, r, pk.prime);
        
        // Compute c2 = m * h^r mod p where h = g^x
        let h_r = Self::mod_pow(pk.public_key, r, pk.prime);
        let c2 = field_mul(*plaintext, h_r);
        
        Ok(ElGamalCiphertext { c1, c2 })
    }
    
    fn decrypt(sk: &Self::PrivateKey, ciphertext: &Self::CiphertextSpace) -> Result<Self::PlaintextSpace> {
        // Compute s = c1^x mod p
        let s = Self::mod_pow(ciphertext.c1, sk.private_key, sk.prime);
        
        // Compute s^(-1) mod p
        let s_inv = Self::mod_inverse(s, sk.prime)?;
        
        // Recover plaintext: m = c2 * s^(-1) mod p
        let plaintext = field_mul(ciphertext.c2, s_inv);
        
        Ok(plaintext)
    }
}

impl MultiplicativelyHomomorphic for ElGamal {
    fn multiply_ciphertexts(
        _pk: &Self::PublicKey,
        c1: &Self::CiphertextSpace,
        c2: &Self::CiphertextSpace,
    ) -> Result<Self::CiphertextSpace> {
        // ElGamal multiplication: (g^r1, m1*h^r1) * (g^r2, m2*h^r2) = (g^(r1+r2), m1*m2*h^(r1+r2))
        let new_c1 = field_mul(c1.c1, c2.c1);
        let new_c2 = field_mul(c1.c2, c2.c2);
        
        Ok(ElGamalCiphertext {
            c1: new_c1,
            c2: new_c2,
        })
    }
    
    fn power(
        _pk: &Self::PublicKey,
        ciphertext: &Self::CiphertextSpace,
        exponent: u64,
    ) -> Result<Self::CiphertextSpace> {
        // Compute ciphertext^exponent
        let prime = FIELD_PRIME;
        let new_c1 = Self::mod_pow(ciphertext.c1, exponent, prime);
        let new_c2 = Self::mod_pow(ciphertext.c2, exponent, prime);
        
        Ok(ElGamalCiphertext {
            c1: new_c1,
            c2: new_c2,
        })
    }
}

// ElGamal utility functions
impl ElGamal {
    pub fn encrypt_zero(pk: &ElGamalPublicKey) -> Result<ElGamalCiphertext> {
        Self::encrypt(pk, &1u64) // Encrypt 1 (multiplicative identity)
    }
    
    pub fn randomize_ciphertext(
        pk: &ElGamalPublicKey,
        ciphertext: &ElGamalCiphertext,
    ) -> Result<ElGamalCiphertext> {
        // Re-randomize by multiplying with encryption of 1
        let zero_encryption = Self::encrypt_zero(pk)?;
        Self::multiply_ciphertexts(pk, ciphertext, &zero_encryption)
    }
    
    pub fn is_encryption_of_one(
        sk: &ElGamalPrivateKey,
        ciphertext: &ElGamalCiphertext,
    ) -> Result<bool> {
        let decrypted = Self::decrypt(sk, ciphertext)?;
        Ok(decrypted == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_elgamal_keygen() {
        let (pk, sk) = ElGamal::keygen().unwrap();
        
        assert!(pk.generator > 0);
        assert!(pk.public_key > 0);
        assert!(pk.prime > 0);
        assert!(sk.private_key > 0);
        assert_eq!(pk.prime, sk.prime);
    }
    
    #[test]
    fn test_elgamal_encrypt_decrypt() {
        let (pk, sk) = ElGamal::keygen().unwrap();
        let message = 42u64;
        
        let ciphertext = ElGamal::encrypt(&pk, &message).unwrap();
        let decrypted = ElGamal::decrypt(&sk, &ciphertext).unwrap();
        
        assert_eq!(message, decrypted);
    }
    
    #[test]
    fn test_elgamal_homomorphic_multiplication() {
        let (pk, sk) = ElGamal::keygen().unwrap();
        let m1 = 7u64;
        let m2 = 6u64;
        
        let c1 = ElGamal::encrypt(&pk, &m1).unwrap();
        let c2 = ElGamal::encrypt(&pk, &m2).unwrap();
        
        // Homomorphic multiplication
        let c_product = ElGamal::multiply_ciphertexts(&pk, &c1, &c2).unwrap();
        let decrypted_product = ElGamal::decrypt(&sk, &c_product).unwrap();
        
        assert_eq!(decrypted_product, field_mul(m1, m2));
    }
    
    #[test]
    fn test_elgamal_power() {
        let (pk, sk) = ElGamal::keygen().unwrap();
        let message = 3u64;
        let exponent = 4u64;
        
        let ciphertext = ElGamal::encrypt(&pk, &message).unwrap();
        let powered_ciphertext = ElGamal::power(&pk, &ciphertext, exponent).unwrap();
        let decrypted = ElGamal::decrypt(&sk, &powered_ciphertext).unwrap();
        
        let expected = ElGamal::mod_pow(message, exponent, FIELD_PRIME);
        assert_eq!(decrypted, expected);
    }
    
    #[test]
    fn test_elgamal_encrypt_zero() {
        let (pk, sk) = ElGamal::keygen().unwrap();
        
        let zero_encryption = ElGamal::encrypt_zero(&pk).unwrap();
        let decrypted = ElGamal::decrypt(&sk, &zero_encryption).unwrap();
        
        assert_eq!(decrypted, 1); // Multiplicative identity
    }
    
    #[test]
    fn test_elgamal_randomization() {
        let (pk, sk) = ElGamal::keygen().unwrap();
        let message = 123u64;
        
        let original_ciphertext = ElGamal::encrypt(&pk, &message).unwrap();
        let randomized_ciphertext = ElGamal::randomize_ciphertext(&pk, &original_ciphertext).unwrap();
        
        // Should decrypt to the same value
        let decrypted_original = ElGamal::decrypt(&sk, &original_ciphertext).unwrap();
        let decrypted_randomized = ElGamal::decrypt(&sk, &randomized_ciphertext).unwrap();
        
        assert_eq!(decrypted_original, decrypted_randomized);
        assert_eq!(decrypted_original, message);
        
        // But ciphertexts should be different (with high probability)
        assert_ne!(original_ciphertext.c1, randomized_ciphertext.c1);
        assert_ne!(original_ciphertext.c2, randomized_ciphertext.c2);
    }
    
    #[test]
    fn test_elgamal_multiple_multiplications() {
        let (pk, sk) = ElGamal::keygen().unwrap();
        let messages = vec![2u64, 3u64, 5u64];
        
        let mut ciphertexts = Vec::new();
        for &msg in &messages {
            ciphertexts.push(ElGamal::encrypt(&pk, &msg).unwrap());
        }
        
        // Multiply all ciphertexts together
        let mut product_ciphertext = ciphertexts[0].clone();
        for i in 1..ciphertexts.len() {
            product_ciphertext = ElGamal::multiply_ciphertexts(&pk, &product_ciphertext, &ciphertexts[i]).unwrap();
        }
        
        let decrypted_product = ElGamal::decrypt(&sk, &product_ciphertext).unwrap();
        
        // Expected product: 2 * 3 * 5 = 30
        let expected_product = messages.iter().fold(1u64, |acc, &x| field_mul(acc, x));
        assert_eq!(decrypted_product, expected_product);
    }
}