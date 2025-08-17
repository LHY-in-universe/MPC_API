//! RSA encryption scheme (multiplicatively homomorphic)

use super::*;
// use crate::secret_sharing::{field_mul}; // Unused import
use rand::{Rng, thread_rng};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSAPublicKey {
    pub n: u64,  // n = p * q
    pub e: u64,  // public exponent
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSAPrivateKey {
    pub n: u64,  // n = p * q
    pub d: u64,  // private exponent
    pub p: u64,  // prime factor
    pub q: u64,  // prime factor
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSACiphertext {
    pub value: u64,
}

pub struct RSA;

impl RSA {
    fn mod_pow(base: u64, exp: u64, modulus: u64) -> u64 {
        if exp == 0 {
            return 1;
        }
        
        let mut result = 1u128;
        let mut base = (base as u128) % (modulus as u128);
        let mut exp = exp;
        
        while exp > 0 {
            if exp % 2 == 1 {
                result = (result * base) % (modulus as u128);
            }
            exp >>= 1;
            base = (base * base) % (modulus as u128);
        }
        
        (result % (modulus as u128)) as u64
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
    
    fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        if n == 2 {
            return true;
        }
        if n % 2 == 0 {
            return false;
        }
        
        let sqrt_n = (n as f64).sqrt() as u64;
        for i in (3..=sqrt_n).step_by(2) {
            if n % i == 0 {
                return false;
            }
        }
        true
    }
    
    fn generate_prime_near(target: u64) -> u64 {
        let mut candidate = target;
        while !Self::is_prime(candidate) {
            candidate += 1;
            if candidate > target + 1000 {
                candidate = target - 1;
                while candidate > 2 && !Self::is_prime(candidate) {
                    candidate -= 1;
                }
                break;
            }
        }
        candidate
    }
    
    fn gcd(a: u64, b: u64) -> u64 {
        if b == 0 {
            a
        } else {
            Self::gcd(b, a % b)
        }
    }
}

impl HomomorphicEncryption for RSA {
    type PlaintextSpace = u64;
    type CiphertextSpace = RSACiphertext;
    type PublicKey = RSAPublicKey;
    type PrivateKey = RSAPrivateKey;
    
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)> {
        let mut rng = thread_rng();
        
        // Generate two primes p and q
        let p = Self::generate_prime_near(rng.gen_range(100..200));
        let q = Self::generate_prime_near(rng.gen_range(200..300));
        
        if p == q {
            return Err(MpcError::CryptographicError("p and q must be different".to_string()));
        }
        
        let n = p * q;
        let phi_n = (p - 1) * (q - 1);
        
        // Choose e such that gcd(e, phi_n) = 1
        let mut e = 65537u64; // Common choice
        if e >= phi_n {
            e = 3; // Fallback for small keys
        }
        
        while Self::gcd(e, phi_n) != 1 {
            e += 2;
            if e >= phi_n {
                return Err(MpcError::CryptographicError("Cannot find suitable e".to_string()));
            }
        }
        
        // Compute d = e^(-1) mod phi_n
        let d = Self::mod_inverse(e, phi_n)?;
        
        let pk = RSAPublicKey { n, e };
        let sk = RSAPrivateKey { n, d, p, q };
        
        Ok((pk, sk))
    }
    
    fn encrypt(pk: &Self::PublicKey, plaintext: &Self::PlaintextSpace) -> Result<Self::CiphertextSpace> {
        if *plaintext >= pk.n {
            return Err(MpcError::CryptographicError("Plaintext too large".to_string()));
        }
        
        let ciphertext_value = Self::mod_pow(*plaintext, pk.e, pk.n);
        Ok(RSACiphertext { value: ciphertext_value })
    }
    
    fn decrypt(sk: &Self::PrivateKey, ciphertext: &Self::CiphertextSpace) -> Result<Self::PlaintextSpace> {
        let plaintext = Self::mod_pow(ciphertext.value, sk.d, sk.n);
        Ok(plaintext)
    }
}

impl MultiplicativelyHomomorphic for RSA {
    fn multiply_ciphertexts(
        pk: &Self::PublicKey,
        c1: &Self::CiphertextSpace,
        c2: &Self::CiphertextSpace,
    ) -> Result<Self::CiphertextSpace> {
        // RSA multiplication: E(m1) * E(m2) = E(m1 * m2)
        let result = ((c1.value as u128 * c2.value as u128) % pk.n as u128) as u64;
        Ok(RSACiphertext { value: result })
    }
    
    fn power(
        pk: &Self::PublicKey,
        ciphertext: &Self::CiphertextSpace,
        exponent: u64,
    ) -> Result<Self::CiphertextSpace> {
        let result = Self::mod_pow(ciphertext.value, exponent, pk.n);
        Ok(RSACiphertext { value: result })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rsa_keygen() {
        let result = RSA::keygen();
        assert!(result.is_ok());
        
        let (pk, sk) = result.unwrap();
        assert!(pk.n > 0);
        assert!(pk.e > 0);
        assert!(sk.d > 0);
        assert_eq!(pk.n, sk.n);
    }
    
    #[test]
    fn test_rsa_encrypt_decrypt() {
        let (pk, sk) = RSA::keygen().unwrap();
        let message = 42u64;
        
        if message < pk.n {
            let ciphertext = RSA::encrypt(&pk, &message).unwrap();
            let decrypted = RSA::decrypt(&sk, &ciphertext).unwrap();
            assert_eq!(message, decrypted);
        }
    }
    
    #[test]
    fn test_rsa_homomorphic_multiplication() {
        let (pk, sk) = RSA::keygen().unwrap();
        let m1 = 7u64;
        let m2 = 6u64;
        
        if m1 < pk.n && m2 < pk.n && (m1 * m2) < pk.n {
            let c1 = RSA::encrypt(&pk, &m1).unwrap();
            let c2 = RSA::encrypt(&pk, &m2).unwrap();
            
            let c_product = RSA::multiply_ciphertexts(&pk, &c1, &c2).unwrap();
            let decrypted_product = RSA::decrypt(&sk, &c_product).unwrap();
            
            assert_eq!(decrypted_product, m1 * m2);
        }
    }
}