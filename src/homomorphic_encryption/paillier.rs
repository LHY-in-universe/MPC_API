//! Paillier encryption scheme (additively homomorphic)

use super::*;
// use crate::secret_sharing::{field_add, field_mul}; // Unused imports
use rand::{Rng, thread_rng};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    pub n: u64,      // n = p * q
    pub n_squared: u64, // n^2
    pub g: u64,      // generator
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierPrivateKey {
    pub lambda: u64, // lcm(p-1, q-1)
    pub mu: u64,     // (L(g^lambda mod n^2))^(-1) mod n
    pub n: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierCiphertext {
    pub value: u64,
}

pub struct Paillier;

impl Paillier {
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
    
    fn gcd(a: u64, b: u64) -> u64 {
        if b == 0 {
            a
        } else {
            Self::gcd(b, a % b)
        }
    }
    
    fn lcm(a: u64, b: u64) -> u64 {
        (a * b) / Self::gcd(a, b)
    }
    
    fn l_function(x: u64, n: u64) -> u64 {
        (x - 1) / n
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
}

impl HomomorphicEncryption for Paillier {
    type PlaintextSpace = u64;
    type CiphertextSpace = PaillierCiphertext;
    type PublicKey = PaillierPublicKey;
    type PrivateKey = PaillierPrivateKey;
    
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)> {
        let mut rng = thread_rng();
        
        // Generate two primes p and q (simplified for demonstration)
        let p = Self::generate_prime_near(rng.gen_range(1000..2000));
        let q = Self::generate_prime_near(rng.gen_range(2000..3000));
        
        if p == q {
            return Err(MpcError::CryptographicError("p and q must be different".to_string()));
        }
        
        let n = p * q;
        let n_squared = n * n;
        
        // Compute lambda = lcm(p-1, q-1)
        let lambda = Self::lcm(p - 1, q - 1);
        
        // Choose g (simplified: g = n + 1)
        let g = n + 1;
        
        // Compute mu = (L(g^lambda mod n^2))^(-1) mod n
        let g_lambda = Self::mod_pow(g, lambda, n_squared);
        let l_value = Self::l_function(g_lambda, n);
        let mu = Self::mod_inverse(l_value, n)?;
        
        let pk = PaillierPublicKey {
            n,
            n_squared,
            g,
        };
        
        let sk = PaillierPrivateKey {
            lambda,
            mu,
            n,
        };
        
        Ok((pk, sk))
    }
    
    fn encrypt(pk: &Self::PublicKey, plaintext: &Self::PlaintextSpace) -> Result<Self::CiphertextSpace> {
        let mut rng = thread_rng();
        
        // Generate random r coprime to n
        let mut r = rng.gen_range(1..pk.n);
        while Self::gcd(r, pk.n) != 1 {
            r = rng.gen_range(1..pk.n);
        }
        
        // Compute c = g^m * r^n mod n^2
        let g_m = Self::mod_pow(pk.g, *plaintext, pk.n_squared);
        let r_n = Self::mod_pow(r, pk.n, pk.n_squared);
        let c = ((g_m as u128 * r_n as u128) % pk.n_squared as u128) as u64;
        
        Ok(PaillierCiphertext { value: c })
    }
    
    fn decrypt(sk: &Self::PrivateKey, ciphertext: &Self::CiphertextSpace) -> Result<Self::PlaintextSpace> {
        let n_squared = sk.n * sk.n;
        
        // Compute c^lambda mod n^2
        let c_lambda = Self::mod_pow(ciphertext.value, sk.lambda, n_squared);
        
        // Compute L(c^lambda mod n^2)
        let l_value = Self::l_function(c_lambda, sk.n);
        
        // Compute m = L(c^lambda mod n^2) * mu mod n
        let plaintext = ((l_value as u128 * sk.mu as u128) % sk.n as u128) as u64;
        
        Ok(plaintext)
    }
}

impl AdditivelyHomomorphic for Paillier {
    fn add_ciphertexts(
        pk: &Self::PublicKey,
        c1: &Self::CiphertextSpace,
        c2: &Self::CiphertextSpace,
    ) -> Result<Self::CiphertextSpace> {
        // Paillier addition: E(m1) * E(m2) = E(m1 + m2)
        let result = ((c1.value as u128 * c2.value as u128) % pk.n_squared as u128) as u64;
        Ok(PaillierCiphertext { value: result })
    }
    
    fn scalar_multiply(
        pk: &Self::PublicKey,
        ciphertext: &Self::CiphertextSpace,
        scalar: &Self::PlaintextSpace,
    ) -> Result<Self::CiphertextSpace> {
        // Paillier scalar multiplication: E(m)^k = E(k*m)
        let result = Self::mod_pow(ciphertext.value, *scalar, pk.n_squared);
        Ok(PaillierCiphertext { value: result })
    }
}

// Paillier utility functions
impl Paillier {
    pub fn encrypt_zero(pk: &PaillierPublicKey) -> Result<PaillierCiphertext> {
        Self::encrypt(pk, &0u64)
    }
    
    pub fn negate_ciphertext(
        pk: &PaillierPublicKey,
        ciphertext: &PaillierCiphertext,
    ) -> Result<PaillierCiphertext> {
        // To negate: multiply by encryption of (n-1) which represents -1 mod n
        let neg_one = pk.n - 1;
        Self::scalar_multiply(pk, ciphertext, &neg_one)
    }
    
    pub fn subtract_ciphertexts(
        pk: &PaillierPublicKey,
        c1: &PaillierCiphertext,
        c2: &PaillierCiphertext,
    ) -> Result<PaillierCiphertext> {
        // Subtraction: E(m1) - E(m2) = E(m1) * E(-m2)
        let neg_c2 = Self::negate_ciphertext(pk, c2)?;
        Self::add_ciphertexts(pk, c1, &neg_c2)
    }
    
    pub fn randomize_ciphertext(
        pk: &PaillierPublicKey,
        ciphertext: &PaillierCiphertext,
    ) -> Result<PaillierCiphertext> {
        // Re-randomize by adding encryption of 0
        let zero_encryption = Self::encrypt_zero(pk)?;
        Self::add_ciphertexts(pk, ciphertext, &zero_encryption)
    }
}

