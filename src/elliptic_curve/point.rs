//! Elliptic curve point operations

use super::*;

impl ECPoint {
    pub fn negate(&self) -> Self {
        if self.is_infinity {
            ECPoint::infinity()
        } else {
            ECPoint::new(self.x, SimpleEC::field_sub(0, self.y))
        }
    }
}

// Simplified elliptic curve for demonstration (y^2 = x^3 + 7 mod p)
pub struct SimpleEC;

impl SimpleEC {
    const A: u64 = 0;
    const B: u64 = 7;
    
    // Field arithmetic functions for the curve
    fn field_add(a: u64, b: u64) -> u64 {
        let p = Self::params().p;
        ((a as u128 + b as u128) % p as u128) as u64
    }
    
    fn field_sub(a: u64, b: u64) -> u64 {
        let p = Self::params().p;
        if a >= b {
            a - b
        } else {
            p - (b - a)
        }
    }
    
    fn field_mul(a: u64, b: u64) -> u64 {
        let p = Self::params().p;
        ((a as u128 * b as u128) % p as u128) as u64
    }
    
    // Removed unused helper functions: find_y_for_x, mod_sqrt, mod_pow, 
    // find_valid_generator_point, is_valid_point
    // These were used for dynamic point finding but we now use hardcoded values
    
    fn mod_inverse(a: u64) -> Result<u64> {
        let p = Self::params().p;
        Self::mod_inverse_with_prime(a, p)
    }
    
    fn mod_inverse_with_prime(a: u64, prime: u64) -> Result<u64> {
        // Extended Euclidean algorithm
        let mut old_r = a as i128;
        let mut r = prime as i128;
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
                (old_s + prime as i128) as u64
            } else {
                old_s as u64
            };
            Ok(result)
        } else {
            Err(MpcError::CryptographicError("No modular inverse exists".to_string()))
        }
    }
}

impl SimpleEC {
    // Helper functions for elliptic curve operations have been removed
    // as we're using a simplified approach with hardcoded parameters
}

impl EllipticCurve for SimpleEC {
    fn params() -> ECParams {
        // For testing, use a smaller prime to ensure elliptic curve operations work
        // In production, use proper curve parameters like secp256k1
        let test_prime = 97u64; // Small prime for testing
        let test_order = 79u64; // Actual order of the elliptic curve group (79 points total)
        
        // For y² = x³ + 7 (mod 97), use a valid point we found
        // Point (1, 28) is on the curve: 28² = 784 ≡ 8 (mod 97), and 1³ + 7 = 8
        let test_g = ECPoint::new(1, 28); // Valid point on curve y² = x³ + 7 (mod 97)
        
        ECParams {
            a: Self::A,
            b: Self::B,
            p: test_prime,
            n: test_order,
            g: test_g,
        }
    }
    
    fn point_add(p1: &ECPoint, p2: &ECPoint) -> Result<ECPoint> {
        // Handle point at infinity cases
        if p1.is_infinity {
            return Ok(p2.clone());
        }
        if p2.is_infinity {
            return Ok(p1.clone());
        }
        
        // Check if points are the same
        if p1.x == p2.x {
            if p1.y == p2.y {
                // Point doubling case
                return Self::point_double(p1);
            } else if p1.y == Self::field_sub(0, p2.y) {
                // Points are inverses of each other
                return Ok(ECPoint::infinity());
            }
        }
        
        // Point addition: slope = (y2 - y1) / (x2 - x1)
        let numerator = Self::field_sub(p2.y, p1.y);
        let denominator = Self::field_sub(p2.x, p1.x);
        
        if denominator == 0 {
            return Err(MpcError::CryptographicError("Cannot add points with same x-coordinate".to_string()));
        }
        
        let denominator_inv = Self::mod_inverse(denominator)?;
        let slope = Self::field_mul(numerator, denominator_inv);
        
        // x3 = slope^2 - x1 - x2
        let x3 = Self::field_sub(Self::field_sub(Self::field_mul(slope, slope), p1.x), p2.x);
        
        // y3 = slope * (x1 - x3) - y1
        let y3 = Self::field_sub(Self::field_mul(slope, Self::field_sub(p1.x, x3)), p1.y);
        
        Ok(ECPoint::new(x3, y3))
    }
    
    fn point_double(point: &ECPoint) -> Result<ECPoint> {
        if point.is_infinity {
            return Ok(ECPoint::infinity());
        }
        
        if point.y == 0 {
            return Ok(ECPoint::infinity());
        }
        
        // Point doubling: slope = (3*x^2 + a) / (2*y)
        let numerator = Self::field_add(Self::field_mul(3, Self::field_mul(point.x, point.x)), Self::A);
        let denominator = Self::field_mul(2, point.y);
        let denominator_inv = Self::mod_inverse(denominator)?;
        let slope = Self::field_mul(numerator, denominator_inv);
        
        // x3 = slope^2 - 2*x1
        let x3 = Self::field_sub(Self::field_mul(slope, slope), Self::field_mul(2, point.x));
        
        // y3 = slope * (x1 - x3) - y1
        let y3 = Self::field_sub(Self::field_mul(slope, Self::field_sub(point.x, x3)), point.y);
        
        Ok(ECPoint::new(x3, y3))
    }
    
    fn scalar_multiply(scalar: u64, point: &ECPoint) -> Result<ECPoint> {
        if scalar == 0 || point.is_infinity {
            return Ok(ECPoint::infinity());
        }
        
        if scalar == 1 {
            return Ok(point.clone());
        }
        
        // Double-and-add algorithm
        let mut result = ECPoint::infinity();
        let mut addend = point.clone();
        let mut k = scalar;
        
        while k > 0 {
            if k % 2 == 1 {
                result = Self::point_add(&result, &addend)?;
            }
            addend = Self::point_double(&addend)?;
            k /= 2;
        }
        
        Ok(result)
    }
    
    fn is_on_curve(point: &ECPoint) -> bool {
        if point.is_infinity {
            return true;
        }
        
        // Simplified curve check: y^2 = x^3 + 7 (mod p) since a = 0
        let p = Self::params().p as u128;
        let y_squared = ((point.y as u128) * (point.y as u128)) % p;
        let x_squared = ((point.x as u128) * (point.x as u128)) % p;
        let x_cubed = (x_squared * (point.x as u128)) % p;
        let right_side = (x_cubed + (Self::B as u128)) % p;
        
        y_squared == right_side
    }
}

// Tests moved to tests/elliptic_curve_tests.rs
