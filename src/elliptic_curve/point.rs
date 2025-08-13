//! Elliptic curve point operations

use super::*;
use crate::secret_sharing::{FIELD_PRIME, field_add, field_sub, field_mul};

impl ECPoint {
    pub fn negate(&self) -> Self {
        if self.is_infinity {
            ECPoint::infinity()
        } else {
            ECPoint::new(self.x, field_sub(0, self.y))
        }
    }
}

// Simplified elliptic curve for demonstration (y^2 = x^3 + 7 mod p)
pub struct SimpleEC;

impl SimpleEC {
    const A: u64 = 0;
    const B: u64 = 7;
    
    fn mod_inverse(a: u64) -> Result<u64> {
        // Extended Euclidean algorithm
        let mut old_r = a as i128;
        let mut r = FIELD_PRIME as i128;
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
                (old_s + FIELD_PRIME as i128) as u64
            } else {
                old_s as u64
            };
            Ok(result)
        } else {
            Err(MpcError::CryptographicError("No modular inverse exists".to_string()))
        }
    }
}

impl EllipticCurve for SimpleEC {
    fn params() -> ECParams {
        // Using a simple generator point (this should be chosen more carefully in practice)
        let g = ECPoint::new(2, 3); // This is just an example
        
        ECParams {
            a: Self::A,
            b: Self::B,
            p: FIELD_PRIME,
            n: FIELD_PRIME - 1, // Simplified order
            g,
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
        
        // Check if points are inverses of each other
        if p1.x == p2.x && p1.y == field_sub(0, p2.y) {
            return Ok(ECPoint::infinity());
        }
        
        let slope = if p1.x == p2.x && p1.y == p2.y {
            // Point doubling: slope = (3*x^2 + a) / (2*y)
            let numerator = field_add(field_mul(3, field_mul(p1.x, p1.x)), Self::A);
            let denominator = field_mul(2, p1.y);
            let denominator_inv = Self::mod_inverse(denominator)?;
            field_mul(numerator, denominator_inv)
        } else {
            // Point addition: slope = (y2 - y1) / (x2 - x1)
            let numerator = field_sub(p2.y, p1.y);
            let denominator = field_sub(p2.x, p1.x);
            let denominator_inv = Self::mod_inverse(denominator)?;
            field_mul(numerator, denominator_inv)
        };
        
        // x3 = slope^2 - x1 - x2
        let x3 = field_sub(field_sub(field_mul(slope, slope), p1.x), p2.x);
        
        // y3 = slope * (x1 - x3) - y1
        let y3 = field_sub(field_mul(slope, field_sub(p1.x, x3)), p1.y);
        
        Ok(ECPoint::new(x3, y3))
    }
    
    fn point_double(point: &ECPoint) -> Result<ECPoint> {
        Self::point_add(point, point)
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
        
        // Check if y^2 = x^3 + ax + b (mod p)
        let left = field_mul(point.y, point.y);
        let right = field_add(
            field_add(
                field_mul(field_mul(point.x, point.x), point.x),
                field_mul(Self::A, point.x)
            ),
            Self::B
        );
        
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_point_infinity() {
        let inf = ECPoint::infinity();
        assert!(inf.is_infinity());
        
        let p = ECPoint::new(1, 2);
        assert!(!p.is_infinity());
    }
    
    #[test]
    fn test_point_negate() {
        let p = ECPoint::new(5, 10);
        let neg_p = p.negate();
        
        assert_eq!(neg_p.x, p.x);
        assert_eq!(neg_p.y, field_sub(0, p.y));
    }
    
    #[test]
    fn test_point_addition_with_infinity() {
        let p = ECPoint::new(3, 4);
        let inf = ECPoint::infinity();
        
        let result1 = SimpleEC::point_add(&p, &inf).unwrap();
        let result2 = SimpleEC::point_add(&inf, &p).unwrap();
        
        assert_eq!(result1, p);
        assert_eq!(result2, p);
    }
    
    #[test]
    fn test_scalar_multiplication() {
        let p = ECPoint::new(2, 3);
        
        // 0 * P = O (point at infinity)
        let result = SimpleEC::scalar_multiply(0, &p).unwrap();
        assert!(result.is_infinity());
        
        // 1 * P = P
        let result = SimpleEC::scalar_multiply(1, &p).unwrap();
        assert_eq!(result, p);
        
        // 2 * P = P + P
        let doubled = SimpleEC::point_double(&p).unwrap();
        let result = SimpleEC::scalar_multiply(2, &p).unwrap();
        assert_eq!(result, doubled);
    }
    
    #[test]
    fn test_ec_params() {
        let params = SimpleEC::params();
        
        assert_eq!(params.a, SimpleEC::A);
        assert_eq!(params.b, SimpleEC::B);
        assert_eq!(params.p, FIELD_PRIME);
    }
    
    #[test]
    fn test_point_doubling() {
        let p = ECPoint::new(2, 3);
        
        // Verify that 2P = P + P
        let doubled = SimpleEC::point_double(&p).unwrap();
        let added = SimpleEC::point_add(&p, &p).unwrap();
        
        assert_eq!(doubled, added);
    }
}