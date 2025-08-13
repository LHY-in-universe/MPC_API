//! Scalar arithmetic for elliptic curves

// use super::*; // Unused import
use crate::secret_sharing::FIELD_PRIME;

#[derive(Debug, Clone, PartialEq)]
pub struct Scalar {
    pub value: u64,
}

impl Scalar {
    pub fn new(value: u64) -> Self {
        Self { value: value % FIELD_PRIME }
    }
    
    pub fn zero() -> Self {
        Self { value: 0 }
    }
    
    pub fn one() -> Self {
        Self { value: 1 }
    }
    
    pub fn add(&self, other: &Scalar) -> Scalar {
        Scalar::new((self.value + other.value) % FIELD_PRIME)
    }
    
    pub fn multiply(&self, other: &Scalar) -> Scalar {
        let product = (self.value as u128 * other.value as u128) % FIELD_PRIME as u128;
        Scalar::new(product as u64)
    }
}