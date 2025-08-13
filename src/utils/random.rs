//! Random utility functions

use rand::{RngCore, thread_rng, Rng};
use crate::secret_sharing::FIELD_PRIME;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_u64() -> u64 {
    let mut rng = thread_rng();
    rng.next_u64()
}

/// Generate a random element in the finite field
pub fn random_field_element() -> u64 {
    let mut rng = thread_rng();
    rng.gen_range(1..FIELD_PRIME) // Exclude 0 for better randomness
}