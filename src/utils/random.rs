//! Random utility functions

use rand::{RngCore, thread_rng};

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