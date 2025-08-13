//! SPDZ Protocol Implementation
//! 
//! SPDZ (pronounced "Speedz") is a protocol for secure multi-party computation
//! that enables parties to jointly compute functions over private inputs.

pub mod share;
pub mod offline;
pub mod online;
pub mod preprocessing;

pub use share::*;
pub use offline::*;
pub use online::*;
pub use preprocessing::*;

use crate::{MpcError, Result};
use crate::secret_sharing::{FIELD_PRIME, field_add, field_sub, field_mul};
use crate::authentication::{HMAC, HmacKey, HmacTag};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

pub type PlayerId = usize;
pub type ShareId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SPDZParams {
    pub num_parties: usize,
    pub party_id: PlayerId,
    pub threshold: usize,
    pub security_parameter: usize,
}

impl SPDZParams {
    pub fn new(num_parties: usize, party_id: PlayerId, threshold: usize) -> Self {
        Self {
            num_parties,
            party_id,
            threshold,
            security_parameter: 128,
        }
    }
    
    pub fn is_valid(&self) -> bool {
        self.party_id < self.num_parties 
            && self.threshold > 0 
            && self.threshold < self.num_parties
    }
}