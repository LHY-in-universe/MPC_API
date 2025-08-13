//! Message Authentication Codes (消息认证码)
//! 
//! This module implements various message authentication code schemes

pub mod hmac;
pub mod poly1305;
pub mod gmac;
pub mod cmac;

pub use hmac::*;
pub use poly1305::*;
pub use gmac::*;
pub use cmac::*;

use crate::{MpcError, Result};
use serde::{Deserialize, Serialize};

pub trait MessageAuthenticationCode {
    type Key;
    type Message;
    type Tag;
    
    fn generate_key() -> Self::Key;
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag;
    fn verify(key: &Self::Key, message: &Self::Message, tag: &Self::Tag) -> bool;
}

// Basic properties for MACs
pub trait UnforgeableMac: MessageAuthenticationCode {
    fn is_unforgeable() -> bool { true }
}

pub trait SecureMac: MessageAuthenticationCode {
    fn is_secure() -> bool { true }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MacTag {
    pub tag: Vec<u8>,
}

impl MacTag {
    pub fn new(tag: Vec<u8>) -> Self {
        MacTag { tag }
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Self {
        MacTag { tag: bytes.to_vec() }
    }
    
    pub fn to_bytes(&self) -> &[u8] {
        &self.tag
    }
    
    pub fn len(&self) -> usize {
        self.tag.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.tag.is_empty()
    }
}