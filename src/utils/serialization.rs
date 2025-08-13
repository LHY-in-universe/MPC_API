//! Serialization utility functions

use serde::{Serialize, Deserialize};
use crate::Result;

pub fn serialize_to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value)
        .map_err(|e| crate::MpcError::SerializationError(e.to_string()))
}

pub fn deserialize_from_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes)
        .map_err(|e| crate::MpcError::SerializationError(e.to_string()))
}