//! Garbled Circuits (混淆电路) implementation
//! 
//! This module provides implementations of garbled circuits for secure computation.
//! Garbled circuits allow two parties to compute a function on their private inputs
//! without revealing the inputs to each other.

pub mod circuit;
pub mod gate;
pub mod wire;
pub mod garbler;
pub mod evaluator;
pub mod free_xor;

pub use circuit::*;
pub use gate::*;
pub use wire::*;
pub use garbler::*;
pub use evaluator::*;
pub use free_xor::*;

use crate::{MpcError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use rand::{Rng, RngCore};

pub type Label = [u8; 16]; // 128-bit wire labels
pub type WireId = u32;
pub type GateId = u32;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GateType {
    And,
    Or,
    Xor,
    Not,
    Input,
    Output,
}

#[derive(Debug, Clone)]
pub struct GarbledGate {
    pub id: GateId,
    pub gate_type: GateType,
    pub input_wires: Vec<WireId>,
    pub output_wire: WireId,
    pub garbled_table: Option<Vec<Label>>,
}

#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    pub gates: Vec<GarbledGate>,
    pub input_wires: Vec<WireId>,
    pub output_wires: Vec<WireId>,
    pub wire_labels: std::collections::HashMap<WireId, (Label, Label)>, // (label_0, label_1)
}

pub fn hash_to_label(input: &[u8]) -> Label {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut label = [0u8; 16];
    label.copy_from_slice(&result[..16]);
    label
}

pub fn xor_labels(a: &Label, b: &Label) -> Label {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

pub fn generate_random_label<R: RngCore>(rng: &mut R) -> Label {
    let mut label = [0u8; 16];
    rng.fill_bytes(&mut label);
    label
}