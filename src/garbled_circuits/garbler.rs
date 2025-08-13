//! Garbler implementation for creating garbled circuits

use super::*;
use crate::secret_sharing::{FIELD_PRIME, field_add, field_mul};
use std::collections::HashMap;
use rand::{thread_rng, RngCore};

pub struct Garbler {
    pub global_offset: Label,
}

impl Garbler {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let global_offset = generate_random_label(&mut rng);
        Self { global_offset }
    }
    
    pub fn garble_circuit(&self, circuit: &Circuit) -> Result<GarbledCircuit> {
        let mut rng = thread_rng();
        let mut wire_labels = HashMap::new();
        let mut garbled_gates = Vec::new();
        
        // Generate labels for all wires
        for wire_id in 0..circuit.wire_count {
            let label_0 = generate_random_label(&mut rng);
            let label_1 = xor_labels(&label_0, &self.global_offset);
            wire_labels.insert(wire_id, (label_0, label_1));
        }
        
        // Garble each gate
        for gate in &circuit.gates {
            let garbled_gate = self.garble_gate(gate, &wire_labels)?;
            garbled_gates.push(garbled_gate);
        }
        
        Ok(GarbledCircuit {
            gates: garbled_gates,
            input_wires: circuit.input_wires.clone(),
            output_wires: circuit.output_wires.clone(),
            wire_labels,
        })
    }
    
    fn garble_gate(&self, gate: &Gate, wire_labels: &HashMap<WireId, (Label, Label)>) -> Result<GarbledGate> {
        match gate.gate_type {
            GateType::And => self.garble_and_gate(gate, wire_labels),
            GateType::Or => self.garble_or_gate(gate, wire_labels),
            GateType::Xor => self.garble_xor_gate(gate, wire_labels),
            GateType::Not => self.garble_not_gate(gate, wire_labels),
            _ => Err(MpcError::ProtocolError("Invalid gate type for garbling".to_string())),
        }
    }
    
    fn garble_and_gate(&self, gate: &Gate, wire_labels: &HashMap<WireId, (Label, Label)>) -> Result<GarbledGate> {
        if gate.input_wires.len() != 2 {
            return Err(MpcError::ProtocolError("AND gate must have exactly 2 inputs".to_string()));
        }
        
        let (a0, a1) = wire_labels[&gate.input_wires[0]];
        let (b0, b1) = wire_labels[&gate.input_wires[1]];
        let (c0, c1) = wire_labels[&gate.output_wire];
        
        // Create garbled table for AND gate
        // Truth table: 00->0, 01->0, 10->0, 11->1
        let mut garbled_table = Vec::new();
        
        // Entry for (0,0) -> 0
        let entry_00 = self.encrypt_label(&[a0, b0], &c0);
        garbled_table.push(entry_00);
        
        // Entry for (0,1) -> 0
        let entry_01 = self.encrypt_label(&[a0, b1], &c0);
        garbled_table.push(entry_01);
        
        // Entry for (1,0) -> 0
        let entry_10 = self.encrypt_label(&[a1, b0], &c0);
        garbled_table.push(entry_10);
        
        // Entry for (1,1) -> 1
        let entry_11 = self.encrypt_label(&[a1, b1], &c1);
        garbled_table.push(entry_11);
        
        // Shuffle the table to hide the true mapping
        self.shuffle_garbled_table(&mut garbled_table);
        
        Ok(GarbledGate {
            id: gate.id,
            gate_type: gate.gate_type.clone(),
            input_wires: gate.input_wires.clone(),
            output_wire: gate.output_wire,
            garbled_table: Some(garbled_table),
        })
    }
    
    fn garble_or_gate(&self, gate: &Gate, wire_labels: &HashMap<WireId, (Label, Label)>) -> Result<GarbledGate> {
        if gate.input_wires.len() != 2 {
            return Err(MpcError::ProtocolError("OR gate must have exactly 2 inputs".to_string()));
        }
        
        let (a0, a1) = wire_labels[&gate.input_wires[0]];
        let (b0, b1) = wire_labels[&gate.input_wires[1]];
        let (c0, c1) = wire_labels[&gate.output_wire];
        
        // Create garbled table for OR gate
        // Truth table: 00->0, 01->1, 10->1, 11->1
        let mut garbled_table = Vec::new();
        
        // Entry for (0,0) -> 0
        let entry_00 = self.encrypt_label(&[a0, b0], &c0);
        garbled_table.push(entry_00);
        
        // Entry for (0,1) -> 1
        let entry_01 = self.encrypt_label(&[a0, b1], &c1);
        garbled_table.push(entry_01);
        
        // Entry for (1,0) -> 1
        let entry_10 = self.encrypt_label(&[a1, b0], &c1);
        garbled_table.push(entry_10);
        
        // Entry for (1,1) -> 1
        let entry_11 = self.encrypt_label(&[a1, b1], &c1);
        garbled_table.push(entry_11);
        
        self.shuffle_garbled_table(&mut garbled_table);
        
        Ok(GarbledGate {
            id: gate.id,
            gate_type: gate.gate_type.clone(),
            input_wires: gate.input_wires.clone(),
            output_wire: gate.output_wire,
            garbled_table: Some(garbled_table),
        })
    }
    
    fn garble_xor_gate(&self, gate: &Gate, wire_labels: &HashMap<WireId, (Label, Label)>) -> Result<GarbledGate> {
        if gate.input_wires.len() != 2 {
            return Err(MpcError::ProtocolError("XOR gate must have exactly 2 inputs".to_string()));
        }
        
        // XOR gates can use the free-XOR optimization - no garbled table needed
        // Output label = input1_label XOR input2_label
        Ok(GarbledGate {
            id: gate.id,
            gate_type: gate.gate_type.clone(),
            input_wires: gate.input_wires.clone(),
            output_wire: gate.output_wire,
            garbled_table: None, // Free XOR - no table needed
        })
    }
    
    fn garble_not_gate(&self, gate: &Gate, wire_labels: &HashMap<WireId, (Label, Label)>) -> Result<GarbledGate> {
        if gate.input_wires.len() != 1 {
            return Err(MpcError::ProtocolError("NOT gate must have exactly 1 input".to_string()));
        }
        
        // NOT gate just swaps the wire labels
        Ok(GarbledGate {
            id: gate.id,
            gate_type: gate.gate_type.clone(),
            input_wires: gate.input_wires.clone(),
            output_wire: gate.output_wire,
            garbled_table: None, // No table needed for NOT
        })
    }
    
    fn encrypt_label(&self, input_labels: &[Label], output_label: &Label) -> Label {
        let mut combined_input = Vec::new();
        for label in input_labels {
            combined_input.extend_from_slice(label);
        }
        
        let key = hash_to_label(&combined_input);
        xor_labels(&key, output_label)
    }
    
    fn shuffle_garbled_table(&self, table: &mut [Label]) {
        // For simplicity, we'll use a deterministic shuffle based on the labels
        // In practice, you might want a more sophisticated shuffling mechanism
        table.sort_by(|a, b| a.cmp(b));
    }
    
    pub fn get_input_labels(&self, garbled_circuit: &GarbledCircuit, inputs: &[bool]) -> Result<Vec<Label>> {
        if inputs.len() != garbled_circuit.input_wires.len() {
            return Err(MpcError::ProtocolError("Input length mismatch".to_string()));
        }
        
        let mut input_labels = Vec::new();
        for (i, &input_bit) in inputs.iter().enumerate() {
            let wire_id = garbled_circuit.input_wires[i];
            let (label_0, label_1) = garbled_circuit.wire_labels[&wire_id];
            let label = if input_bit { label_1 } else { label_0 };
            input_labels.push(label);
        }
        
        Ok(input_labels)
    }
}

impl Default for Garbler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_garble_and_gate() {
        let garbler = Garbler::new();
        let mut circuit = Circuit::new();
        
        let wire1 = circuit.add_input_wire();
        let wire2 = circuit.add_input_wire();
        let output = circuit.and_gate(wire1, wire2);
        circuit.add_output_wire(output);
        
        let garbled_circuit = garbler.garble_circuit(&circuit).unwrap();
        
        assert_eq!(garbled_circuit.gates.len(), 1);
        assert_eq!(garbled_circuit.input_wires.len(), 2);
        assert_eq!(garbled_circuit.output_wires.len(), 1);
        
        let garbled_gate = &garbled_circuit.gates[0];
        assert_eq!(garbled_gate.gate_type, GateType::And);
        assert!(garbled_gate.garbled_table.is_some());
        assert_eq!(garbled_gate.garbled_table.as_ref().unwrap().len(), 4);
    }
    
    #[test]
    fn test_garble_xor_gate() {
        let garbler = Garbler::new();
        let mut circuit = Circuit::new();
        
        let wire1 = circuit.add_input_wire();
        let wire2 = circuit.add_input_wire();
        let output = circuit.xor_gate(wire1, wire2);
        circuit.add_output_wire(output);
        
        let garbled_circuit = garbler.garble_circuit(&circuit).unwrap();
        
        let garbled_gate = &garbled_circuit.gates[0];
        assert_eq!(garbled_gate.gate_type, GateType::Xor);
        assert!(garbled_gate.garbled_table.is_none()); // Free XOR
    }
}