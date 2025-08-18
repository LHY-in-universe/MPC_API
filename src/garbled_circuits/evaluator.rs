//! Evaluator implementation for garbled circuits

use super::*;
// use std::collections::HashMap; // Unused import

pub struct Evaluator {
    wire_state: WireState,
}

impl Evaluator {
    pub fn new() -> Self {
        Self {
            wire_state: WireState::new(),
        }
    }
    
    pub fn evaluate(&mut self, garbled_circuit: &GarbledCircuit, input_labels: &[Label]) -> Result<Vec<Label>> {
        // Set input labels
        self.wire_state.set_input_labels(&garbled_circuit.input_wires, input_labels)?;
        
        // Evaluate gates in topological order
        for gate in &garbled_circuit.gates {
            self.evaluate_gate(gate, garbled_circuit)?;
        }
        
        // Get output labels
        self.wire_state.get_output_labels(&garbled_circuit.output_wires)
    }
    
    fn evaluate_gate(&mut self, gate: &GarbledGate, garbled_circuit: &GarbledCircuit) -> Result<()> {
        match gate.gate_type {
            GateType::And | GateType::Or | GateType::Xor => {
                self.evaluate_table_gate(gate, garbled_circuit)
            }
            GateType::Not => {
                self.evaluate_not_gate(gate, garbled_circuit)
            }
            _ => Err(MpcError::ProtocolError("Invalid gate type for evaluation".to_string())),
        }
    }
    
    fn evaluate_table_gate(&mut self, gate: &GarbledGate, garbled_circuit: &GarbledCircuit) -> Result<()> {
        if gate.input_wires.len() != 2 {
            return Err(MpcError::ProtocolError("Table gate must have exactly 2 inputs".to_string()));
        }
        
        let garbled_table = gate.garbled_table.as_ref()
            .ok_or_else(|| MpcError::ProtocolError("Missing garbled table".to_string()))?;
        
        if garbled_table.len() != 4 {
            return Err(MpcError::ProtocolError("Invalid garbled table size".to_string()));
        }
        
        // Get input labels
        let input1_label = self.wire_state.get_wire_label(gate.input_wires[0])
            .ok_or_else(|| MpcError::ProtocolError("Missing input label".to_string()))?;
        let input2_label = self.wire_state.get_wire_label(gate.input_wires[1])
            .ok_or_else(|| MpcError::ProtocolError("Missing input label".to_string()))?;
        
        // Try to decrypt each entry in the garbled table
        let combined_input = [input1_label, input2_label].concat();
        let decryption_key = hash_to_label(&combined_input);
        
        for encrypted_label in garbled_table {
            let decrypted_label = xor_labels(&decryption_key, encrypted_label);
            
            // Check if this is a valid output label by trying to match it with known labels
            if self.is_valid_output_label(&decrypted_label, gate.output_wire, garbled_circuit) {
                self.wire_state.set_wire_label(gate.output_wire, decrypted_label);
                return Ok(());
            }
        }
        
        Err(MpcError::ProtocolError("Failed to decrypt garbled table entry".to_string()))
    }
    
    
    fn evaluate_not_gate(&mut self, gate: &GarbledGate, garbled_circuit: &GarbledCircuit) -> Result<()> {
        if gate.input_wires.len() != 1 {
            return Err(MpcError::ProtocolError("NOT gate must have exactly 1 input".to_string()));
        }
        
        let input_label = self.wire_state.get_wire_label(gate.input_wires[0])
            .ok_or_else(|| MpcError::ProtocolError("Missing input label".to_string()))?;
        
        // For NOT gate, we need to map to the opposite label
        let (label_0, label_1) = garbled_circuit.wire_labels[&gate.output_wire];
        let input_wire_labels = garbled_circuit.wire_labels[&gate.input_wires[0]];
        
        let output_label = if input_label == input_wire_labels.0 {
            label_1 // input is 0, output is 1
        } else {
            label_0 // input is 1, output is 0
        };
        
        self.wire_state.set_wire_label(gate.output_wire, output_label);
        Ok(())
    }
    
    fn is_valid_output_label(&self, label: &Label, wire_id: WireId, garbled_circuit: &GarbledCircuit) -> bool {
        if let Some((label_0, label_1)) = garbled_circuit.wire_labels.get(&wire_id) {
            label == label_0 || label == label_1
        } else {
            false
        }
    }
    
    pub fn decode_output(&self, output_labels: &[Label], garbled_circuit: &GarbledCircuit) -> Result<Vec<bool>> {
        let mut output_bits = Vec::new();
        
        for (i, &output_label) in output_labels.iter().enumerate() {
            let wire_id = garbled_circuit.output_wires[i];
            let (label_0, label_1) = garbled_circuit.wire_labels[&wire_id];
            
            if output_label == label_0 {
                output_bits.push(false);
            } else if output_label == label_1 {
                output_bits.push(true);
            } else {
                return Err(MpcError::ProtocolError("Invalid output label".to_string()));
            }
        }
        
        Ok(output_bits)
    }
    
    pub fn clear_state(&mut self) {
        self.wire_state.clear();
    }
}

impl Default for Evaluator {
    fn default() -> Self {
        Self::new()
    }
}

// Convenience function for complete evaluation
pub fn evaluate_garbled_circuit(
    garbled_circuit: &GarbledCircuit,
    input_labels: &[Label],
) -> Result<Vec<bool>> {
    let mut evaluator = Evaluator::new();
    let output_labels = evaluator.evaluate(garbled_circuit, input_labels)?;
    evaluator.decode_output(&output_labels, garbled_circuit)
}
