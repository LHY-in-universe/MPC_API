//! Free XOR optimization for garbled circuits

use super::*;

pub struct FreeXorOptimizer {
    pub global_offset: Label,
}

impl FreeXorOptimizer {
    pub fn new(global_offset: Label) -> Self {
        Self { global_offset }
    }
    
    // Optimize circuit by identifying XOR gates that can use free XOR
    pub fn optimize_circuit(&self, circuit: &Circuit) -> Circuit {
        let mut optimized = circuit.clone();
        
        // Mark XOR gates as free (they already are in our implementation)
        // This is mainly for documentation and potential future optimizations
        for gate in &mut optimized.gates {
            if gate.gate_type == GateType::Xor {
                // XOR gates are automatically free in our implementation
            }
        }
        
        optimized
    }
    
    // Generate wire labels with free XOR property
    pub fn generate_wire_labels(&self, wire_count: u32) -> std::collections::HashMap<WireId, (Label, Label)> {
        let mut rng = rand::thread_rng();
        let mut wire_labels = std::collections::HashMap::new();
        
        for wire_id in 0..wire_count {
            let label_0 = generate_random_label(&mut rng);
            let label_1 = xor_labels(&label_0, &self.global_offset);
            wire_labels.insert(wire_id, (label_0, label_1));
        }
        
        wire_labels
    }
    
    // Evaluate XOR gate using free XOR
    pub fn evaluate_free_xor(&self, input1_label: &Label, input2_label: &Label) -> Label {
        xor_labels(input1_label, input2_label)
    }
    
    // Check if a gate can use free XOR optimization
    pub fn can_use_free_xor(&self, gate: &Gate) -> bool {
        matches!(gate.gate_type, GateType::Xor | GateType::Not)
    }
    
    // Count the number of free gates in a circuit
    pub fn count_free_gates(&self, circuit: &Circuit) -> usize {
        circuit.gates.iter()
            .filter(|gate| self.can_use_free_xor(gate))
            .count()
    }
    
    // Calculate communication savings from free XOR
    pub fn calculate_savings(&self, circuit: &Circuit) -> (usize, usize) {
        let total_gates = circuit.gates.len();
        let free_gates = self.count_free_gates(circuit);
        let table_gates = total_gates - free_gates;
        
        // Each table gate requires 4 labels (16 bytes each)
        // Free gates require 0 communication
        let with_optimization = table_gates * 4 * 16;
        let without_optimization = total_gates * 4 * 16;
        
        (without_optimization, with_optimization)
    }
    
    // Verify free XOR property holds for wire labels
    pub fn verify_free_xor_property(&self, wire_labels: &std::collections::HashMap<WireId, (Label, Label)>) -> bool {
        for (label_0, label_1) in wire_labels.values() {
            let computed_label_1 = xor_labels(label_0, &self.global_offset);
            if *label_1 != computed_label_1 {
                return false;
            }
        }
        true
    }
}

// Utility functions for free XOR circuits
pub fn is_linear_circuit(circuit: &Circuit) -> bool {
    circuit.gates.iter().all(|gate| {
        matches!(gate.gate_type, GateType::Xor | GateType::Not | GateType::Input | GateType::Output)
    })
}

pub fn count_non_linear_gates(circuit: &Circuit) -> usize {
    circuit.gates.iter()
        .filter(|gate| matches!(gate.gate_type, GateType::And | GateType::Or))
        .count()
}

// Create a circuit that demonstrates free XOR benefits
pub fn create_xor_heavy_circuit(num_bits: usize) -> Circuit {
    let mut circuit = Circuit::new();
    
    // Create input wires
    let mut input_wires = Vec::new();
    for _ in 0..(num_bits * 2) {
        input_wires.push(circuit.add_input_wire());
    }
    
    // Create XOR chain
    let mut current_wires = input_wires;
    while current_wires.len() > 1 {
        let mut next_wires = Vec::new();
        
        for chunk in current_wires.chunks(2) {
            if chunk.len() == 2 {
                let xor_output = circuit.xor_gate(chunk[0], chunk[1]);
                next_wires.push(xor_output);
            } else {
                next_wires.push(chunk[0]);
            }
        }
        
        current_wires = next_wires;
    }
    
    // Add final output
    if !current_wires.is_empty() {
        circuit.add_output_wire(current_wires[0]);
    }
    
    circuit
}
