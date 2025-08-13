//! Circuit representation and basic operations

use super::*;
// use std::collections::HashMap; // Unused import

#[derive(Debug, Clone)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub input_wires: Vec<WireId>,
    pub output_wires: Vec<WireId>,
    pub wire_count: u32,
}

#[derive(Debug, Clone)]
pub struct Gate {
    pub id: GateId,
    pub gate_type: GateType,
    pub input_wires: Vec<WireId>,
    pub output_wire: WireId,
}

impl Circuit {
    pub fn new() -> Self {
        Self {
            gates: Vec::new(),
            input_wires: Vec::new(),
            output_wires: Vec::new(),
            wire_count: 0,
        }
    }
    
    pub fn add_input_wire(&mut self) -> WireId {
        let wire_id = self.wire_count;
        self.wire_count += 1;
        self.input_wires.push(wire_id);
        wire_id
    }
    
    pub fn add_output_wire(&mut self, wire_id: WireId) {
        self.output_wires.push(wire_id);
    }
    
    pub fn add_gate(&mut self, gate_type: GateType, input_wires: Vec<WireId>) -> WireId {
        let gate_id = self.gates.len() as GateId;
        let output_wire = self.wire_count;
        self.wire_count += 1;
        
        let gate = Gate {
            id: gate_id,
            gate_type,
            input_wires,
            output_wire,
        };
        
        self.gates.push(gate);
        output_wire
    }
    
    pub fn and_gate(&mut self, wire1: WireId, wire2: WireId) -> WireId {
        self.add_gate(GateType::And, vec![wire1, wire2])
    }
    
    pub fn or_gate(&mut self, wire1: WireId, wire2: WireId) -> WireId {
        self.add_gate(GateType::Or, vec![wire1, wire2])
    }
    
    pub fn xor_gate(&mut self, wire1: WireId, wire2: WireId) -> WireId {
        self.add_gate(GateType::Xor, vec![wire1, wire2])
    }
    
    pub fn not_gate(&mut self, wire: WireId) -> WireId {
        self.add_gate(GateType::Not, vec![wire])
    }
    
    // Helper method to create a simple adder circuit
    pub fn create_adder(num_bits: usize) -> Self {
        let mut circuit = Self::new();
        
        // Input wires for two numbers
        let mut a_wires = Vec::new();
        let mut b_wires = Vec::new();
        
        for _ in 0..num_bits {
            a_wires.push(circuit.add_input_wire());
            b_wires.push(circuit.add_input_wire());
        }
        
        let mut sum_wires = Vec::new();
        let mut carry = None;
        
        // Build full adders for each bit
        for i in 0..num_bits {
            let (sum, new_carry) = if i == 0 {
                // Half adder for first bit
                let sum = circuit.xor_gate(a_wires[i], b_wires[i]);
                let carry = circuit.and_gate(a_wires[i], b_wires[i]);
                (sum, Some(carry))
            } else {
                // Full adder for other bits
                let temp_sum = circuit.xor_gate(a_wires[i], b_wires[i]);
                let sum = circuit.xor_gate(temp_sum, carry.unwrap());
                
                let temp_carry1 = circuit.and_gate(a_wires[i], b_wires[i]);
                let temp_carry2 = circuit.and_gate(temp_sum, carry.unwrap());
                let new_carry = circuit.or_gate(temp_carry1, temp_carry2);
                
                (sum, Some(new_carry))
            };
            
            sum_wires.push(sum);
            circuit.add_output_wire(sum);
            carry = new_carry;
        }
        
        // Add carry as final output
        if let Some(carry_wire) = carry {
            circuit.add_output_wire(carry_wire);
        }
        
        circuit
    }
    
    // Helper method to create a multiplexer circuit
    pub fn create_mux(num_bits: usize) -> Self {
        let mut circuit = Self::new();
        
        // Input wires: selector + two data inputs
        let selector = circuit.add_input_wire();
        let mut input_a = Vec::new();
        let mut input_b = Vec::new();
        
        for _ in 0..num_bits {
            input_a.push(circuit.add_input_wire());
            input_b.push(circuit.add_input_wire());
        }
        
        // For each bit: output = (selector AND input_b) OR (!selector AND input_a)
        for i in 0..num_bits {
            let not_selector = circuit.not_gate(selector);
            let path_a = circuit.and_gate(not_selector, input_a[i]);
            let path_b = circuit.and_gate(selector, input_b[i]);
            let output = circuit.or_gate(path_a, path_b);
            circuit.add_output_wire(output);
        }
        
        circuit
    }
}

impl Default for Circuit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_circuit_creation() {
        let mut circuit = Circuit::new();
        
        let wire1 = circuit.add_input_wire();
        let wire2 = circuit.add_input_wire();
        let and_output = circuit.and_gate(wire1, wire2);
        circuit.add_output_wire(and_output);
        
        assert_eq!(circuit.input_wires.len(), 2);
        assert_eq!(circuit.output_wires.len(), 1);
        assert_eq!(circuit.gates.len(), 1);
        assert_eq!(circuit.gates[0].gate_type, GateType::And);
    }
    
    #[test]
    fn test_adder_circuit() {
        let circuit = Circuit::create_adder(4);
        
        // 4-bit adder should have 8 input wires (4 for each number)
        assert_eq!(circuit.input_wires.len(), 8);
        
        // Should have 5 output wires (4 sum bits + 1 carry)
        assert_eq!(circuit.output_wires.len(), 5);
        
        // Should have multiple gates for the adder logic
        assert!(circuit.gates.len() > 0);
    }
}