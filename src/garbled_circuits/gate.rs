//! Gate definitions and operations

use super::*;

impl Gate {
    pub fn new(id: GateId, gate_type: GateType, input_wires: Vec<WireId>, output_wire: WireId) -> Self {
        Self {
            id,
            gate_type,
            input_wires,
            output_wire,
        }
    }
    
    pub fn evaluate(&self, inputs: &[bool]) -> Result<bool> {
        match self.gate_type {
            GateType::And => {
                if inputs.len() != 2 {
                    return Err(MpcError::ProtocolError("AND gate requires exactly 2 inputs".to_string()));
                }
                Ok(inputs[0] && inputs[1])
            }
            GateType::Or => {
                if inputs.len() != 2 {
                    return Err(MpcError::ProtocolError("OR gate requires exactly 2 inputs".to_string()));
                }
                Ok(inputs[0] || inputs[1])
            }
            GateType::Xor => {
                if inputs.len() != 2 {
                    return Err(MpcError::ProtocolError("XOR gate requires exactly 2 inputs".to_string()));
                }
                Ok(inputs[0] ^ inputs[1])
            }
            GateType::Not => {
                if inputs.len() != 1 {
                    return Err(MpcError::ProtocolError("NOT gate requires exactly 1 input".to_string()));
                }
                Ok(!inputs[0])
            }
            GateType::Input | GateType::Output => {
                Err(MpcError::ProtocolError("Input/Output gates cannot be evaluated".to_string()))
            }
        }
    }
    
    pub fn input_count(&self) -> usize {
        match self.gate_type {
            GateType::And | GateType::Or | GateType::Xor => 2,
            GateType::Not => 1,
            GateType::Input => 0,
            GateType::Output => 1,
        }
    }
    
    pub fn is_linear(&self) -> bool {
        matches!(self.gate_type, GateType::Xor | GateType::Not)
    }
}

impl GarbledGate {
    pub fn new(id: GateId, gate_type: GateType, input_wires: Vec<WireId>, output_wire: WireId) -> Self {
        Self {
            id,
            gate_type,
            input_wires,
            output_wire,
            garbled_table: None,
        }
    }
    
    pub fn with_table(mut self, table: Vec<Label>) -> Self {
        self.garbled_table = Some(table);
        self
    }
    
    pub fn is_free(&self) -> bool {
        // Free gates don't require a garbled table (XOR, NOT)
        matches!(self.gate_type, GateType::Xor | GateType::Not)
    }
    
    pub fn table_size(&self) -> usize {
        match self.gate_type {
            GateType::And | GateType::Or => 4, // 2^2 entries
            GateType::Xor | GateType::Not => 0, // Free gates
            _ => 0,
        }
    }
}
