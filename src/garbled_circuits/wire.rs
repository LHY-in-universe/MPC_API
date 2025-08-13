//! Wire management and label operations

use super::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Wire {
    pub id: WireId,
    pub value: Option<bool>,
    pub label: Option<Label>,
}

impl Wire {
    pub fn new(id: WireId) -> Self {
        Self {
            id,
            value: None,
            label: None,
        }
    }
    
    pub fn with_value(id: WireId, value: bool) -> Self {
        Self {
            id,
            value: Some(value),
            label: None,
        }
    }
    
    pub fn with_label(id: WireId, label: Label) -> Self {
        Self {
            id,
            value: None,
            label: Some(label),
        }
    }
    
    pub fn set_value(&mut self, value: bool) {
        self.value = Some(value);
    }
    
    pub fn set_label(&mut self, label: Label) {
        self.label = Some(label);
    }
    
    pub fn get_value(&self) -> Option<bool> {
        self.value
    }
    
    pub fn get_label(&self) -> Option<Label> {
        self.label
    }
}

#[derive(Debug, Clone)]
pub struct WireState {
    wires: HashMap<WireId, Wire>,
}

impl WireState {
    pub fn new() -> Self {
        Self {
            wires: HashMap::new(),
        }
    }
    
    pub fn add_wire(&mut self, wire: Wire) {
        self.wires.insert(wire.id, wire);
    }
    
    pub fn get_wire(&self, id: WireId) -> Option<&Wire> {
        self.wires.get(&id)
    }
    
    pub fn get_wire_mut(&mut self, id: WireId) -> Option<&mut Wire> {
        self.wires.get_mut(&id)
    }
    
    pub fn set_wire_value(&mut self, id: WireId, value: bool) {
        if let Some(wire) = self.wires.get_mut(&id) {
            wire.set_value(value);
        } else {
            self.wires.insert(id, Wire::with_value(id, value));
        }
    }
    
    pub fn set_wire_label(&mut self, id: WireId, label: Label) {
        if let Some(wire) = self.wires.get_mut(&id) {
            wire.set_label(label);
        } else {
            self.wires.insert(id, Wire::with_label(id, label));
        }
    }
    
    pub fn get_wire_value(&self, id: WireId) -> Option<bool> {
        self.wires.get(&id)?.get_value()
    }
    
    pub fn get_wire_label(&self, id: WireId) -> Option<Label> {
        self.wires.get(&id)?.get_label()
    }
    
    pub fn clear(&mut self) {
        self.wires.clear();
    }
    
    pub fn wire_count(&self) -> usize {
        self.wires.len()
    }
    
    pub fn has_wire(&self, id: WireId) -> bool {
        self.wires.contains_key(&id)
    }
    
    pub fn get_all_values(&self) -> HashMap<WireId, bool> {
        self.wires
            .iter()
            .filter_map(|(id, wire)| wire.get_value().map(|v| (*id, v)))
            .collect()
    }
    
    pub fn get_all_labels(&self) -> HashMap<WireId, Label> {
        self.wires
            .iter()
            .filter_map(|(id, wire)| wire.get_label().map(|l| (*id, l)))
            .collect()
    }
    
    pub fn set_input_values(&mut self, input_wires: &[WireId], values: &[bool]) -> Result<()> {
        if input_wires.len() != values.len() {
            return Err(MpcError::ProtocolError("Input wire count mismatch".to_string()));
        }
        
        for (&wire_id, &value) in input_wires.iter().zip(values.iter()) {
            self.set_wire_value(wire_id, value);
        }
        
        Ok(())
    }
    
    pub fn set_input_labels(&mut self, input_wires: &[WireId], labels: &[Label]) -> Result<()> {
        if input_wires.len() != labels.len() {
            return Err(MpcError::ProtocolError("Input wire count mismatch".to_string()));
        }
        
        for (&wire_id, &label) in input_wires.iter().zip(labels.iter()) {
            self.set_wire_label(wire_id, label);
        }
        
        Ok(())
    }
    
    pub fn get_output_values(&self, output_wires: &[WireId]) -> Result<Vec<bool>> {
        let mut output_values = Vec::new();
        
        for &wire_id in output_wires {
            if let Some(value) = self.get_wire_value(wire_id) {
                output_values.push(value);
            } else {
                return Err(MpcError::ProtocolError(format!("Output wire {} has no value", wire_id)));
            }
        }
        
        Ok(output_values)
    }
    
    pub fn get_output_labels(&self, output_wires: &[WireId]) -> Result<Vec<Label>> {
        let mut output_labels = Vec::new();
        
        for &wire_id in output_wires {
            if let Some(label) = self.get_wire_label(wire_id) {
                output_labels.push(label);
            } else {
                return Err(MpcError::ProtocolError(format!("Output wire {} has no label", wire_id)));
            }
        }
        
        Ok(output_labels)
    }
}

impl Default for WireState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wire_creation() {
        let wire = Wire::new(0);
        assert_eq!(wire.id, 0);
        assert_eq!(wire.get_value(), None);
        assert_eq!(wire.get_label(), None);
        
        let wire_with_value = Wire::with_value(1, true);
        assert_eq!(wire_with_value.id, 1);
        assert_eq!(wire_with_value.get_value(), Some(true));
        
        let label = [1u8; 16];
        let wire_with_label = Wire::with_label(2, label);
        assert_eq!(wire_with_label.id, 2);
        assert_eq!(wire_with_label.get_label(), Some(label));
    }
    
    #[test]
    fn test_wire_state() {
        let mut state = WireState::new();
        
        state.set_wire_value(0, true);
        state.set_wire_value(1, false);
        
        assert_eq!(state.get_wire_value(0), Some(true));
        assert_eq!(state.get_wire_value(1), Some(false));
        assert_eq!(state.get_wire_value(2), None);
        
        assert_eq!(state.wire_count(), 2);
        assert!(state.has_wire(0));
        assert!(state.has_wire(1));
        assert!(!state.has_wire(2));
        
        let label = [42u8; 16];
        state.set_wire_label(0, label);
        assert_eq!(state.get_wire_label(0), Some(label));
    }
    
    #[test]
    fn test_input_output_operations() {
        let mut state = WireState::new();
        let input_wires = vec![0, 1, 2];
        let input_values = vec![true, false, true];
        
        state.set_input_values(&input_wires, &input_values).unwrap();
        
        let output_wires = vec![0, 1];
        let output_values = state.get_output_values(&output_wires).unwrap();
        assert_eq!(output_values, vec![true, false]);
        
        // Test label operations
        let labels = vec![[1u8; 16], [2u8; 16], [3u8; 16]];
        state.set_input_labels(&input_wires, &labels).unwrap();
        
        let output_labels = state.get_output_labels(&output_wires).unwrap();
        assert_eq!(output_labels, vec![[1u8; 16], [2u8; 16]]);
    }
}