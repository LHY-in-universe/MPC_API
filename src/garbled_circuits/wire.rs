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
                return Err(MpcError::ProtocolError(format!("Output wire {wire_id} has no value")));
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
                return Err(MpcError::ProtocolError(format!("Output wire {wire_id} has no label")));
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
