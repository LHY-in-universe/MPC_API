//! OT Extension protocols for efficiently performing many OTs

use super::*;

#[derive(Debug, Clone)]
pub struct OTExtension {
    pub security_parameter: usize, // κ
    pub base_ots: Vec<(u64, u64)>, // Base OT outputs
}

impl OTExtension {
    pub fn new(security_parameter: usize) -> Self {
        Self {
            security_parameter,
            base_ots: Vec::new(),
        }
    }
    
    // Initialize with base OTs
    pub fn setup_base_ots(&mut self) -> Result<()> {
        let mut random_ot = RandomOT::new();
        
        for i in 0..self.security_parameter {
            let choice = (i % 2) == 0; // Alternate choices for demo
            let (r0, r1, rb) = random_ot.execute_random_ot(choice)?;
            self.base_ots.push((r0, r1));
        }
        
        Ok(())
    }
    
    // Extend to perform many OTs efficiently
    pub fn extend_ots(&self, num_ots: usize, choices: &[ChoiceBit]) -> Result<Vec<(u64, u64)>> {
        if choices.len() != num_ots {
            return Err(MpcError::ProtocolError("Choice vector length mismatch".to_string()));
        }
        
        if self.base_ots.is_empty() {
            return Err(MpcError::ProtocolError("Base OTs not initialized".to_string()));
        }
        
        let mut extended_ots = Vec::new();
        
        // Simplified OT extension (real implementations are more complex)
        for i in 0..num_ots {
            let base_index = i % self.base_ots.len();
            let (base_r0, base_r1) = self.base_ots[base_index];
            
            // Use base OT outputs to derive new OT values
            let seed = field_add(base_r0, (i as u64));
            let derived_r0 = self.hash_expand(seed, 0);
            let derived_r1 = self.hash_expand(seed, 1);
            
            if choices[i] {
                extended_ots.push((derived_r1, derived_r0)); // Swapped based on choice
            } else {
                extended_ots.push((derived_r0, derived_r1));
            }
        }
        
        Ok(extended_ots)
    }
    
    // Hash function for expanding seeds
    fn hash_expand(&self, seed: u64, index: u8) -> u64 {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(seed.to_le_bytes());
        hasher.update([index]);
        let result = hasher.finalize();
        
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&result[..8]);
        u64::from_le_bytes(bytes) % FIELD_PRIME
    }
    
    // Batch OT extension for better efficiency
    pub fn batch_extend_ots(&self, batch_size: usize, all_choices: &[ChoiceBit]) -> Result<Vec<Vec<(u64, u64)>>> {
        let mut batches = Vec::new();
        
        for batch_choices in all_choices.chunks(batch_size) {
            let batch_result = self.extend_ots(batch_choices.len(), batch_choices)?;
            batches.push(batch_result);
        }
        
        Ok(batches)
    }
}

// 1-out-of-N OT extension
#[derive(Debug, Clone)]
pub struct OneOutOfNOT {
    pub n: usize, // Number of messages
    base_extension: OTExtension,
}

impl OneOutOfNOT {
    pub fn new(n: usize, security_parameter: usize) -> Self {
        Self {
            n,
            base_extension: OTExtension::new(security_parameter),
        }
    }
    
    pub fn setup(&mut self) -> Result<()> {
        self.base_extension.setup_base_ots()
    }
    
    // Execute 1-out-of-N OT using binary tree reduction
    pub fn execute_1_out_of_n_ot(&self, messages: &[u64], choice: usize) -> Result<u64> {
        if choice >= messages.len() {
            return Err(MpcError::ProtocolError("Choice index out of bounds".to_string()));
        }
        
        if messages.len() != self.n {
            return Err(MpcError::ProtocolError("Message count mismatch".to_string()));
        }
        
        // Convert choice to binary representation
        let choice_bits = self.choice_to_bits(choice);
        
        // Use binary tree of 1-out-of-2 OTs
        let mut current_messages = messages.to_vec();
        
        for &bit in &choice_bits {
            if current_messages.len() <= 1 {
                break;
            }
            
            let mut next_messages = Vec::new();
            
            for chunk in current_messages.chunks(2) {
                if chunk.len() == 2 {
                    // Execute 1-out-of-2 OT
                    let msg0_bytes = chunk[0].to_le_bytes().to_vec();
                    let msg1_bytes = chunk[1].to_le_bytes().to_vec();
                    
                    let result_bytes = execute_basic_ot(msg0_bytes, msg1_bytes, bit)?;
                    
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&result_bytes[..8]);
                    let result = u64::from_le_bytes(bytes);
                    
                    next_messages.push(result);
                } else {
                    next_messages.push(chunk[0]);
                }
            }
            
            current_messages = next_messages;
        }
        
        Ok(current_messages[0])
    }
    
    fn choice_to_bits(&self, choice: usize) -> Vec<bool> {
        let num_bits = (self.n.next_power_of_two().trailing_zeros() as usize).max(1);
        let mut bits = Vec::new();
        
        for i in 0..num_bits {
            bits.push(((choice >> i) & 1) == 1);
        }
        
        bits
    }
    
    // Batch 1-out-of-N OT
    pub fn batch_1_out_of_n_ot(&self, all_messages: &[Vec<u64>], choices: &[usize]) -> Result<Vec<u64>> {
        if all_messages.len() != choices.len() {
            return Err(MpcError::ProtocolError("Batch size mismatch".to_string()));
        }
        
        let mut results = Vec::new();
        
        for (messages, &choice) in all_messages.iter().zip(choices.iter()) {
            let result = self.execute_1_out_of_n_ot(messages, choice)?;
            results.push(result);
        }
        
        Ok(results)
    }
}

// String OT for variable-length messages
#[derive(Debug, Clone)]
pub struct StringOT {
    extension: OTExtension,
}

impl StringOT {
    pub fn new(security_parameter: usize) -> Self {
        Self {
            extension: OTExtension::new(security_parameter),
        }
    }
    
    pub fn setup(&mut self) -> Result<()> {
        self.extension.setup_base_ots()
    }
    
    // OT for strings of different lengths
    pub fn execute_string_ot(&self, msg0: &[u8], msg1: &[u8], choice: ChoiceBit) -> Result<Vec<u8>> {
        let max_len = msg0.len().max(msg1.len());
        
        // Pad messages to same length
        let mut padded_msg0 = msg0.to_vec();
        let mut padded_msg1 = msg1.to_vec();
        
        padded_msg0.resize(max_len, 0);
        padded_msg1.resize(max_len, 0);
        
        // Execute OT for each byte position
        let mut result = Vec::new();
        
        for i in 0..max_len {
            let byte_msg0 = vec![padded_msg0[i]];
            let byte_msg1 = vec![padded_msg1[i]];
            
            let byte_result = execute_basic_ot(byte_msg0, byte_msg1, choice)?;
            result.extend(byte_result);
        }
        
        // Remove padding from result
        while result.last() == Some(&0) && result.len() > msg0.len().min(msg1.len()) {
            result.pop();
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ot_extension_setup() {
        let mut ot_ext = OTExtension::new(128);
        assert!(ot_ext.setup_base_ots().is_ok());
        assert_eq!(ot_ext.base_ots.len(), 128);
    }
    
    #[test]
    fn test_ot_extension_extend() {
        let mut ot_ext = OTExtension::new(8);
        ot_ext.setup_base_ots().unwrap();
        
        let choices = vec![false, true, false, true];
        let extended = ot_ext.extend_ots(4, &choices).unwrap();
        
        assert_eq!(extended.len(), 4);
    }
    
    #[test]
    fn test_1_out_of_n_ot() {
        let mut one_out_of_n = OneOutOfNOT::new(4, 8);
        one_out_of_n.setup().unwrap();
        
        let messages = vec![100, 200, 300, 400];
        let choice = 2;
        
        let result = one_out_of_n.execute_1_out_of_n_ot(&messages, choice).unwrap();
        assert_eq!(result, messages[choice]);
    }
    
    #[test]
    fn test_choice_to_bits() {
        let one_out_of_n = OneOutOfNOT::new(8, 8);
        
        let bits = one_out_of_n.choice_to_bits(5); // 5 = 101 in binary
        assert_eq!(bits, vec![true, false, true]); // LSB first
    }
    
    #[test]
    fn test_string_ot() {
        let mut string_ot = StringOT::new(8);
        string_ot.setup().unwrap();
        
        let msg0 = b"Hello";
        let msg1 = b"World!";
        
        let result0 = string_ot.execute_string_ot(msg0, msg1, false).unwrap();
        assert_eq!(result0, msg0);
        
        let result1 = string_ot.execute_string_ot(msg0, msg1, true).unwrap();
        assert_eq!(result1, msg1);
    }
    
    #[test]
    fn test_batch_extend_ots() {
        let mut ot_ext = OTExtension::new(4);
        ot_ext.setup_base_ots().unwrap();
        
        let all_choices = vec![false, true, false, true, true, false];
        let batches = ot_ext.batch_extend_ots(3, &all_choices).unwrap();
        
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 3);
        assert_eq!(batches[1].len(), 3);
    }
}