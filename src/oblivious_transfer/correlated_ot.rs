//! Correlated Oblivious Transfer (相关不经意传输) implementation
//! 
//! In correlated OT, the two messages are related by a fixed offset.
//! This is useful for many MPC protocols where we need OT on correlated values.

use super::*;

#[derive(Debug, Clone)]
pub struct CorrelatedOT {
    pub correlation: u64, // The fixed correlation between messages
    pub setup: DHOTSetup,
}

impl CorrelatedOT {
    pub fn new(correlation: u64) -> Self {
        Self {
            correlation,
            setup: DHOTSetup::new(),
        }
    }
    
    // Sender has a base value x, and the two messages are (x, x + correlation)
    pub fn execute_correlated_ot(
        &mut self,
        base_value: u64,
        choice: ChoiceBit,
    ) -> Result<u64> {
        let msg0 = base_value;
        let msg1 = field_add(base_value, self.correlation);
        
        // Convert to byte messages for basic OT
        let msg0_bytes = msg0.to_le_bytes().to_vec();
        let msg1_bytes = msg1.to_le_bytes().to_vec();
        
        let result_bytes = execute_basic_ot(msg0_bytes, msg1_bytes, choice)?;
        
        // Convert back to u64
        if result_bytes.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&result_bytes[..8]);
            Ok(u64::from_le_bytes(bytes))
        } else {
            Err(MpcError::ProtocolError("Invalid result length".to_string()))
        }
    }
    
    // Batch correlated OT for multiple values
    pub fn batch_correlated_ot(
        &mut self,
        base_values: &[u64],
        choices: &[ChoiceBit],
    ) -> Result<Vec<u64>> {
        if base_values.len() != choices.len() {
            return Err(MpcError::ProtocolError("Length mismatch".to_string()));
        }
        
        let mut results = Vec::new();
        for (&base_value, &choice) in base_values.iter().zip(choices.iter()) {
            let result = self.execute_correlated_ot(base_value, choice)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    // Optimized version using vector operations
    pub fn vector_correlated_ot(
        &mut self,
        base_values: &[u64],
        choices: &[ChoiceBit],
    ) -> Result<Vec<u64>> {
        if base_values.len() != choices.len() {
            return Err(MpcError::ProtocolError("Length mismatch".to_string()));
        }
        
        // Pack multiple values into single OT messages
        let mut msg0_packed = Vec::new();
        let mut msg1_packed = Vec::new();
        
        for &base_value in base_values {
            msg0_packed.extend_from_slice(&base_value.to_le_bytes());
            let correlated_value = field_add(base_value, self.correlation);
            msg1_packed.extend_from_slice(&correlated_value.to_le_bytes());
        }
        
        // Execute single OT with packed messages
        let choice_bit = choices[0]; // Use first choice for demo (in practice, use more sophisticated packing)
        let result_packed = execute_basic_ot(msg0_packed, msg1_packed, choice_bit)?;
        
        // Unpack results
        let mut results = Vec::new();
        for chunk in result_packed.chunks(8) {
            if chunk.len() == 8 {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(chunk);
                results.push(u64::from_le_bytes(bytes));
            }
        }
        
        Ok(results)
    }
}

// Helper function for creating common correlations
impl CorrelatedOT {
    pub fn new_additive_shares(secret: u64) -> Self {
        Self::new(secret)
    }
    
    pub fn new_multiplication_pairs(factor: u64) -> Self {
        Self::new(factor)
    }
    
    pub fn new_boolean_shares() -> Self {
        Self::new(1) // XOR correlation for boolean shares
    }
}

// Specialized correlated OT for common MPC primitives
#[derive(Debug, Clone)]
pub struct AdditiveShareOT {
    pub secret: u64,
    inner: CorrelatedOT,
}

impl AdditiveShareOT {
    pub fn new(secret: u64) -> Self {
        Self {
            secret,
            inner: CorrelatedOT::new(secret),
        }
    }
    
    // Generate additive shares: (r, s-r) where s is the secret
    pub fn generate_shares(&mut self, choice: ChoiceBit) -> Result<u64> {
        let mut rng = rand::thread_rng();
        let random_value = rng.gen_range(0..FIELD_PRIME);
        
        self.inner.execute_correlated_ot(random_value, choice)
    }
    
    // Verify that shares reconstruct to the secret
    pub fn verify_shares(&self, share0: u64, share1: u64) -> bool {
        field_add(share0, share1) == self.secret
    }
}

// Boolean correlated OT for XOR shares
#[derive(Debug, Clone)]
pub struct BooleanCorrelatedOT {
    #[allow(dead_code)]
    inner: CorrelatedOT,
}

impl BooleanCorrelatedOT {
    pub fn new() -> Self {
        Self {
            inner: CorrelatedOT::new(1), // XOR with 1
        }
    }
    
    pub fn execute_boolean_ot(&mut self, bit: bool, choice: ChoiceBit) -> Result<bool> {
        let bit_value = if bit { 1u64 } else { 0u64 };
        
        // For boolean OT, we want XOR logic: sender has (b, b⊕1) messages
        let msg0 = bit_value;
        let msg1 = bit_value ^ 1; // XOR with 1
        
        // Use basic OT directly for boolean values
        let msg0_bytes = msg0.to_le_bytes().to_vec();
        let msg1_bytes = msg1.to_le_bytes().to_vec();
        
        let result_bytes = execute_basic_ot(msg0_bytes, msg1_bytes, choice)?;
        
        // Convert back to bool
        if result_bytes.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&result_bytes[..8]);
            let result = u64::from_le_bytes(bytes);
            Ok(result != 0)
        } else {
            Err(MpcError::ProtocolError("Invalid result length".to_string()))
        }
    }
    
    // Generate XOR shares: (r, b ⊕ r) where b is the secret bit
    pub fn generate_xor_shares(&mut self, secret_bit: bool, choice: ChoiceBit) -> Result<bool> {
        self.execute_boolean_ot(secret_bit, choice)
    }
}

impl Default for BooleanCorrelatedOT {
    fn default() -> Self {
        Self::new()
    }
}
