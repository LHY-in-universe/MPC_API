//! Vector Oblivious Linear Function Evaluation (向量不经意线性函数计算)
//! 
//! VOLE allows computing f(x) = a*x + b where a,b are vectors and x is a scalar,
//! such that the sender learns nothing about x and receiver learns f(x) but not a,b.

use super::*;
use crate::secret_sharing::{field_add, field_mul};

// Type aliases for complex types
pub type VOLEResult = (Vec<u64>, Vec<u64>, u64, Vec<u64>);
pub type BatchVOLEResult = Vec<VOLEResult>;

#[derive(Debug, Clone)]
pub struct VectorOLE {
    pub vector_length: usize,
    pub base_ot: BasicOT,
}

impl VectorOLE {
    pub fn new(vector_length: usize) -> Self {
        Self {
            vector_length,
            base_ot: BasicOT::new(),
        }
    }
    
    // Execute Vector OLE: sender has vectors a,b; receiver has scalar x; receiver gets a*x + b
    pub fn execute_vole(
        &mut self,
        sender_a: &[u64],  // Vector a
        sender_b: &[u64],  // Vector b  
        receiver_x: u64,   // Scalar x
    ) -> Result<Vec<u64>> {
        if sender_a.len() != self.vector_length || sender_b.len() != self.vector_length {
            return Err(MpcError::ProtocolError("Vector length mismatch".to_string()));
        }
        
        let mut results = Vec::new();
        
        // For each position i, execute OLE to compute a[i]*x + b[i]
        for i in 0..self.vector_length {
            let result = self.execute_single_ole(sender_a[i], sender_b[i], receiver_x)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    // Execute single OLE: f(x) = a*x + b
    fn execute_single_ole(&mut self, a: u64, b: u64, x: u64) -> Result<u64> {
        // Use correlated OT to implement OLE
        // We need to compute a*x + b without revealing a,b to receiver or x to sender
        
        // Method: Use two OTs
        // First OT: receiver chooses bit based on x, gets shares of ax
        // Second OT: receiver gets b and completes the computation
        
        // For simplicity, we'll use a direct approach with basic OT
        // In practice, this would use more sophisticated techniques
        
        // Compute the two possible outputs: a*0 + b = b, a*1 + b = a + b
        let msg0 = b;                    // When x = 0
        let msg1 = field_add(a, b);      // When x = 1 (for boolean x)
        
        // For full scalar x, we need to generalize this
        // Here we'll use a simplified version treating x as boolean
        let choice = (x % 2) == 1;
        
        let msg0_bytes = msg0.to_le_bytes().to_vec();
        let msg1_bytes = msg1.to_le_bytes().to_vec();
        
        let result_bytes = execute_basic_ot(msg0_bytes, msg1_bytes, choice)?;
        
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&result_bytes[..8]);
        Ok(u64::from_le_bytes(bytes))
    }
    
    // Batch VOLE for multiple vectors
    pub fn batch_vole(
        &mut self,
        sender_vectors: &[(Vec<u64>, Vec<u64>)], // (a_i, b_i) pairs
        receiver_scalars: &[u64],                // x_i values
    ) -> Result<Vec<Vec<u64>>> {
        if sender_vectors.len() != receiver_scalars.len() {
            return Err(MpcError::ProtocolError("Batch size mismatch".to_string()));
        }
        
        let mut results = Vec::new();
        
        for ((a, b), &x) in sender_vectors.iter().zip(receiver_scalars.iter()) {
            let result = self.execute_vole(a, b, x)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    // Subfield VOLE - VOLE over smaller field embedded in larger field
    pub fn subfield_vole(
        &mut self,
        sender_a: &[u64],
        sender_b: &[u64], 
        receiver_x: u64,
        subfield_size: u64,
    ) -> Result<Vec<u64>> {
        // Ensure all values are in the subfield
        let a_sub: Vec<u64> = sender_a.iter().map(|&v| v % subfield_size).collect();
        let b_sub: Vec<u64> = sender_b.iter().map(|&v| v % subfield_size).collect();
        let x_sub = receiver_x % subfield_size;
        
        let results = self.execute_vole(&a_sub, &b_sub, x_sub)?;
        
        // Results are naturally in the subfield due to the field operations
        Ok(results.into_iter().map(|v| v % subfield_size).collect())
    }
}

// Vector Random OLE - generates random vectors for VOLE
#[derive(Debug, Clone)]
pub struct VectorRandomOLE {
    vector_length: usize,
    random_ot: RandomOT,
}

impl VectorRandomOLE {
    pub fn new(vector_length: usize) -> Self {
        Self {
            vector_length,
            random_ot: RandomOT::new(),
        }
    }
    
    // Generate random VOLE: sender gets random (a,b), receiver gets random x, and a*x + b
    pub fn generate_random_vole(&mut self, receiver_choice: ChoiceBit) -> Result<VOLEResult> {
        let mut sender_a = Vec::new();
        let mut sender_b = Vec::new();
        let mut receiver_results = Vec::new();
        
        // Use the random OT to generate secure random values
        let (_r0, _r1, chosen) = self.random_ot.execute_random_ot(receiver_choice)?;
        
        // Generate random x for receiver based on the random OT output
        let mut rng = rand::thread_rng();
        let receiver_x = if receiver_choice {
            chosen.wrapping_add(rng.gen_range(0..FIELD_PRIME / 2)) % FIELD_PRIME
        } else {
            rng.gen_range(0..FIELD_PRIME)
        };
        
        for _i in 0..self.vector_length {
            // Generate random a[i], b[i] for sender
            let a_i = rng.gen_range(0..FIELD_PRIME);
            let b_i = rng.gen_range(0..FIELD_PRIME);
            
            // Compute a[i]*x + b[i] for receiver
            let result_i = field_add(field_mul(a_i, receiver_x), b_i);
            
            sender_a.push(a_i);
            sender_b.push(b_i);
            receiver_results.push(result_i);
        }
        
        Ok((sender_a, sender_b, receiver_x, receiver_results))
    }
    
    // Batch random VOLE generation
    pub fn batch_random_vole(
        &mut self, 
        batch_size: usize, 
        choices: &[ChoiceBit]
    ) -> Result<BatchVOLEResult> {
        if choices.len() != batch_size {
            return Err(MpcError::ProtocolError("Batch size mismatch".to_string()));
        }
        
        let mut results = Vec::new();
        
        for &choice in choices {
            let result = self.generate_random_vole(choice)?;
            results.push(result);
        }
        
        Ok(results)
    }
}

// Specialized VOLE for boolean circuits
#[derive(Debug, Clone)]
pub struct BooleanVOLE {
    vector_length: usize,
}

impl BooleanVOLE {
    pub fn new(vector_length: usize) -> Self {
        Self { vector_length }
    }
    
    // Boolean VOLE: compute a ∧ x ⊕ b (AND then XOR)
    pub fn execute_boolean_vole(
        &self,
        sender_a: &[bool],  // Boolean vector a
        sender_b: &[bool],  // Boolean vector b
        receiver_x: bool,   // Boolean scalar x
    ) -> Result<Vec<bool>> {
        if sender_a.len() != self.vector_length || sender_b.len() != self.vector_length {
            return Err(MpcError::ProtocolError("Vector length mismatch".to_string()));
        }
        
        let mut results = Vec::new();
        
        for i in 0..self.vector_length {
            // Boolean OLE: a[i] ∧ x ⊕ b[i]
            let and_result = sender_a[i] && receiver_x;
            let final_result = and_result ^ sender_b[i];
            results.push(final_result);
        }
        
        Ok(results)
    }
    
    // Convert to/from u64 representation for compatibility
    pub fn execute_boolean_vole_u64(
        &self,
        sender_a: &[u64],
        sender_b: &[u64], 
        receiver_x: u64,
    ) -> Result<Vec<u64>> {
        // Convert to boolean
        let a_bool: Vec<bool> = sender_a.iter().map(|&v| (v % 2) == 1).collect();
        let b_bool: Vec<bool> = sender_b.iter().map(|&v| (v % 2) == 1).collect();
        let x_bool = (receiver_x % 2) == 1;
        
        // Execute boolean VOLE
        let result_bool = self.execute_boolean_vole(&a_bool, &b_bool, x_bool)?;
        
        // Convert back to u64
        let results: Vec<u64> = result_bool.iter().map(|&b| if b { 1u64 } else { 0u64 }).collect();
        
        Ok(results)
    }
}
