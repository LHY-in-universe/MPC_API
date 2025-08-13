//! Oblivious Linear Function Evaluation (不经意线性函数计算)
//! 
//! OLE allows computing f(x) = a*x + b where a,b are scalars controlled by sender
//! and x is a scalar controlled by receiver. Receiver learns f(x) but not a,b.

use super::*;
use crate::secret_sharing::{field_add, field_mul, field_sub};

#[derive(Debug, Clone)]
pub struct ObliviousLinearEvaluation {
    pub setup: DHOTSetup,
}

impl ObliviousLinearEvaluation {
    pub fn new() -> Self {
        Self {
            setup: DHOTSetup::new(),
        }
    }
    
    // Execute OLE: f(x) = a*x + b
    pub fn execute_ole(&mut self, a: u64, b: u64, x: u64) -> Result<u64> {
        // Method 1: Using polynomial interpolation
        // We create a degree-1 polynomial f(t) = a*t + b
        // Receiver with input x learns f(x) but not a or b
        
        // For simplicity, we'll use a basic OT-based approach
        // In practice, this would use more efficient protocols
        
        // Compute f(x) = a*x + b
        let result = field_add(field_mul(a, x), b);
        
        // This is a simplified version - in a real OLE protocol,
        // the computation would be oblivious
        Ok(result)
    }
    
    // Secure OLE using OT
    pub fn secure_ole(&mut self, sender_a: u64, sender_b: u64, receiver_x: u64) -> Result<u64> {
        // Use multiple OTs to compute a*x + b securely
        // This is a simplified version of the real protocol
        
        // Method: Express x in binary and use OTs for each bit
        let x_bits = self.to_binary(receiver_x, 64);
        let mut result = sender_b; // Start with b
        
        let mut power_of_two = 1u64;
        for &bit in &x_bits {
            if bit {
                // If bit is 1, add a * 2^i to result
                let contribution = field_mul(sender_a, power_of_two);
                result = field_add(result, contribution);
            }
            power_of_two = field_mul(power_of_two, 2);
            if power_of_two >= FIELD_PRIME {
                break;
            }
        }
        
        Ok(result)
    }
    
    // Convert number to binary representation
    fn to_binary(&self, mut num: u64, bits: usize) -> Vec<bool> {
        let mut binary = Vec::new();
        for _ in 0..bits {
            binary.push((num & 1) == 1);
            num >>= 1;
            if num == 0 {
                break;
            }
        }
        binary
    }
    
    // Batch OLE for multiple evaluations
    pub fn batch_ole(&mut self, params: &[(u64, u64, u64)]) -> Result<Vec<u64>> {
        let mut results = Vec::new();
        
        for &(a, b, x) in params {
            let result = self.execute_ole(a, b, x)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    // OLE with preprocessing - generates random OLE correlations
    pub fn preprocess_ole(&mut self) -> Result<(u64, u64, u64, u64)> {
        let mut rng = rand::thread_rng();
        
        // Generate random a, b, x
        let a = rng.gen_range(0..FIELD_PRIME);
        let b = rng.gen_range(0..FIELD_PRIME);
        let x = rng.gen_range(0..FIELD_PRIME);
        
        // Compute y = a*x + b
        let y = field_add(field_mul(a, x), b);
        
        Ok((a, b, x, y))
    }
    
    // Use preprocessed correlations for efficient OLE
    pub fn ole_from_preprocessing(
        &self,
        target_a: u64,
        target_b: u64,
        target_x: u64,
        preprocess_a: u64,
        preprocess_b: u64,
        preprocess_x: u64,
        preprocess_y: u64,
    ) -> Result<u64> {
        // Use preprocessing to compute target_a * target_x + target_b
        // This involves some additional protocol steps in practice
        
        // For now, just compute directly (this would be oblivious in real implementation)
        let delta_a = field_sub(target_a, preprocess_a);
        let delta_b = field_sub(target_b, preprocess_b);
        let delta_x = field_sub(target_x, preprocess_x);
        
        // Reconstruct result using preprocessing
        let base_result = preprocess_y; // a*x + b from preprocessing
        let correction = field_add(
            field_mul(delta_a, target_x),
            field_add(
                field_mul(preprocess_a, delta_x),
                delta_b
            )
        );
        
        Ok(field_add(base_result, correction))
    }
}

impl Default for ObliviousLinearEvaluation {
    fn default() -> Self {
        Self::new()
    }
}

// Specialized OLE for specific use cases
#[derive(Debug, Clone)]
pub struct BooleanOLE {
    inner: ObliviousLinearEvaluation,
}

impl BooleanOLE {
    pub fn new() -> Self {
        Self {
            inner: ObliviousLinearEvaluation::new(),
        }
    }
    
    // Boolean OLE: compute a ∧ x ⊕ b
    pub fn execute_boolean_ole(&mut self, a: bool, b: bool, x: bool) -> Result<bool> {
        // Convert to field elements
        let a_field = if a { 1u64 } else { 0u64 };
        let b_field = if b { 1u64 } else { 0u64 };
        let x_field = if x { 1u64 } else { 0u64 };
        
        // Execute OLE in the field
        let result_field = self.inner.execute_ole(a_field, b_field, x_field)?;
        
        // Convert back to boolean
        Ok((result_field % 2) == 1)
    }
    
    // Batch boolean OLE
    pub fn batch_boolean_ole(&mut self, params: &[(bool, bool, bool)]) -> Result<Vec<bool>> {
        let mut results = Vec::new();
        
        for &(a, b, x) in params {
            let result = self.execute_boolean_ole(a, b, x)?;
            results.push(result);
        }
        
        Ok(results)
    }
}

impl Default for BooleanOLE {
    fn default() -> Self {
        Self::new()
    }
}

// Random OLE - generates random linear correlations
#[derive(Debug, Clone)]
pub struct RandomOLE {
    inner: ObliviousLinearEvaluation,
}

impl RandomOLE {
    pub fn new() -> Self {
        Self {
            inner: ObliviousLinearEvaluation::new(),
        }
    }
    
    // Generate random OLE correlation
    pub fn generate_random_ole(&mut self) -> Result<(u64, u64, u64, u64)> {
        self.inner.preprocess_ole()
    }
    
    // Generate multiple random OLE correlations
    pub fn batch_random_ole(&mut self, count: usize) -> Result<Vec<(u64, u64, u64, u64)>> {
        let mut correlations = Vec::new();
        
        for _ in 0..count {
            let correlation = self.generate_random_ole()?;
            correlations.push(correlation);
        }
        
        Ok(correlations)
    }
    
    // Convert OLE correlation to additive shares
    pub fn ole_to_additive_shares(&self, a: u64, b: u64, x: u64, y: u64) -> (u64, u64) {
        // Split y = a*x + b into additive shares
        let mut rng = rand::thread_rng();
        let share1 = rng.gen_range(0..FIELD_PRIME);
        let share2 = field_sub(y, share1);
        
        (share1, share2)
    }
    
    // Convert OLE correlation to XOR shares (for boolean case)
    pub fn ole_to_xor_shares(&self, a: bool, b: bool, x: bool, y: bool) -> (bool, bool) {
        // Split y = (a ∧ x) ⊕ b into XOR shares
        let mut rng = rand::thread_rng();
        let share1 = rng.gen::<bool>();
        let share2 = y ^ share1;
        
        (share1, share2)
    }
}

impl Default for RandomOLE {
    fn default() -> Self {
        Self::new()
    }
}

// OLE-based multiplication protocol
#[derive(Debug, Clone)]
pub struct OLEMultiplication {
    ole: ObliviousLinearEvaluation,
}

impl OLEMultiplication {
    pub fn new() -> Self {
        Self {
            ole: ObliviousLinearEvaluation::new(),
        }
    }
    
    // Use OLE to compute multiplication: party A has x, party B has y, compute x*y
    pub fn multiply_using_ole(&mut self, x: u64, y: u64) -> Result<u64> {
        // Method: Use OLE with a=y, b=0, input=x to compute y*x + 0 = x*y
        self.ole.execute_ole(y, 0, x)
    }
    
    // Secure multiplication using random OLE preprocessing
    pub fn secure_multiply(
        &mut self,
        x: u64,
        y: u64,
        random_a: u64,
        random_b: u64,
        random_x: u64,
        random_y: u64,
    ) -> Result<u64> {
        // Use preprocessing to compute x*y securely
        // This is a simplified version of the actual protocol
        
        self.ole.ole_from_preprocessing(
            y,    // target_a = y (we want to compute y*x)
            0,    // target_b = 0
            x,    // target_x = x
            random_a,
            random_b,
            random_x,
            random_y,
        )
    }
}

impl Default for OLEMultiplication {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_ole() {
        let mut ole = ObliviousLinearEvaluation::new();
        
        let a = 5u64;
        let b = 3u64;
        let x = 7u64;
        
        let result = ole.execute_ole(a, b, x).unwrap();
        let expected = field_add(field_mul(a, x), b); // 5*7 + 3 = 38
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_secure_ole() {
        let mut ole = ObliviousLinearEvaluation::new();
        
        let a = 10u64;
        let b = 5u64;
        let x = 3u64;
        
        let result = ole.secure_ole(a, b, x).unwrap();
        let expected = field_add(field_mul(a, x), b); // 10*3 + 5 = 35
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_batch_ole() {
        let mut ole = ObliviousLinearEvaluation::new();
        
        let params = vec![
            (2, 3, 4), // 2*4 + 3 = 11
            (5, 1, 2), // 5*2 + 1 = 11
            (3, 0, 7), // 3*7 + 0 = 21
        ];
        
        let results = ole.batch_ole(&params).unwrap();
        
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], field_add(field_mul(2, 4), 3));
        assert_eq!(results[1], field_add(field_mul(5, 2), 1));
        assert_eq!(results[2], field_add(field_mul(3, 7), 0));
    }
    
    #[test]
    fn test_boolean_ole() {
        let mut bool_ole = BooleanOLE::new();
        
        // Test all combinations
        let test_cases = [
            (false, false, false, false), // 0∧0⊕0 = 0
            (false, false, true, false),  // 0∧1⊕0 = 0
            (false, true, false, true),   // 0∧0⊕1 = 1
            (false, true, true, true),    // 0∧1⊕1 = 1
            (true, false, false, false),  // 1∧0⊕0 = 0
            (true, false, true, true),    // 1∧1⊕0 = 1
            (true, true, false, true),    // 1∧0⊕1 = 1
            (true, true, true, false),    // 1∧1⊕1 = 0
        ];
        
        for (a, b, x, expected) in test_cases.iter() {
            let result = bool_ole.execute_boolean_ole(*a, *b, *x).unwrap();
            assert_eq!(result, *expected, "Failed for a={}, b={}, x={}", a, b, x);
        }
    }
    
    #[test]
    fn test_ole_preprocessing() {
        let mut ole = ObliviousLinearEvaluation::new();
        
        let (a, b, x, y) = ole.preprocess_ole().unwrap();
        
        // Verify that y = a*x + b
        let expected_y = field_add(field_mul(a, x), b);
        assert_eq!(y, expected_y);
    }
    
    #[test]
    fn test_ole_from_preprocessing() {
        let ole = ObliviousLinearEvaluation::new();
        
        // Setup preprocessing
        let preprocess_a = 2u64;
        let preprocess_b = 3u64;
        let preprocess_x = 4u64;
        let preprocess_y = field_add(field_mul(preprocess_a, preprocess_x), preprocess_b); // 2*4+3=11
        
        // Target computation
        let target_a = 5u64;
        let target_b = 1u64;
        let target_x = 3u64;
        
        let result = ole.ole_from_preprocessing(
            target_a, target_b, target_x,
            preprocess_a, preprocess_b, preprocess_x, preprocess_y
        ).unwrap();
        
        let expected = field_add(field_mul(target_a, target_x), target_b); // 5*3+1=16
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_random_ole() {
        let mut random_ole = RandomOLE::new();
        
        let correlations = random_ole.batch_random_ole(5).unwrap();
        assert_eq!(correlations.len(), 5);
        
        // Verify each correlation
        for (a, b, x, y) in correlations {
            let expected_y = field_add(field_mul(a, x), b);
            assert_eq!(y, expected_y);
        }
    }
    
    #[test]
    fn test_ole_multiplication() {
        let mut ole_mult = OLEMultiplication::new();
        
        let x = 6u64;
        let y = 7u64;
        
        let result = ole_mult.multiply_using_ole(x, y).unwrap();
        let expected = field_mul(x, y); // 6*7 = 42
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_ole_shares() {
        let random_ole = RandomOLE::new();
        
        // Test additive shares
        let (share1, share2) = random_ole.ole_to_additive_shares(10, 20, 30, 40);
        assert_eq!(field_add(share1, share2), 40);
        
        // Test XOR shares
        let (xor_share1, xor_share2) = random_ole.ole_to_xor_shares(true, false, true, true);
        assert_eq!(xor_share1 ^ xor_share2, true);
    }
}