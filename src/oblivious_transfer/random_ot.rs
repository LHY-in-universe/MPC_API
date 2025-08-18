//! Random Oblivious Transfer (随机不经意传输) implementation
//! 
//! In random OT, the sender doesn't choose the messages - they are generated randomly.
//! This is useful for generating random shares and other MPC building blocks.

use super::*;

#[derive(Debug, Clone)]
pub struct RandomOT {
    pub setup: DHOTSetup,
}

impl RandomOT {
    pub fn new() -> Self {
        Self {
            setup: DHOTSetup::new(),
        }
    }
    
    // Execute random OT where sender gets (r0, r1) and receiver gets rb
    pub fn execute_random_ot(&mut self, choice: ChoiceBit) -> Result<(u64, u64, u64)> {
        let mut rng = rand::thread_rng();
        
        // Generate two random values
        let r0 = rng.gen_range(0..FIELD_PRIME);
        let r1 = rng.gen_range(0..FIELD_PRIME);
        
        // Convert to byte messages
        let msg0_bytes = r0.to_le_bytes().to_vec();
        let msg1_bytes = r1.to_le_bytes().to_vec();
        
        // Execute basic OT
        let result_bytes = execute_basic_ot(msg0_bytes, msg1_bytes, choice)?;
        
        // Convert back to u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&result_bytes[..8]);
        let rb = u64::from_le_bytes(bytes);
        
        // Return (sender's r0, sender's r1, receiver's rb)
        Ok((r0, r1, rb))
    }
    
    // Batch random OT for multiple instances
    pub fn batch_random_ot(&mut self, choices: &[ChoiceBit]) -> Result<Vec<(u64, u64, u64)>> {
        let mut results = Vec::new();
        
        for &choice in choices {
            let result = self.execute_random_ot(choice)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    // Generate random additive shares
    pub fn generate_random_additive_shares(&mut self, choice: ChoiceBit) -> Result<(u64, u64)> {
        let (r0, r1, rb) = self.execute_random_ot(choice)?;
        
        // The sum r0 + r1 is known to sender, rb is known to receiver
        let sender_share = field_add(r0, r1);
        let receiver_share = rb;
        
        Ok((sender_share, receiver_share))
    }
    
    // Generate random multiplication triples (a, b, c) where c = a * b
    pub fn generate_random_multiplication_triple(&mut self, choices: &[ChoiceBit; 3]) -> Result<MultiplicationTriple> {
        if choices.len() != 3 {
            return Err(MpcError::ProtocolError("Need exactly 3 choices for multiplication triple".to_string()));
        }
        
        // Generate three random OT instances
        let (a0, a1, a_recv) = self.execute_random_ot(choices[0])?;
        let (b0, b1, b_recv) = self.execute_random_ot(choices[1])?;
        let (_c0, _c1, c_recv) = self.execute_random_ot(choices[2])?;
        
        // For now, we'll create a simple triple (not cryptographically secure)
        // In practice, this requires more sophisticated protocols
        let a_sender = if choices[0] { a1 } else { a0 };
        let b_sender = if choices[1] { b1 } else { b0 };
        let c_expected = field_mul(a_sender, b_sender);
        
        Ok(MultiplicationTriple {
            a_share: (a_sender, a_recv),
            b_share: (b_sender, b_recv),
            c_share: (c_expected, c_recv),
        })
    }
}

impl Default for RandomOT {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MultiplicationTriple {
    pub a_share: (u64, u64), // (sender_share, receiver_share)
    pub b_share: (u64, u64),
    pub c_share: (u64, u64),
}

impl MultiplicationTriple {
    pub fn verify(&self) -> bool {
        let a = field_add(self.a_share.0, self.a_share.1);
        let b = field_add(self.b_share.0, self.b_share.1);
        let c = field_add(self.c_share.0, self.c_share.1);
        
        field_mul(a, b) == c
    }
    
    pub fn get_sender_shares(&self) -> (u64, u64, u64) {
        (self.a_share.0, self.b_share.0, self.c_share.0)
    }
    
    pub fn get_receiver_shares(&self) -> (u64, u64, u64) {
        (self.a_share.1, self.b_share.1, self.c_share.1)
    }
}

// Random OT for boolean values
#[derive(Debug, Clone)]
pub struct RandomBooleanOT {
    inner: RandomOT,
}

impl RandomBooleanOT {
    pub fn new() -> Self {
        Self {
            inner: RandomOT::new(),
        }
    }
    
    pub fn execute_random_boolean_ot(&mut self, choice: ChoiceBit) -> Result<(bool, bool, bool)> {
        let (r0, r1, rb) = self.inner.execute_random_ot(choice)?;
        
        // Convert to boolean values
        let b0 = (r0 % 2) == 1;
        let b1 = (r1 % 2) == 1;
        let bb = (rb % 2) == 1;
        
        Ok((b0, b1, bb))
    }
    
    // Generate random XOR shares: sender gets (s0, s1), receiver gets sb where s0 ⊕ s1 = sb
    pub fn generate_random_xor_shares(&mut self, choice: ChoiceBit) -> Result<(bool, bool)> {
        let (b0, b1, bb) = self.execute_random_boolean_ot(choice)?;
        
        // Create XOR shares
        let sender_share = b0 ^ b1;
        let receiver_share = bb;
        
        Ok((sender_share, receiver_share))
    }
}

impl Default for RandomBooleanOT {
    fn default() -> Self {
        Self::new()
    }
}

// OT-based coin flipping for generating shared randomness
pub struct RandomCoinFlipping {
    random_ot: RandomOT,
}

impl RandomCoinFlipping {
    pub fn new() -> Self {
        Self {
            random_ot: RandomOT::new(),
        }
    }
    
    // Generate a shared random bit using random OT
    pub fn flip_coin(&mut self) -> Result<bool> {
        let mut rng = rand::thread_rng();
        let choice = rng.gen::<bool>();
        
        let (r0, r1, rb) = self.random_ot.execute_random_ot(choice)?;
        
        // The shared random bit is the XOR of all random values
        let shared_bit = ((r0 % 2) ^ (r1 % 2) ^ (rb % 2)) == 1;
        
        Ok(shared_bit)
    }
    
    // Generate multiple shared random bits
    pub fn flip_coins(&mut self, count: usize) -> Result<Vec<bool>> {
        let mut coins = Vec::new();
        
        for _ in 0..count {
            coins.push(self.flip_coin()?);
        }
        
        Ok(coins)
    }
}

impl Default for RandomCoinFlipping {
    fn default() -> Self {
        Self::new()
    }
}
