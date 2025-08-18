//! Naor-Pinkas OT implementation
//! 
//! Efficient OT protocol based on DDH assumption

use super::*;

// Type alias for complex return type
pub type NPOTResult = (u64, Vec<u8>, Vec<u8>);

#[derive(Debug, Clone)]
pub struct NaorPinkasOT {
    pub setup: DHOTSetup,
    pub pk_r: Option<u64>,  // Receiver's public key
    pub pk_s: Option<u64>,  // Sender's public key
    pub receiver_choice: Option<ChoiceBit>, // Receiver's choice
}

impl NaorPinkasOT {
    pub fn new() -> Self {
        Self {
            setup: DHOTSetup::new(),
            pk_r: None,
            pk_s: None,
            receiver_choice: None,
        }
    }
    
    // Receiver's first message: pk_r = g^r if choice=0, g^(r+1) if choice=1
    pub fn receiver_round1(&mut self, choice: ChoiceBit) -> Result<u64> {
        self.receiver_choice = Some(choice);
        
        // Generate random receiver key
        let r = self.setup.receiver_private;
        
        // Standard Naor-Pinkas: modify the public key based on choice
        let exponent = if choice {
            field_add(r, 1) // r + 1 for choice = 1
        } else {
            r // r for choice = 0
        };
        
        let pk_r = self.setup.pow_mod(self.setup.generator, exponent);
        self.pk_r = Some(pk_r);
        
        Ok(pk_r)
    }
    
    // Sender's response: Generate h = g^s and compute OT messages
    pub fn sender_round1(&mut self, pk_r: u64, msg0: &[u8], msg1: &[u8]) -> Result<(u64, Vec<u8>, Vec<u8>)> {
        // Generate sender's key
        let s = self.setup.sender_private;
        let h = self.setup.pow_mod(self.setup.generator, s); // h = g^s
        self.pk_s = Some(h);
        
        // In standard Naor-Pinkas:
        // If receiver chose 0: pk_r = g^r, so k0 = pk_r^s = g^(rs)
        // If receiver chose 1: pk_r = g^(r+1), so k1 = pk_r^s = g^((r+1)s)
        // 
        // The sender computes:
        // k0 = pk_r^s (works if receiver sent g^r)  
        // k1 = (pk_r / g)^s (works if receiver sent g^(r+1))
        
        let k0 = self.setup.pow_mod(pk_r, s);
        
        // For k1: if pk_r = g^(r+1), then pk_r/g = g^r, so (pk_r/g)^s = g^(rs)
        let g_inv = self.mod_inverse(self.setup.generator)?;
        let pk_r_over_g = field_mul(pk_r, g_inv);
        let k1 = self.setup.pow_mod(pk_r_over_g, s);
        
        // Encrypt messages
        let key0 = self.derive_key(k0);
        let key1 = self.derive_key(k1);
        
        let enc_msg0 = self.encrypt(msg0, &key0);
        let enc_msg1 = self.encrypt(msg1, &key1);
        
        Ok((h, enc_msg0, enc_msg1))
    }
    
    // Receiver's final step: Decrypt the chosen message
    pub fn receiver_round2(&self, h: u64, choice: ChoiceBit, enc_msg0: &[u8], enc_msg1: &[u8]) -> Result<Vec<u8>> {
        let r = self.setup.receiver_private;
        
        // In the corrected Naor-Pinkas protocol:
        // - If choice = 0: receiver sent g^r, so can compute k0 = h^r = (g^s)^r = g^(rs)
        // - If choice = 1: receiver sent g^(r+1), so can compute k1 = h^r = (g^s)^r = g^(rs)
        // 
        // The key is always h^r = g^(rs), but the receiver can only decrypt
        // the message corresponding to their choice.
        
        let k = self.setup.pow_mod(h, r);
        let key = self.derive_key(k);
        
        // Decrypt the appropriate message based on choice
        let decrypted = if choice {
            self.decrypt(enc_msg1, &key)
        } else {
            self.decrypt(enc_msg0, &key)
        };
        
        Ok(decrypted)
    }
    
    fn mod_inverse(&self, a: u64) -> Result<u64> {
        let mut old_r = a as i128;
        let mut r = self.setup.prime as i128;
        let mut old_s = 1i128;
        let mut s = 0i128;
        
        while r != 0 {
            let quotient = old_r / r;
            let temp_r = r;
            r = old_r - quotient * r;
            old_r = temp_r;
            
            let temp_s = s;
            s = old_s - quotient * s;
            old_s = temp_s;
        }
        
        if old_r == 1 {
            let result = if old_s < 0 {
                (old_s + self.setup.prime as i128) as u64
            } else {
                old_s as u64
            };
            Ok(result)
        } else {
            Err(MpcError::CryptographicError("No modular inverse exists".to_string()))
        }
    }
    
    fn derive_key(&self, shared_secret: u64) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.to_le_bytes());
        hasher.finalize().to_vec()
    }
    
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        xor_bytes(plaintext, &key[..plaintext.len().min(key.len())])
    }
    
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        xor_bytes(ciphertext, &key[..ciphertext.len().min(key.len())])
    }
}

impl Default for NaorPinkasOT {
    fn default() -> Self {
        Self::new()
    }
}

// Complete Naor-Pinkas OT execution
pub fn execute_naor_pinkas_ot(msg0: &[u8], msg1: &[u8], choice: ChoiceBit) -> Result<Vec<u8>> {
    let mut sender = NaorPinkasOT::new();
    let mut receiver = NaorPinkasOT::new();
    
    // Share the same setup parameters
    receiver.setup = sender.setup.clone();
    
    // Protocol execution
    let pk_r = receiver.receiver_round1(choice)?;
    let (h, enc_msg0, enc_msg1) = sender.sender_round1(pk_r, msg0, msg1)?;
    let result = receiver.receiver_round2(h, choice, &enc_msg0, &enc_msg1)?;
    
    Ok(result)
}

// Batch Naor-Pinkas OT for multiple instances
#[derive(Debug, Clone)]
pub struct BatchNaorPinkasOT {
    instances: Vec<NaorPinkasOT>,
}

impl BatchNaorPinkasOT {
    pub fn new(batch_size: usize) -> Self {
        let mut instances = Vec::new();
        for _ in 0..batch_size {
            instances.push(NaorPinkasOT::new());
        }
        
        Self { instances }
    }
    
    pub fn execute_batch(
        &mut self,
        messages: &[(Vec<u8>, Vec<u8>)], // (msg0, msg1) pairs
        choices: &[ChoiceBit],
    ) -> Result<Vec<Vec<u8>>> {
        if messages.len() != choices.len() || messages.len() != self.instances.len() {
            return Err(MpcError::ProtocolError("Batch size mismatch".to_string()));
        }
        
        let mut results = Vec::new();
        
        for ((_i, (msg0, msg1)), &choice) in messages.iter().enumerate().zip(choices.iter()) {
            let result = execute_naor_pinkas_ot(msg0, msg1, choice)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    // Optimized batch execution with shared randomness
    pub fn execute_batch_optimized(
        &mut self,
        messages: &[(Vec<u8>, Vec<u8>)],
        choices: &[ChoiceBit],
    ) -> Result<Vec<Vec<u8>>> {
        // In a real implementation, this would share random values across instances
        // For now, just call the regular batch execution
        self.execute_batch(messages, choices)
    }
}

// Adaptive OT where sender can send messages based on receiver's choices
#[derive(Debug, Clone)]
pub struct AdaptiveOT {
    base_ot: NaorPinkasOT,
}

impl AdaptiveOT {
    pub fn new() -> Self {
        Self {
            base_ot: NaorPinkasOT::new(),
        }
    }
    
    // Receiver commits to choices upfront
    pub fn commit_choices(&mut self, choices: &[ChoiceBit]) -> Result<Vec<u64>> {
        let mut commitments = Vec::new();
        
        for &choice in choices {
            let pk_r = self.base_ot.receiver_round1(choice)?;
            commitments.push(pk_r);
        }
        
        Ok(commitments)
    }
    
    // Sender responds adaptively based on receiver's commitments
    pub fn adaptive_send(
        &mut self,
        commitments: &[u64],
        message_generator: impl Fn(usize) -> (Vec<u8>, Vec<u8>),
    ) -> Result<Vec<NPOTResult>> {
        let mut responses = Vec::new();
        
        for (i, &commitment) in commitments.iter().enumerate() {
            let (msg0, msg1) = message_generator(i);
            let (h, enc_msg0, enc_msg1) = self.base_ot.sender_round1(commitment, &msg0, &msg1)?;
            responses.push((h, enc_msg0, enc_msg1));
        }
        
        Ok(responses)
    }
}

impl Default for AdaptiveOT {
    fn default() -> Self {
        Self::new()
    }
}
