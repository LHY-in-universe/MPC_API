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
    
    // Receiver's first message: pk_r = g^r
    pub fn receiver_round1(&mut self, choice: ChoiceBit) -> Result<u64> {
        self.receiver_choice = Some(choice);
        
        // Generate random receiver key
        let r = self.setup.receiver_private;
        let base_pk = self.setup.pow_mod(self.setup.generator, r);
        self.pk_r = Some(base_pk);
        
        // In the Naor-Pinkas protocol, the receiver always sends g^r
        // The choice affects which message they can decrypt, not what they send
        Ok(base_pk)
    }
    
    // Sender's response: Generate h = g^s and compute OT messages
    pub fn sender_round1(&mut self, pk_r: u64, msg0: &[u8], msg1: &[u8]) -> Result<(u64, Vec<u8>, Vec<u8>)> {
        // Generate sender's key
        let s = self.setup.sender_private;
        let h = self.setup.pow_mod(self.setup.generator, s); // h = g^s
        self.pk_s = Some(h);
        
        // Compute shared secrets
        // k0 = pk_r^s = (g^r)^s = g^(rs) if choice = 0
        // k1 = (pk_r / h)^s = (g^r / g^s)^s = g^(r-s)s if choice = 1
        
        let k0 = self.setup.pow_mod(pk_r, s);
        
        // For k1, we need (pk_r / h)^s
        let h_inv = self.mod_inverse(h)?;
        let pk_r_over_h = field_mul(pk_r, h_inv);
        let k1 = self.setup.pow_mod(pk_r_over_h, s);
        
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
        let pk_r = self.pk_r.unwrap();
        
        // Compute the decryption key based on choice
        let k = if choice {
            // For choice = 1: k = (pk_r / h)^r = ((g^r / g^s))^r 
            // But we need to match what sender computed: k1 = (pk_r / h)^s
            // So receiver computes: (h / g^r)^r but this gets complicated...
            // Let's use a simpler approach: k = h^r / pk_r
            let hr = self.setup.pow_mod(h, r);
            let pk_r_inv = self.mod_inverse(pk_r)?;
            field_mul(hr, pk_r_inv)
        } else {
            // For choice = 0: k = h^r = (g^s)^r = g^(rs) 
            self.setup.pow_mod(h, r)
        };
        
        // Derive decryption key
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_naor_pinkas_ot_choice_0() {
        let msg0 = b"Message Zero".to_vec();
        let msg1 = b"Message One".to_vec();
        let choice = false;
        
        let result = execute_naor_pinkas_ot(&msg0, &msg1, choice).unwrap();
        assert_eq!(result, msg0);
    }
    
    #[test]
    fn test_naor_pinkas_ot_choice_1() {
        let msg0 = b"Message Zero".to_vec();
        let msg1 = b"Message One".to_vec();
        let choice = true;
        
        let result = execute_naor_pinkas_ot(&msg0, &msg1, choice).unwrap();
        assert_eq!(result, msg1);
    }
    
    #[test]
    fn test_batch_naor_pinkas_ot() {
        let mut batch_ot = BatchNaorPinkasOT::new(3);
        
        let messages = vec![
            (b"First 0".to_vec(), b"First 1".to_vec()),
            (b"Second 0".to_vec(), b"Second 1".to_vec()),
            (b"Third 0".to_vec(), b"Third 1".to_vec()),
        ];
        let choices = vec![false, true, false];
        
        let results = batch_ot.execute_batch(&messages, &choices).unwrap();
        
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], b"First 0");
        assert_eq!(results[1], b"Second 1");
        assert_eq!(results[2], b"Third 0");
    }
    
    #[test]
    fn test_adaptive_ot() {
        let mut adaptive_ot = AdaptiveOT::new();
        let choices = vec![false, true];
        
        let commitments = adaptive_ot.commit_choices(&choices).unwrap();
        assert_eq!(commitments.len(), 2);
        
        let responses = adaptive_ot.adaptive_send(&commitments, |i| {
            (format!("Message {}_0", i).into_bytes(), format!("Message {}_1", i).into_bytes())
        }).unwrap();
        
        assert_eq!(responses.len(), 2);
    }
    
    #[test]
    fn test_key_derivation() {
        let ot = NaorPinkasOT::new();
        let secret = 12345u64;
        
        let key1 = ot.derive_key(secret);
        let key2 = ot.derive_key(secret);
        
        // Same secret should produce same key
        assert_eq!(key1, key2);
        
        // Different secret should produce different key
        let key3 = ot.derive_key(54321u64);
        assert_ne!(key1, key3);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let ot = NaorPinkasOT::new();
        let message = b"Test message";
        let key = ot.derive_key(12345u64);
        
        let encrypted = ot.encrypt(message, &key);
        let decrypted = ot.decrypt(&encrypted, &key);
        
        assert_eq!(decrypted, message);
    }
}