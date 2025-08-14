//! Basic 1-out-of-2 Oblivious Transfer implementation
//! 
//! Implements the classic Diffie-Hellman based OT protocol

use super::*;

#[derive(Debug, Clone)]
pub struct BasicOT {
    pub setup: DHOTSetup,
    pub sender_messages: Option<(OTMessage, OTMessage)>,
    pub receiver_choice: Option<ChoiceBit>,
    sender_public_key: Option<u64>,
}

impl BasicOT {
    pub fn new() -> Self {
        Self {
            setup: DHOTSetup::new(),
            sender_messages: None,
            receiver_choice: None,
            sender_public_key: None,
        }
    }
    
    pub fn sender_phase1(&mut self, msg0: OTMessage, msg1: OTMessage) -> Result<u64> {
        self.sender_messages = Some((msg0, msg1));
        
        // Sender computes g^a and sends it
        let sender_public = self.setup.pow_mod(self.setup.generator, self.setup.sender_private);
        Ok(sender_public)
    }
    
    pub fn receiver_phase1(&mut self, choice: ChoiceBit, sender_public: u64) -> Result<u64> {
        self.receiver_choice = Some(choice);
        self.sender_public_key = Some(sender_public);
        
        // Receiver computes either g^b or (g^a * g^b) based on choice
        let receiver_private_exp = self.setup.pow_mod(self.setup.generator, self.setup.receiver_private);
        
        let receiver_public = if choice {
            // Choice = 1: send g^a * g^b = g^(a+b)
            field_mul(sender_public, receiver_private_exp)
        } else {
            // Choice = 0: send g^b
            receiver_private_exp
        };
        
        Ok(receiver_public)
    }
    
    pub fn sender_phase2(&self, receiver_public: u64) -> Result<(OTMessage, OTMessage)> {
        let (msg0, msg1) = self.sender_messages.as_ref()
            .ok_or_else(|| MpcError::ProtocolError("Sender messages not set".to_string()))?;
        
        // Compute shared secrets
        // k0 = (receiver_public)^a = g^(ab) if choice=0, g^(a(a+b)) if choice=1
        // k1 = (receiver_public / g^a)^a = g^(ab) if choice=1, undefined if choice=0
        
        let sender_public = self.setup.pow_mod(self.setup.generator, self.setup.sender_private);
        
        // For choice = 0: receiver_public = g^b, so k0 = (g^b)^a = g^(ab)
        let k0 = self.setup.pow_mod(receiver_public, self.setup.sender_private);
        
        // For choice = 1: receiver_public = g^(a+b), so we need g^b = receiver_public / g^a
        let g_b = field_mul(receiver_public, self.mod_inverse(sender_public)?);
        let k1 = self.setup.pow_mod(g_b, self.setup.sender_private);
        
        // Encrypt messages
        let key0 = hash_to_bytes(k0);
        let key1 = hash_to_bytes(k1);
        
        let encrypted_msg0 = xor_bytes(msg0, &key0[..msg0.len().min(key0.len())]);
        let encrypted_msg1 = xor_bytes(msg1, &key1[..msg1.len().min(key1.len())]);
        
        Ok((encrypted_msg0, encrypted_msg1))
    }
    
    pub fn receiver_phase2(&self, encrypted_messages: (OTMessage, OTMessage)) -> Result<OTMessage> {
        let choice = self.receiver_choice
            .ok_or_else(|| MpcError::ProtocolError("Receiver choice not set".to_string()))?;
        let sender_public = self.sender_public_key
            .ok_or_else(|| MpcError::ProtocolError("Sender public key not stored".to_string()))?;
        
        // Receiver computes the shared secret g^(ab)
        // The receiver knows their private key b, and has the sender's public key g^a
        let shared_secret = self.setup.pow_mod(sender_public, self.setup.receiver_private);
        
        let key = hash_to_bytes(shared_secret);
        
        let encrypted_msg = if choice {
            &encrypted_messages.1
        } else {
            &encrypted_messages.0
        };
        
        let decrypted = xor_bytes(encrypted_msg, &key[..encrypted_msg.len().min(key.len())]);
        Ok(decrypted)
    }
    
    fn mod_inverse(&self, a: u64) -> Result<u64> {
        // Extended Euclidean algorithm for modular inverse
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
}

impl Default for BasicOT {
    fn default() -> Self {
        Self::new()
    }
}

// Complete OT protocol execution
pub fn execute_basic_ot(
    msg0: OTMessage,
    msg1: OTMessage,
    choice: ChoiceBit,
) -> Result<OTMessage> {
    let mut sender = BasicOT::new();
    let mut receiver = BasicOT::new();
    
    // Copy setup parameters for consistency
    receiver.setup = sender.setup.clone();
    
    // Phase 1: Setup
    let sender_public = sender.sender_phase1(msg0, msg1)?;
    let receiver_public = receiver.receiver_phase1(choice, sender_public)?;
    
    // Phase 2: Transfer
    let encrypted_messages = sender.sender_phase2(receiver_public)?;
    let result = receiver.receiver_phase2(encrypted_messages)?;
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_ot_choice_0() {
        let msg0 = b"Message 0".to_vec();
        let msg1 = b"Message 1".to_vec();
        let choice = false; // Choose msg0
        
        let result = execute_basic_ot(msg0.clone(), msg1, choice).unwrap();
        assert_eq!(result, msg0);
    }
    
    #[test]
    fn test_basic_ot_choice_1() {
        let msg0 = b"Message 0".to_vec();
        let msg1 = b"Message 1".to_vec();
        let choice = true; // Choose msg1
        
        let result = execute_basic_ot(msg0, msg1.clone(), choice).unwrap();
        assert_eq!(result, msg1);
    }
    
    #[test]
    fn test_basic_ot_different_lengths() {
        let msg0 = b"Short".to_vec();
        let msg1 = b"This is a much longer message".to_vec();
        let choice = true;
        
        let result = execute_basic_ot(msg0, msg1.clone(), choice).unwrap();
        assert_eq!(result, msg1);
    }
    
    #[test]
    fn test_basic_ot_empty_messages() {
        let msg0 = Vec::new();
        let msg1 = b"Only one".to_vec();
        let choice = false;
        
        let result = execute_basic_ot(msg0.clone(), msg1, choice).unwrap();
        assert_eq!(result, msg0);
    }
    
    #[test]
    fn test_modular_inverse() {
        let ot = BasicOT::new();
        let a = 123u64;
        let inv = ot.mod_inverse(a).unwrap();
        let product = field_mul(a, inv);
        assert_eq!(product, 1);
    }
}