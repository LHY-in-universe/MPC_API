use mpc_api::beaver_triples::protocol_messages::*;
use mpc_api::homomorphic_encryption::BFVCiphertext;

#[test]
fn test_protocol_context_creation() {
    let config = BFVBeaverConfig::default();
    let context = BFVBeaverProtocolContext::new(config, 0);
    
    assert_eq!(context.party_id, 0);
    assert_eq!(context.state, ProtocolState::Initialized);
    assert_eq!(context.current_round, ProtocolRound::ThresholdKeyGen);
}

#[test]
fn test_round_advancement() {
    let config = BFVBeaverConfig::default();
    let mut context = BFVBeaverProtocolContext::new(config, 0);
    
    assert_eq!(context.current_round, ProtocolRound::ThresholdKeyGen);
    
    context.advance_round().unwrap();
    assert_eq!(context.current_round, ProtocolRound::EncryptedShares);
    
    context.advance_round().unwrap();
    assert_eq!(context.current_round, ProtocolRound::HomomorphicAggregation);
}

#[test]
fn test_message_validation() {
    let msg = BFVBeaverMessage::EncryptedShares {
        party_id: 1,
        enc_a_i: BFVCiphertext { c0: vec![1, 2, 3], c1: vec![4, 5, 6] },
        enc_b_i: BFVCiphertext { c0: vec![7, 8, 9], c1: vec![10, 11, 12] },
        commitment: vec![1, 2, 3, 4],
    };
    
    assert!(msg.validate().is_ok());
    assert!(msg.verify_sender(1).is_ok());
    assert!(msg.verify_sender(2).is_err());
}