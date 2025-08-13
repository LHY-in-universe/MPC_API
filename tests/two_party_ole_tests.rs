use mpc_api::beaver_triples::two_party_ole::*;
use mpc_api::beaver_triples::{secure_multiply, BeaverTripleGenerator};
use mpc_api::secret_sharing::{ShamirSecretSharing, SecretSharing, field_mul, FIELD_PRIME};

#[test]
fn test_two_party_protocol_creation() {
    let p1_protocol = TwoPartyOLEProtocol::new(PartyRole::P1);
    let p2_protocol = TwoPartyOLEProtocol::new(PartyRole::PN);
    
    assert_eq!(p1_protocol.get_role(), PartyRole::P1);
    assert_eq!(p2_protocol.get_role(), PartyRole::PN);
    assert_eq!(p1_protocol.get_current_step(), ProtocolStep::RandomGeneration);
    assert_eq!(p2_protocol.get_current_step(), ProtocolStep::RandomGeneration);
}

#[test]
fn test_random_value_generation() {
    let mut protocol = TwoPartyOLEProtocol::new(PartyRole::P1);
    
    let (x, y) = protocol.step1_2_generate_random_values().unwrap();
    
    assert!(x < FIELD_PRIME);
    assert!(y < FIELD_PRIME);
    assert_eq!(protocol.get_current_step(), ProtocolStep::FirstOLE);
}

#[test]
fn test_shamir_sharing_basic() {
    // Test basic Shamir sharing functionality
    let secret = 123456u64;
    let threshold = 2;
    let party_count = 2;
    
    let shares = ShamirSecretSharing::share(&secret, threshold, party_count).unwrap();
    
    // Reconstruct with all shares
    let reconstructed = ShamirSecretSharing::reconstruct(&shares, threshold).unwrap();
    assert_eq!(secret, reconstructed);
    
    // Test reconstruction with exactly threshold shares
    let reconstructed2 = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold).unwrap();
    assert_eq!(secret, reconstructed2);
}

#[test]
fn test_two_party_generator() {
    let mut generator = TwoPartyBeaverGenerator::new();
    
    assert_eq!(generator.get_party_count(), 2);
    assert_eq!(generator.get_threshold(), 2);
    
    // 测试单个三元组生成
    let triple = generator.generate_single().unwrap();
    assert_eq!(triple.shares.len(), 2);
    
    // 验证三元组
    assert!(generator.verify_triple(&triple).unwrap());
}

#[test]  
fn test_complete_protocol_execution() {
    let mut generator = TwoPartyBeaverGenerator::new();
    
    // 执行完整协议
    let triple = generator.execute_two_party_protocol().unwrap();
    
    // 验证结果
    assert_eq!(triple.shares.len(), 2);
    assert!(triple.verify(2).unwrap());
    
    // 验证原始值的正确性
    if let Some((a, b, c)) = triple.original_values {
        assert_eq!(c, field_mul(a, b));
        assert!(a < FIELD_PRIME);
        assert!(b < FIELD_PRIME);  
        assert!(c < FIELD_PRIME);
    }
}

#[test]
fn test_message_based_protocol() {
    let mut generator = TwoPartyBeaverGenerator::new();
    
    // 执行基于消息的协议
    let triple = generator.execute_with_messages().unwrap();
    
    // 验证结果
    assert_eq!(triple.shares.len(), 2);
    assert!(triple.verify(2).unwrap());
}

#[test]
fn test_batch_generation() {
    let mut generator = TwoPartyBeaverGenerator::new();
    
    let batch_size = 3;
    let triples = generator.generate_batch(batch_size).unwrap();
    
    assert_eq!(triples.len(), batch_size);
    
    // 验证每个三元组
    for triple in &triples {
        assert!(generator.verify_triple(triple).unwrap());
    }
    
    // 验证三元组的唯一性
    let mut ids = std::collections::HashSet::new();
    for triple in &triples {
        for beaver_share in triple.shares.values() {
            assert!(ids.insert(beaver_share.id));
        }
    }
}

#[test]
fn test_protocol_step_progression() {
    let mut protocol = TwoPartyOLEProtocol::new(PartyRole::P1);
    
    // 初始状态
    assert_eq!(protocol.get_current_step(), ProtocolStep::RandomGeneration);
    assert!(!protocol.is_completed());
    
    // 步骤1-2
    protocol.step1_2_generate_random_values().unwrap();
    assert_eq!(protocol.get_current_step(), ProtocolStep::FirstOLE);
    
    // 步骤3-4  
    protocol.step3_4_first_ole(12345).unwrap();
    assert_eq!(protocol.get_current_step(), ProtocolStep::SecondOLE);
    
    // 步骤5-6
    protocol.step5_6_second_ole(67890).unwrap();
    assert_eq!(protocol.get_current_step(), ProtocolStep::FinalComputation);
    
    // 步骤7
    let triple = protocol.step7_final_computation().unwrap();
    assert_eq!(protocol.get_current_step(), ProtocolStep::Completed);
    assert!(protocol.is_completed());
    assert!(triple.verify(2).unwrap());
}

#[test]
fn test_protocol_reset() {
    let mut protocol = TwoPartyOLEProtocol::new(PartyRole::P1);
    
    // 执行几个步骤
    protocol.step1_2_generate_random_values().unwrap();
    protocol.step3_4_first_ole(123).unwrap();
    
    // 重置协议
    protocol.reset();
    
    // 验证重置后的状态
    assert_eq!(protocol.get_current_step(), ProtocolStep::RandomGeneration);
    assert!(!protocol.is_completed());
}

#[test]
fn test_secure_multiplication_with_two_party_triple() {
    let mut generator = TwoPartyBeaverGenerator::new();
    let triple = generator.generate_single().unwrap();
    
    // 创建测试输入
    let x = 15u64;
    let y = 25u64;
    let expected = field_mul(x, y);
    
    let x_shares = ShamirSecretSharing::share(&x, 2, 2).unwrap();
    let y_shares = ShamirSecretSharing::share(&y, 2, 2).unwrap();
    
    // 执行安全乘法
    let result_shares = secure_multiply(&x_shares, &y_shares, &triple, 2).unwrap();
    
    // 重构结果  
    let result = ShamirSecretSharing::reconstruct(&result_shares, 2).unwrap();
    
    // 验证结果
    assert_eq!(result, expected);
}