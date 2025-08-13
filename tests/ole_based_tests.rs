use mpc_api::beaver_triples::ole_based::*;
use mpc_api::beaver_triples::{secure_multiply, BeaverTripleGenerator};
use mpc_api::secret_sharing::{ShamirSecretSharing, SecretSharing, field_mul};

#[test]
fn test_ole_beaver_generator_creation() {
    let generator = OLEBeaverGenerator::new(3, 2, 0);
    assert!(generator.is_ok());
    
    let gen = generator.unwrap();
    assert_eq!(gen.get_party_count(), 3);
    assert_eq!(gen.get_threshold(), 2);
}

#[test]
fn test_ole_beaver_generator_invalid_params() {
    // 门限值太大
    let result = OLEBeaverGenerator::new(3, 4, 0);
    assert!(result.is_err());
    
    // 参与方 ID 无效
    let result = OLEBeaverGenerator::new(3, 2, 3);
    assert!(result.is_err());
}

#[test]
fn test_single_triple_generation() {
    let mut generator = OLEBeaverGenerator::new(3, 2, 0).unwrap();
    let triple = generator.generate_single().unwrap();
    
    // 验证三元组结构
    assert_eq!(triple.shares.len(), 3);
    assert!(triple.verify(2).unwrap());
    
    // 验证密码学性质
    let verifier = OLEBeaverVerifier::new(3, 2);
    assert!(verifier.verify_cryptographic_properties(&triple).unwrap());
}

#[test]
fn test_batch_generation() {
    let mut generator = OLEBeaverGenerator::new(3, 2, 0).unwrap();
    let batch_size = 5;
    let triples = generator.generate_batch(batch_size).unwrap();
    
    assert_eq!(triples.len(), batch_size);
    
    // 验证每个三元组
    for triple in &triples {
        assert!(triple.verify(2).unwrap());
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
fn test_batch_ole_beaver_generator() {
    let mut batch_generator = BatchOLEBeaverGenerator::new(3, 2, 0, 10).unwrap();
    let triples = batch_generator.generate_optimized_batch(15).unwrap();
    
    assert_eq!(triples.len(), 15);
    
    // 验证所有三元组
    let verifier = OLEBeaverVerifier::new(3, 2);
    let results = verifier.batch_verify(&triples).unwrap();
    assert!(results.iter().all(|&x| x));
}

#[test]
fn test_secure_multiplication_with_ole_triple() {
    let mut generator = OLEBeaverGenerator::new(3, 2, 0).unwrap();
    let triple = generator.generate_single().unwrap();
    
    // 创建测试输入
    let x = 15u64;
    let y = 25u64;
    let expected = field_mul(x, y);
    
    let x_shares = ShamirSecretSharing::share(&x, 2, 3).unwrap();
    let y_shares = ShamirSecretSharing::share(&y, 2, 3).unwrap();
    
    // 执行安全乘法
    let result_shares = secure_multiply(&x_shares, &y_shares, &triple, 2).unwrap();
    
    // 重构结果
    let result = ShamirSecretSharing::reconstruct(&result_shares[0..2], 2).unwrap();
    
    // 验证结果
    assert_eq!(result, expected);
}

#[test]
fn test_verifier_functionality() {
    let mut generator = OLEBeaverGenerator::new(3, 2, 0).unwrap();
    let verifier = OLEBeaverVerifier::new(3, 2);
    
    // 生成有效三元组
    let valid_triple = generator.generate_single().unwrap();
    assert!(verifier.verify_cryptographic_properties(&valid_triple).unwrap());
    
    // 测试批量验证
    let triples = generator.generate_batch(3).unwrap();
    let results = verifier.batch_verify(&triples).unwrap();
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|&x| x));
}