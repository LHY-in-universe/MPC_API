use mpc_api::beaver_triples::trusted_party::*;
use mpc_api::beaver_triples::{secure_multiply, BeaverTripleGenerator};
use mpc_api::secret_sharing::{ShamirSecretSharing, SecretSharing, field_mul};

#[test]
fn test_trusted_party_generator_creation() {
    let generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None);
    assert!(generator.is_ok());
    
    let gen = generator.unwrap();
    assert_eq!(gen.get_party_count(), 3);
    assert_eq!(gen.get_threshold(), 2);
}

#[test]
fn test_trusted_party_invalid_params() {
    // 门限值太大
    let result = TrustedPartyBeaverGenerator::new(3, 4, 0, None);
    assert!(result.is_err());
    
    // 参与方 ID 无效
    let result = TrustedPartyBeaverGenerator::new(3, 2, 3, None);
    assert!(result.is_err());
}

#[test]
fn test_single_triple_generation() {
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None).unwrap();
    let triple = generator.generate_single().unwrap();
    
    // 验证三元组结构
    assert_eq!(triple.shares.len(), 3);
    assert!(triple.verify(2).unwrap());
    
    // 验证乘法关系
    if let Some((a, b, c)) = triple.original_values {
        assert_eq!(c, field_mul(a, b));
    }
}

#[test]
fn test_batch_generation() {
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None).unwrap();
    let batch_size = 5;
    let triples = generator.generate_batch(batch_size).unwrap();
    
    assert_eq!(triples.len(), batch_size);
    
    // 验证每个三元组
    for triple in &triples {
        assert!(triple.verify(2).unwrap());
        if let Some((a, b, c)) = triple.original_values {
            assert_eq!(c, field_mul(a, b));
        }
    }
}

#[test]
fn test_precomputed_pool() {
    let config = TrustedPartyConfig {
        enable_precomputation: true,
        pool_size: 10,
        batch_size: 5,
        enable_security_checks: true,
    };
    
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, Some(config)).unwrap();
    
    // 从池中获取三元组应该很快
    for _ in 0..5 {
        let triple = generator.generate_single().unwrap();
        assert!(triple.verify(2).unwrap());
    }
}

#[test]
fn test_batch_trusted_party_generator() {
    let mut batch_generator = BatchTrustedPartyGenerator::new(3, 2, 0, 20).unwrap();
    let triples = batch_generator.generate_optimized_batch(15).unwrap();
    
    assert_eq!(triples.len(), 15);
    
    // 验证所有三元组
    for triple in &triples {
        assert!(triple.verify(2).unwrap());
    }
}

#[test]
fn test_secure_multiplication_with_trusted_triple() {
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None).unwrap();
    let triple = generator.generate_single().unwrap();
    
    // 创建测试输入
    let x = 20u64;
    let y = 30u64;
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
fn test_trusted_party_auditor() {
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None).unwrap();
    let triples = generator.generate_batch(10).unwrap();
    
    let auditor = TrustedPartyAuditor::new(3, 2);
    
    // 审计统计性质
    assert!(auditor.audit_statistical_properties(&triples).unwrap());
    
    // 审计密码学性质  
    assert!(auditor.audit_cryptographic_properties(&triples).unwrap());
}

#[test]
fn test_triple_verification() {
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None).unwrap();
    let triple = generator.generate_single().unwrap();
    
    // 使用生成器验证三元组
    assert!(generator.verify_triple(&triple).unwrap());
    
    // 验证三元组的内部一致性
    for beaver_share in triple.shares.values() {
        assert!(beaver_share.is_consistent());
    }
}