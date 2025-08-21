//! # 修复的API使用指南
//! 
//! ## Bash 测试代码
//! 
//! ```bash
//! # 编译检查
//! cargo check --example fixed_api_usage_guide
//! 
//! # 运行修复的API指南
//! cargo run --example fixed_api_usage_guide
//! 
//! # 运行所有测试
//! cargo test --example fixed_api_usage_guide
//! 
//! # 性能基准测试
//! cargo bench --bench mpc_benchmarks -- fixed_api
//! 
//! # 生成修复API文档
//! cargo doc --example fixed_api_usage_guide --open
//! ```
//! 
//! 提供当前可用API的完整使用示例，确保所有示例都能编译和运行

use mpc_api::{
    secret_sharing::{ShamirSecretSharing, SecretSharing, AdditiveSecretSharingScheme, field_add, field_mul},
    beaver_triples::{TrustedPartyBeaverGenerator, BeaverTripleGenerator, secure_multiply},
    commitment::{HashCommitment, MerkleTree, CommitmentScheme},
    authentication::{HMAC, MessageAuthenticationCode},
    Result,
};

/// 1. 完整的秘密分享示例
pub fn comprehensive_secret_sharing_demo() -> Result<()> {
    println!("=== 1. 完整秘密分享演示 ===");
    
    // Shamir秘密分享
    println!("\n--- Shamir秘密分享 ---");
    let secret = 123456u64;
    let threshold = 3;
    let parties = 5;
    
    let shares = ShamirSecretSharing::share(&secret, threshold, parties)?;
    println!("分享 {} 给 {} 方，门限 {}", secret, parties, threshold);
    
    let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
    println!("重构结果: {}", reconstructed);
    assert_eq!(secret, reconstructed);
    
    // 加法秘密分享
    println!("\n--- 加法秘密分享 ---");
    let scheme = AdditiveSecretSharingScheme::new();
    let additive_shares = scheme.share_additive(&secret, parties)?;
    let additive_result = scheme.reconstruct_additive(&additive_shares)?;
    println!("加法分享重构: {}", additive_result);
    assert_eq!(secret, additive_result);
    
    Ok(())
}

/// 2. Beaver三元组安全计算示例
pub fn secure_computation_demo() -> Result<()> {
    println!("\n=== 2. 安全计算演示 ===");
    
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None)?;
    
    // 生成Beaver三元组
    let triple = generator.generate_single()?;
    println!("成功生成Beaver三元组");
    
    // 安全乘法计算
    let x = 15u64;
    let y = 25u64;
    let expected = field_mul(x, y);
    
    println!("计算 {} × {} = {}", x, y, expected);
    
    let x_shares = ShamirSecretSharing::share(&x, 2, 3)?;
    let y_shares = ShamirSecretSharing::share(&y, 2, 3)?;
    
    let result_shares = secure_multiply(&x_shares, &y_shares, &triple, 2)?;
    let result = ShamirSecretSharing::reconstruct(&result_shares[0..2], 2)?;
    
    println!("安全乘法结果: {}", result);
    assert_eq!(result, expected);
    
    Ok(())
}

/// 3. 承诺方案示例
pub fn commitment_demo() -> Result<()> {
    println!("\n=== 3. 承诺方案演示 ===");
    
    // Hash承诺
    println!("\n--- Hash承诺 ---");
    let message = b"secret message";
    let randomness = HashCommitment::generate_randomness(32);
    let commitment = HashCommitment::commit(message.to_vec(), randomness.clone());
    let is_valid = HashCommitment::verify(commitment, message.to_vec(), randomness);
    println!("Hash承诺验证: {}", if is_valid { "通过" } else { "失败" });
    assert!(is_valid);
    
    // Merkle树
    println!("\n--- Merkle树 ---");
    let data = vec![
        b"data1".to_vec(),
        b"data2".to_vec(), 
        b"data3".to_vec(),
        b"data4".to_vec(),
    ];
    
    let merkle_tree = MerkleTree::new(&data)?;
    let root = merkle_tree.get_root();
    println!("Merkle根: {:?}", root);
    
    // 生成和验证证明
    let proof = merkle_tree.generate_proof(0)?;
    let is_included = MerkleTree::verify_proof(root, &data[0], &proof)?;
    println!("Merkle证明验证: {}", if is_included { "通过" } else { "失败" });
    assert!(is_included);
    
    Ok(())
}

/// 4. 消息认证示例
pub fn authentication_demo() -> Result<()> {
    println!("\n=== 4. 消息认证演示 ===");
    
    let key = HMAC::generate_key();
    let message = b"test message".to_vec();
    
    let mac = HMAC::authenticate(&key, &message);
    let is_valid = HMAC::verify(&key, &message, &mac);
    
    println!("HMAC验证: {}", if is_valid { "通过" } else { "失败" });
    assert!(is_valid);
    
    // 测试错误消息
    let wrong_message = b"wrong message".to_vec();
    let is_invalid = HMAC::verify(&key, &wrong_message, &mac);
    println!("错误消息验证: {}", if is_invalid { "通过" } else { "失败" });
    assert!(!is_invalid);
    
    Ok(())
}

/// 5. 批量操作示例
pub fn batch_operations_demo() -> Result<()> {
    println!("\n=== 5. 批量操作演示 ===");
    
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None)?;
    
    // 批量生成三元组
    let batch_size = 10;
    let triples = generator.generate_batch(batch_size)?;
    println!("批量生成 {} 个三元组", triples.len());
    
    // 验证所有三元组
    let mut valid_count = 0;
    for triple in &triples {
        if triple.verify(2)? {
            valid_count += 1;
        }
    }
    println!("有效三元组: {}/{}", valid_count, batch_size);
    assert_eq!(valid_count, batch_size);
    
    Ok(())
}

/// 6. 复合运算示例
pub fn complex_computation_demo() -> Result<()> {
    println!("\n=== 6. 复合运算演示 ===");
    
    // 计算多个数的乘积总和: (a1*b1) + (a2*b2) + (a3*b3)
    let inputs = vec![(10, 20), (15, 25), (8, 12)];
    let mut total = 0u64;
    
    let mut generator = TrustedPartyBeaverGenerator::new(3, 2, 0, None)?;
    
    for (i, (a, b)) in inputs.iter().enumerate() {
        let triple = generator.generate_single()?;
        
        let a_shares = ShamirSecretSharing::share(a, 2, 3)?;
        let b_shares = ShamirSecretSharing::share(b, 2, 3)?;
        
        let product_shares = secure_multiply(&a_shares, &b_shares, &triple, 2)?;
        let product = ShamirSecretSharing::reconstruct(&product_shares[0..2], 2)?;
        
        total = field_add(total, product);
        println!("  计算 {}: {} × {} = {}", i+1, a, b, product);
    }
    
    let expected = field_add(field_add(field_mul(10, 20), field_mul(15, 25)), field_mul(8, 12));
    println!("复合计算结果: {}", total);
    println!("期望结果: {}", expected);
    assert_eq!(total, expected);
    
    Ok(())
}

/// 运行所有演示
pub fn run_all_demos() -> Result<()> {
    comprehensive_secret_sharing_demo()?;
    secure_computation_demo()?;
    commitment_demo()?;
    authentication_demo()?;
    batch_operations_demo()?;
    complex_computation_demo()?;
    
    println!("\n🎉 所有API演示完成！");
    Ok(())
}

fn main() -> Result<()> {
    run_all_demos()
}