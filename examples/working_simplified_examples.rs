//! # 简化的可工作MPC示例
//! 
//! ## Bash 测试代码
//! 
//! ```bash
//! # 编译检查
//! cargo check --example working_simplified_examples
//! 
//! # 运行简化示例
//! cargo run --example working_simplified_examples
//! 
//! # 运行所有测试
//! cargo test --example working_simplified_examples
//! 
//! # 性能基准测试
//! cargo bench --bench mpc_benchmarks -- simplified
//! 
//! # 生成简化示例文档
//! cargo doc --example working_simplified_examples --open
//! ```
//! 
//! 包含当前API中能够正常编译和运行的基本示例

use mpc_api::{
    secret_sharing::{ShamirSecretSharing, SecretSharing, AdditiveSecretSharingScheme},
    beaver_triples::{TrustedPartyBeaverGenerator, BeaverTripleGenerator},
    Result,
};

/// 基本Shamir秘密分享示例
pub fn basic_shamir_example() -> Result<()> {
    println!("=== Shamir秘密分享基础示例 ===");
    
    let secret = 12345u64;
    let threshold = 3;
    let total_parties = 5;
    
    println!("原始秘密: {}", secret);
    println!("门限值: {}", threshold);
    println!("参与方数: {}", total_parties);
    
    // 生成分享
    let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
    println!("成功生成 {} 个分享", shares.len());
    
    // 重构秘密
    let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
    println!("重构的秘密: {}", reconstructed);
    
    assert_eq!(secret, reconstructed);
    println!("✓ 验证成功!");
    
    Ok(())
}

/// 基本加法秘密分享示例
pub fn basic_additive_example() -> Result<()> {
    println!("\n=== 加法秘密分享基础示例 ===");
    
    let secret = 54321u64;
    let parties = 4;
    
    println!("原始秘密: {}", secret);
    println!("参与方数: {}", parties);
    
    let scheme = AdditiveSecretSharingScheme::new();
    let shares = scheme.share_additive(&secret, parties)?;
    
    println!("成功生成 {} 个加法分享", shares.len());
    
    // 重构秘密
    let reconstructed = scheme.reconstruct_additive(&shares)?;
    println!("重构的秘密: {}", reconstructed);
    
    assert_eq!(secret, reconstructed);
    println!("✓ 验证成功!");
    
    Ok(())
}

/// 基本Beaver三元组示例
pub fn basic_beaver_example() -> Result<()> {
    println!("\n=== Beaver三元组基础示例 ===");
    
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    
    println!("参与方数: {}", party_count);
    println!("门限值: {}", threshold);
    
    let mut generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
    
    // 生成单个三元组
    let triple = generator.generate_single()?;
    
    println!("成功生成Beaver三元组");
    println!("三元组包含 {} 个分享", triple.shares.len());
    
    // 验证三元组
    let is_valid = triple.verify(threshold)?;
    println!("三元组验证: {}", if is_valid { "✓ 有效" } else { "✗ 无效" });
    
    assert!(is_valid);
    
    Ok(())
}

/// 运行所有基础示例
pub fn run_all_examples() -> Result<()> {
    basic_shamir_example()?;
    basic_additive_example()?;
    basic_beaver_example()?;
    
    println!("\n=== 所有示例运行完成 ===");
    Ok(())
}

fn main() -> Result<()> {
    run_all_examples()
}