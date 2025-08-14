//! # MPC API 完整使用指南 (工作版本)
//! 
//! 本文档展示了 MPC API 中当前可用组件的使用方法，包括：
//! 1. 秘密分享 (Secret Sharing)
//! 2. Beaver 三元组 (Beaver Triples)
//! 3. 承诺方案 (Commitment Schemes)
//! 4. 消息认证码 (Message Authentication Codes)
//! 5. 有限域运算 (Field Operations)

use mpc_api::{
    secret_sharing::{ShamirSecretSharing, SecretSharing, AdditiveSecretSharingScheme, field_add, field_mul},
    beaver_triples::{TrustedPartyBeaverGenerator, BeaverTripleGenerator, secure_multiply},
    commitment::{HashCommitment, MerkleTree, CommitmentScheme},
    authentication::{HMAC, MessageAuthenticationCode},
    Result,
};

/// 1. 秘密分享使用指南
pub mod secret_sharing_guide {
    use super::*;
    
    /// Shamir 秘密分享基础用法
    pub fn basic_shamir_sharing() -> Result<()> {
        println!("=== 1.1 Shamir 秘密分享基础用法 ===");
        
        // 步骤1: 选择参数
        let secret = 42u64;        // 要分享的秘密
        let threshold = 3;         // 门限值：重构需要的最少分享数
        let total_parties = 5;     // 总参与方数
        
        println!("秘密值: {}", secret);
        println!("门限: {} (需要{}个分享来重构)", threshold, threshold);
        println!("总参与方: {}", total_parties);
        
        // 步骤2: 生成分享
        let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
        
        println!("生成的分享:");
        for (i, share) in shares.iter().enumerate() {
            println!("  参与方 {}: ({}, {})", i, share.x, share.y);
        }
        
        // 步骤3: 重构秘密 (使用任意threshold个分享)
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
        
        println!("重构的秘密: {}", reconstructed);
        assert_eq!(secret, reconstructed);
        
        // 步骤4: 验证门限性质 (少于threshold个分享无法重构)
        if threshold > 1 {
            let insufficient_shares = &shares[0..threshold-1];
            match ShamirSecretSharing::reconstruct(insufficient_shares, threshold) {
                Ok(_) => println!("⚠️ 警告: 少于门限的分享也能重构!"),
                Err(_) => println!("✓ 验证: {} 个分享无法重构秘密", insufficient_shares.len()),
            }
        }
        
        println!("✓ Shamir 秘密分享基础演示完成\n");
        Ok(())
    }
    
    /// 加法秘密分享演示
    pub fn additive_sharing() -> Result<()> {
        println!("=== 1.2 加法秘密分享 ===");
        
        let secret = 100u64;
        let parties = 3;
        
        // 加法分享：每方持有一个随机值，和为秘密
        let scheme = AdditiveSecretSharingScheme::new();
        let shares = scheme.share_additive(&secret, parties)?;
        
        println!("秘密: {}", secret);
        println!("加法分享:");
        for (i, share) in shares.iter().enumerate() {
            println!("  参与方 {}: {}", i, share.value);
        }
        
        // 重构：将所有分享相加
        let reconstructed = scheme.reconstruct_additive(&shares)?;
        
        println!("重构结果: {}", reconstructed);
        assert_eq!(secret, reconstructed);
        
        println!("✓ 加法秘密分享演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_shamir_sharing()?;
        additive_sharing()?;
        Ok(())
    }
}

/// 2. Beaver 三元组使用指南
pub mod beaver_triples_guide {
    use super::*;
    
    /// 基础 Beaver 三元组演示
    pub fn basic_beaver_triples() -> Result<()> {
        println!("=== 2.1 基础 Beaver 三元组演示 ===");
        
        let party_count = 3;
        let threshold = 2;
        let party_id = 0;
        
        // 创建可信第三方生成器
        let mut generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
        
        // 生成单个三元组
        let triple = generator.generate_single()?;
        
        println!("成功生成 Beaver 三元组");
        
        // 验证三元组
        let is_valid = triple.verify(threshold)?;
        println!("三元组验证: {}", if is_valid { "✓ 有效" } else { "✗ 无效" });
        assert!(is_valid);
        
        println!("✓ 基础 Beaver 三元组演示完成\n");
        Ok(())
    }
    
    /// 安全乘法演示
    pub fn secure_multiplication() -> Result<()> {
        println!("=== 2.2 安全乘法演示 ===");
        
        let party_count = 3;
        let threshold = 2;
        let party_id = 0;
        
        let mut generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
        let triple = generator.generate_single()?;
        
        // 要相乘的秘密值
        let x = 15u64;
        let y = 25u64;
        let expected = field_mul(x, y);
        
        println!("计算 {} × {} = {}", x, y, expected);
        
        // 对输入进行秘密分享
        let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
        let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
        
        // 使用 Beaver 三元组进行安全乘法
        let product_shares = secure_multiply(&x_shares, &y_shares, &triple, threshold)?;
        
        // 重构结果
        let result = ShamirSecretSharing::reconstruct(&product_shares[0..threshold], threshold)?;
        
        println!("安全乘法结果: {}", result);
        assert_eq!(result, expected);
        
        println!("✓ 安全乘法演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_beaver_triples()?;
        secure_multiplication()?;
        Ok(())
    }
}

/// 3. 承诺方案使用指南
pub mod commitment_guide {
    use super::*;
    
    /// Hash 承诺演示
    pub fn hash_commitment() -> Result<()> {
        println!("=== 3.1 Hash 承诺演示 ===");
        
        let message = b"secret message".to_vec();
        let randomness = HashCommitment::generate_randomness(32);
        
        // 生成承诺
        let commitment = HashCommitment::commit(message.clone(), randomness.clone());
        println!("消息: {:?}", String::from_utf8_lossy(&message));
        println!("承诺生成完成");
        
        // 验证承诺
        let is_valid = HashCommitment::verify(commitment, message.clone(), randomness.clone());
        println!("承诺验证: {}", if is_valid { "✓ 有效" } else { "✗ 无效" });
        assert!(is_valid);
        
        // 测试错误消息
        let wrong_message = b"wrong message".to_vec();
        let is_wrong_valid = HashCommitment::verify(commitment, wrong_message, randomness);
        println!("错误消息验证: {}", if is_wrong_valid { "✗ 应该无效" } else { "✓ 正确拒绝" });
        assert!(!is_wrong_valid);
        
        println!("✓ Hash 承诺演示完成\n");
        Ok(())
    }
    
    /// Merkle 树演示
    pub fn merkle_tree() -> Result<()> {
        println!("=== 3.2 Merkle 树演示 ===");
        
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
        ];
        
        // 构建 Merkle 树
        let merkle_tree = MerkleTree::new(&data)?;
        let root = merkle_tree.get_root();
        
        println!("数据项数量: {}", data.len());
        println!("Merkle 根生成完成");
        
        // 为第一个数据项生成包含证明
        let proof = merkle_tree.generate_proof(0)?;
        let is_included = MerkleTree::verify_proof(root, &data[0], &proof)?;
        
        println!("包含证明验证: {}", if is_included { "✓ 有效" } else { "✗ 无效" });
        assert!(is_included);
        
        println!("✓ Merkle 树演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        hash_commitment()?;
        merkle_tree()?;
        Ok(())
    }
}

/// 4. 消息认证码使用指南
pub mod authentication_guide {
    use super::*;
    
    /// HMAC 演示
    pub fn hmac_demo() -> Result<()> {
        println!("=== 4.1 HMAC 消息认证码演示 ===");
        
        let key = HMAC::generate_key();
        let message = b"important message".to_vec();
        
        // 生成 HMAC
        let mac = HMAC::authenticate(&key, &message);
        println!("消息: {:?}", String::from_utf8_lossy(&message));
        println!("HMAC 生成完成");
        
        // 验证 HMAC
        let is_valid = HMAC::verify(&key, &message, &mac);
        println!("HMAC 验证: {}", if is_valid { "✓ 有效" } else { "✗ 无效" });
        assert!(is_valid);
        
        // 测试篡改检测
        let tampered_message = b"tampered message".to_vec();
        let is_tampered_valid = HMAC::verify(&key, &tampered_message, &mac);
        println!("篡改检测: {}", if is_tampered_valid { "✗ 应该检测到" } else { "✓ 检测到篡改" });
        assert!(!is_tampered_valid);
        
        println!("✓ HMAC 演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        hmac_demo()?;
        Ok(())
    }
}

/// 5. 有限域运算指南
pub mod field_operations_guide {
    use super::*;
    use mpc_api::secret_sharing::{field_sub, field_inv, FIELD_PRIME};
    
    /// 基础有限域运算演示
    pub fn basic_field_operations() -> Result<()> {
        println!("=== 5.1 有限域运算演示 ===");
        
        println!("有限域模数: {}", FIELD_PRIME);
        
        let a = 123456789u64;
        let b = 987654321u64;
        
        println!("操作数 a: {}", a);
        println!("操作数 b: {}", b);
        
        // 基本运算
        let sum = field_add(a, b);
        let difference = field_sub(a, b);
        let product = field_mul(a, b);
        
        println!("加法: a + b = {}", sum);
        println!("减法: a - b = {}", difference);
        println!("乘法: a × b = {}", product);
        
        // 逆元
        if let Some(a_inv) = field_inv(a) {
            let should_be_one = field_mul(a, a_inv);
            println!("逆元: a^(-1) = {}", a_inv);
            println!("验证: a × a^(-1) = {} (应该是1)", should_be_one);
            assert_eq!(should_be_one, 1);
        }
        
        println!("✓ 有限域运算演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_field_operations()?;
        Ok(())
    }
}

/// 运行所有演示
pub fn run_all_demos() -> Result<()> {
    println!("🌟 === MPC API 完整使用指南演示 ===\n");
    
    secret_sharing_guide::run_all()?;
    beaver_triples_guide::run_all()?;
    commitment_guide::run_all()?;
    authentication_guide::run_all()?;
    field_operations_guide::run_all()?;
    
    println!("🎉 === 所有演示完成 ===");
    println!("📝 演示总结:");
    println!("  ✓ 秘密分享 - Shamir 和加法分享方案");
    println!("  ✓ Beaver 三元组 - 安全乘法计算");
    println!("  ✓ 承诺方案 - Hash 承诺和 Merkle 树");
    println!("  ✓ 消息认证 - HMAC 认证码");
    println!("  ✓ 有限域运算 - 基础数学运算");
    println!("\n这些示例展示了 MPC API 的核心功能和实际应用场景。");
    
    Ok(())
}

fn main() -> Result<()> {
    run_all_demos()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secret_sharing_guide() {
        secret_sharing_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_beaver_triples_guide() {
        beaver_triples_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_commitment_guide() {
        commitment_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_authentication_guide() {
        authentication_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_field_operations_guide() {
        field_operations_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_all_demos() {
        run_all_demos().unwrap();
    }
}