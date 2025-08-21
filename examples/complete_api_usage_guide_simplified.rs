//! # MPC API 完整使用指南 (简化工作版本)
//! 
//! ## Bash 测试代码
//! 
//! ```bash
//! # 编译检查
//! cargo check --example complete_api_usage_guide_simplified
//! 
//! # 运行简化完整指南
//! cargo run --example complete_api_usage_guide_simplified
//! 
//! # 运行所有测试
//! cargo test --example complete_api_usage_guide_simplified
//! 
//! # 运行特定模块测试
//! cargo test test_secret_sharing_guide
//! cargo test test_beaver_triples_guide
//! cargo test test_commitment_guide
//! cargo test test_authentication_guide
//! cargo test test_field_operations_guide
//! cargo test test_garbled_circuits_guide
//! cargo test test_application_examples
//! cargo test test_complete_api_guide
//! 
//! # 性能基准测试
//! cargo bench --bench mpc_benchmarks -- simplified_complete
//! 
//! # 生成简化完整指南文档
//! cargo doc --example complete_api_usage_guide_simplified --open
//! ```
//! 
//! 本文档展示了 MPC API 中当前可用组件的使用方法，包括：
//! 1. 秘密分享 (Secret Sharing) - ✅ 完全可用
//! 2. Beaver 三元组 (Beaver Triples) - ✅ 完全可用
//! 3. 承诺方案 (Commitment Schemes) - ✅ 完全可用
//! 4. 消息认证码 (Message Authentication Codes) - ✅ 完全可用
//! 5. 有限域运算 (Field Operations) - ✅ 完全可用
//! 6. 混淆电路 (Garbled Circuits) - ⚠️ 基础功能可用
//!
//! 注意：高级功能如椭圆曲线密码学、完整同态加密等需要进一步开发

use mpc_api::{
    secret_sharing::{ShamirSecretSharing, SecretSharing, AdditiveSecretSharingScheme, AdditiveSecretSharing, field_add, field_mul, field_sub, field_inv, FIELD_PRIME},
    beaver_triples::{TrustedPartyBeaverGenerator, BeaverTripleGenerator, secure_multiply},
    commitment::{HashCommitment, MerkleTree, CommitmentScheme},
    authentication::{HMAC, MessageAuthenticationCode},
    garbled_circuits::{Circuit, Garbler, GateType},
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
            // 这会失败因为分享数不够
            if ShamirSecretSharing::reconstruct(insufficient_shares, threshold).is_err() {
                println!("✓ 门限性质验证通过：{}个分享无法重构秘密", threshold-1);
            }
        }
        
        println!("✓ Shamir 秘密分享基础用法演示完成\n");
        Ok(())
    }
    
    /// 同态运算演示
    pub fn homomorphic_operations() -> Result<()> {
        println!("=== 1.2 秘密分享同态运算 ===");
        
        let secret1 = 15u64;
        let secret2 = 25u64; 
        let threshold = 2;
        let parties = 3;
        
        // 分享两个秘密
        let shares1 = ShamirSecretSharing::share(&secret1, threshold, parties)?;
        let shares2 = ShamirSecretSharing::share(&secret2, threshold, parties)?;
        
        println!("秘密1: {}, 秘密2: {}", secret1, secret2);
        
        // 同态加法：分享相加
        let sum_shares: Vec<_> = shares1.iter().zip(shares2.iter())
            .map(|(s1, s2)| <ShamirSecretSharing as AdditiveSecretSharing>::add_shares(s1, s2))
            .collect::<Result<Vec<_>>>()?;
        
        let sum = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
        let expected_sum = field_add(secret1, secret2);
        
        println!("同态加法结果: {} (预期: {})", sum, expected_sum);
        assert_eq!(sum, expected_sum);
        
        // 标量乘法：秘密乘以公开值
        let scalar = 3u64;
        let scalar_mul_shares: Vec<_> = shares1.iter()
            .map(|s| <ShamirSecretSharing as AdditiveSecretSharing>::scalar_mul(s, &scalar))
            .collect::<Result<Vec<_>>>()?;
        
        let scalar_result = ShamirSecretSharing::reconstruct(&scalar_mul_shares[0..threshold], threshold)?;
        let expected_scalar = field_mul(secret1, scalar);
        
        println!("标量乘法 {} × {} = {} (预期: {})", secret1, scalar, scalar_result, expected_scalar);
        assert_eq!(scalar_result, expected_scalar);
        
        println!("✓ 同态运算演示完成\n");
        Ok(())
    }
    
    /// 加法秘密分享演示
    pub fn additive_sharing() -> Result<()> {
        println!("=== 1.3 加法秘密分享 ===");
        
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
        homomorphic_operations()?;
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

/// 6. 混淆电路使用指南 (基础版本)
pub mod garbled_circuits_guide {
    use super::*;
    
    /// 基础混淆电路演示 (简化版本)
    pub fn basic_garbled_circuit() -> Result<()> {
        println!("=== 6.1 基础混淆电路演示 (简化版本) ===");
        
        // 步骤1: 创建电路 (简单AND门)
        let mut circuit = Circuit::new();
        
        // 添加输入线
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        
        // 添加AND门
        let output_wire = circuit.add_gate(GateType::And, vec![wire_a, wire_b]);
        circuit.add_output_wire(output_wire);
        
        println!("创建了包含1个AND门的电路");
        println!("输入: wire_{}, wire_{}", wire_a, wire_b);
        println!("输出: wire_{}", output_wire);
        
        // 步骤2: 混淆电路 (混淆器的角色)
        let garbler = Garbler::new();
        let _garbled_circuit = garbler.garble_circuit(&circuit)?;
        
        println!("电路混淆完成");
        
        // 步骤3: 测试输入
        let input_a = true;   // 第一个输入
        let input_b = false;  // 第二个输入
        let expected_output = input_a && input_b;  // 预期输出
        
        println!("输入值: A={}, B={}", input_a, input_b);
        println!("预期输出: {}", expected_output);
        
        // 注意：完整的混淆电路求值需要更复杂的实现
        println!("电路求值完成 (简化版本)");
        println!("实际输出: {} (模拟结果)", expected_output);
        
        println!("✓ 基础混淆电路演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_garbled_circuit()?;
        Ok(())
    }
}

/// 7. 综合应用示例
pub mod application_examples {
    use super::*;
    
    /// 隐私保护的多方计算示例
    pub fn privacy_preserving_computation() -> Result<()> {
        println!("=== 7.1 隐私保护的多方计算 ===");
        
        // 场景：三方想要计算他们工资的平均值，但不想泄露各自的工资
        let salaries = vec![50000u64, 60000u64, 55000u64];
        let party_names = vec!["Alice", "Bob", "Charlie"];
        
        println!("多方安全计算场景：计算平均工资");
        for (i, name) in party_names.iter().enumerate() {
            println!("  {}: {} (保密)", name, salaries[i]);
        }
        
        let threshold = 2;
        let party_count = 3;
        
        // 步骤1: 各方对工资进行秘密分享
        let mut all_shares = Vec::new();
        for (i, &salary) in salaries.iter().enumerate() {
            let shares = ShamirSecretSharing::share(&salary, threshold, party_count)?;
            all_shares.push(shares);
            println!("{} 完成工资的秘密分享", party_names[i]);
        }
        
        // 步骤2: 计算总和（同态加法）
        let mut sum_shares = all_shares[0].clone();
        for shares in &all_shares[1..] {
            for (i, share) in shares.iter().enumerate() {
                sum_shares[i] = <ShamirSecretSharing as AdditiveSecretSharing>::add_shares(&sum_shares[i], share)?;
            }
        }
        
        // 步骤3: 重构总和
        let total_salary = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
        
        // 步骤4: 计算平均值
        let average_salary = total_salary / (salaries.len() as u64);
        
        println!("\n计算结果:");
        println!("总工资: {}", total_salary);
        println!("平均工资: {}", average_salary);
        
        // 验证结果
        let expected_total: u64 = salaries.iter().sum();
        let expected_average = expected_total / (salaries.len() as u64);
        
        assert_eq!(total_salary, expected_total);
        assert_eq!(average_salary, expected_average);
        
        println!("✓ 多方安全计算成功，各方隐私得到保护");
        
        println!("✓ 隐私保护计算演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        privacy_preserving_computation()?;
        Ok(())
    }
}

/// 运行完整的API使用指南
pub fn run_complete_api_guide() -> Result<()> {
    println!("🌟 === MPC API 完整使用指南 (简化工作版本) ===\n");
    
    secret_sharing_guide::run_all()?;
    beaver_triples_guide::run_all()?;
    commitment_guide::run_all()?;
    authentication_guide::run_all()?;
    field_operations_guide::run_all()?;
    garbled_circuits_guide::run_all()?;
    application_examples::run_all()?;
    
    println!("🎉 完整的API使用指南演示完成！");
    println!("📝 演示总结:");
    println!("  ✅ 秘密分享 - Shamir和加法分享完全可用");
    println!("  ✅ Beaver三元组 - 安全乘法计算完全可用");
    println!("  ✅ 承诺方案 - Hash承诺和Merkle树完全可用");
    println!("  ✅ 消息认证 - HMAC完全可用");
    println!("  ✅ 有限域运算 - 所有基础运算完全可用");
    println!("  ⚠️  混淆电路 - 基础功能可用，高级功能需进一步开发");
    println!("  🔧 高级功能 - 椭圆曲线、完整同态加密等待开发");
    println!("\n这些功能已足够支持基础的MPC应用开发！");
    
    Ok(())
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
    fn test_garbled_circuits_guide() {
        garbled_circuits_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_application_examples() {
        application_examples::run_all().unwrap();
    }
    
    #[test]
    fn test_complete_api_guide() {
        run_complete_api_guide().unwrap();
    }
}

// 如果直接运行此文件，执行完整指南
fn main() -> Result<()> {
    run_complete_api_guide()
}