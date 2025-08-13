//! # 简单 API 使用示例
//! 
//! 展示 MPC API 中实际可用功能的基本使用方法。
//! 这些示例都是可以编译和运行的。

use mpc_api::{*, Result};

/// 1. 哈希承诺演示
pub fn hash_commitment_demo() -> Result<()> {
    println!("=== 哈希承诺演示 ===");
    
    // 方式1: 直接对 u64 值进行承诺
    let secret_value = 12345u64;
    let randomness = 67890u64;
    
    println!("秘密值: {}", secret_value);
    println!("随机数: {}", randomness);
    
    // 生成承诺
    let commitment = HashCommitment::commit_u64(secret_value, randomness);
    println!("承诺哈希: {:02x?}", &commitment[0..8]); // 只显示前8字节
    
    // 验证承诺
    let is_valid = HashCommitment::verify_u64(&commitment, secret_value, randomness);
    println!("验证结果: {}", if is_valid { "有效" } else { "无效" });
    assert!(is_valid);
    
    // 验证错误值（应该失败）
    let wrong_value = 54321u64;
    let is_wrong_valid = HashCommitment::verify_u64(&commitment, wrong_value, randomness);
    println!("错误值验证: {}", if is_wrong_valid { "有效" } else { "无效" });
    assert!(!is_wrong_valid);
    
    // 方式2: 自动生成随机数的承诺
    let (auto_randomness, auto_commitment) = HashCommitment::auto_commit_u64(secret_value);
    let auto_valid = HashCommitment::verify_u64(&auto_commitment, secret_value, auto_randomness);
    println!("自动承诺验证: {}", if auto_valid { "有效" } else { "无效" });
    assert!(auto_valid);
    
    println!("✓ 哈希承诺演示完成\n");
    Ok(())
}

/// 2. Pedersen 承诺演示
pub fn pedersen_commitment_demo() -> Result<()> {
    println!("=== Pedersen 承诺演示 ===");
    
    // 生成系统参数
    let params = PedersenParams::new()?;
    println!("Pedersen 参数生成完成");
    
    // 创建承诺
    let message = 42u64;
    let randomness = 123456u64;
    
    let commitment_point = PedersenCommitment::commit_with_params(&params, message, randomness)?;
    println!("消息: {}, 随机数: {}", message, randomness);
    println!("承诺点生成完成");
    
    // 验证承诺
    let is_valid = PedersenCommitment::verify_with_params(&params, &commitment_point, message, randomness)?;
    println!("承诺验证: {}", if is_valid { "有效" } else { "无效" });
    assert!(is_valid);
    
    // 同态加法演示
    let message2 = 18u64;
    let randomness2 = 789012u64;
    let commitment2 = PedersenCommitment::commit_with_params(&params, message2, randomness2)?;
    
    let sum_commitment = PedersenCommitment::add_commitments(&commitment_point, &commitment2)?;
    let sum_message = field_add(message, message2);
    let sum_randomness = field_add(randomness, randomness2);
    
    let is_homomorphic = PedersenCommitment::verify_with_params(&params, &sum_commitment, sum_message, sum_randomness)?;
    println!("同态加法: {} + {} = {} ({})", message, message2, sum_message, 
             if is_homomorphic { "有效" } else { "无效" });
    assert!(is_homomorphic);
    
    println!("✓ Pedersen 承诺演示完成\n");
    Ok(())
}

/// 3. Merkle 树演示
pub fn merkle_tree_demo() -> Result<()> {
    println!("=== Merkle 树演示 ===");
    
    // 准备数据
    let data_items = vec![
        b"Transaction 1: Alice -> Bob, $100".to_vec(),
        b"Transaction 2: Bob -> Charlie, $50".to_vec(),
        b"Transaction 3: Charlie -> Alice, $75".to_vec(),
        b"Transaction 4: Alice -> Dave, $25".to_vec(),
    ];
    
    println!("数据项数量: {}", data_items.len());
    for (i, item) in data_items.iter().enumerate() {
        println!("  {}: {}", i, String::from_utf8_lossy(item));
    }
    
    // 构建 Merkle 树
    let merkle_tree = MerkleTree::new(&data_items)?;
    let root_hash = merkle_tree.get_root();
    
    println!("Merkle 树根哈希: {:02x?}", &root_hash[0..8]); // 显示前8字节
    
    // 为第2个交易生成证明
    let prove_index = 1;
    let proof = merkle_tree.generate_proof(prove_index)?;
    
    println!("为索引 {} 生成包含证明", prove_index);
    println!("证明路径长度: {}", proof.path.len());
    
    // 验证包含证明
    let is_included = MerkleTree::verify_proof(
        root_hash,
        &data_items[prove_index],
        prove_index,
        &proof
    )?;
    
    println!("包含证明验证: {}", if is_included { "有效" } else { "无效" });
    assert!(is_included);
    
    // 验证所有数据项
    for i in 0..data_items.len() {
        let proof = merkle_tree.generate_proof(i)?;
        let is_valid = MerkleTree::verify_proof(root_hash, &data_items[i], i, &proof)?;
        println!("  项目 {}: {}", i, if is_valid { "✓" } else { "✗" });
        assert!(is_valid);
    }
    
    println!("✓ Merkle 树演示完成\n");
    Ok(())
}

/// 4. HMAC 消息认证码演示
pub fn hmac_demo() -> Result<()> {
    println!("=== HMAC 消息认证码演示 ===");
    
    let secret_key = b"this_is_a_secret_key_for_testing";
    let message = b"Important message that needs authentication";
    
    println!("密钥长度: {} 字节", secret_key.len());
    println!("消息: {}", String::from_utf8_lossy(message));
    
    // 生成 HMAC
    let hmac_result = HMAC::authenticate(secret_key, message)?;
    println!("HMAC (前8字节): {:02x?}", &hmac_result[0..8]);
    
    // 验证 HMAC
    let is_valid = HMAC::verify(secret_key, message, &hmac_result)?;
    println!("HMAC 验证: {}", if is_valid { "有效" } else { "无效" });
    assert!(is_valid);
    
    // 检测篡改
    let tampered_message = b"Important message that has been TAMPERED";
    let is_tampered_valid = HMAC::verify(secret_key, tampered_message, &hmac_result)?;
    println!("篡改检测: {}", if is_tampered_valid { "未检测到" } else { "检测到篡改" });
    assert!(!is_tampered_valid);
    
    // 检测错误密钥
    let wrong_key = b"wrong_key_for_testing_authentication";
    let is_wrong_key_valid = HMAC::verify(wrong_key, message, &hmac_result)?;
    println!("错误密钥检测: {}", if is_wrong_key_valid { "未检测到" } else { "检测到错误密钥" });
    assert!(!is_wrong_key_valid);
    
    println!("✓ HMAC 演示完成\n");
    Ok(())
}

/// 5. 有限域运算演示
pub fn field_operations_demo() -> Result<()> {
    println!("=== 有限域运算演示 ===");
    
    println!("有限域素数: {}", FIELD_PRIME);
    println!("素数位数: {} 位", 64 - FIELD_PRIME.leading_zeros());
    
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
    
    // 逆元运算
    if let Some(a_inv) = field_inv(a) {
        let should_be_one = field_mul(a, a_inv);
        println!("逆元: a^(-1) = {}", a_inv);
        println!("验证: a × a^(-1) = {} (应该是1)", should_be_one);
        assert_eq!(should_be_one, 1);
    }
    
    // 运算律验证
    println!("\n运算律验证:");
    
    // 加法交换律
    let ab = field_add(a, b);
    let ba = field_add(b, a);
    println!("加法交换律: {} = {} ({})", ab, ba, ab == ba);
    assert_eq!(ab, ba);
    
    // 乘法交换律
    let ab_mul = field_mul(a, b);
    let ba_mul = field_mul(b, a);
    println!("乘法交换律: {} = {} ({})", ab_mul, ba_mul, ab_mul == ba_mul);
    assert_eq!(ab_mul, ba_mul);
    
    println!("✓ 有限域运算演示完成\n");
    Ok(())
}

/// 6. 椭圆曲线密码学演示
pub fn elliptic_curve_demo() -> Result<()> {
    println!("=== 椭圆曲线密码学演示 ===");
    
    // 生成密钥对
    let key_pair = EllipticCurveKeyPair::generate()?;
    println!("椭圆曲线密钥对生成完成");
    
    // 消息签名
    let message = b"This is a message to be signed";
    println!("待签名消息: {}", String::from_utf8_lossy(message));
    
    let signature = key_pair.sign(message)?;
    println!("数字签名生成完成");
    
    // 验证签名
    let is_valid = key_pair.verify(message, &signature)?;
    println!("签名验证: {}", if is_valid { "有效" } else { "无效" });
    assert!(is_valid);
    
    // 验证错误消息（应该失败）
    let wrong_message = b"This is a DIFFERENT message";
    let is_wrong_valid = key_pair.verify(wrong_message, &signature)?;
    println!("错误消息验证: {}", if is_wrong_valid { "有效" } else { "无效" });
    assert!(!is_wrong_valid);
    
    // ECDH 密钥交换演示
    let alice_keys = EllipticCurveKeyPair::generate()?;
    let bob_keys = EllipticCurveKeyPair::generate()?;
    
    let alice_shared = alice_keys.ecdh(&bob_keys.public_key)?;
    let bob_shared = bob_keys.ecdh(&alice_keys.public_key)?;
    
    println!("ECDH 密钥交换: {} 字节", alice_shared.len());
    println!("密钥一致性: {}", if alice_shared == bob_shared { "一致" } else { "不一致" });
    assert_eq!(alice_shared, bob_shared);
    
    println!("✓ 椭圆曲线密码学演示完成\n");
    Ok(())
}

/// 运行所有简单 API 演示
pub fn run_simple_api_demos() -> Result<()> {
    println!("🌟 === 简单 API 使用演示集合 ===\n");
    
    hash_commitment_demo()?;
    pedersen_commitment_demo()?;
    merkle_tree_demo()?;
    hmac_demo()?;
    field_operations_demo()?;
    elliptic_curve_demo()?;
    
    println!("🎉 === 所有简单 API 演示完成 ===");
    println!("📝 演示总结:");
    println!("  ✓ 哈希承诺方案 - 简单高效的承诺和验证");
    println!("  ✓ Pedersen 承诺 - 支持同态运算的承诺方案");
    println!("  ✓ Merkle 树 - 高效的数据完整性证明");
    println!("  ✓ HMAC - 消息认证码和完整性验证");
    println!("  ✓ 有限域运算 - 密码学计算的数学基础");
    println!("  ✓ 椭圆曲线密码学 - 数字签名和密钥交换");
    println!("\n这些示例展示了 MPC API 中实际可用的基础密码学功能。");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_commitment_demo() {
        hash_commitment_demo().unwrap();
    }
    
    #[test]
    fn test_pedersen_commitment_demo() {
        pedersen_commitment_demo().unwrap();
    }
    
    #[test]
    fn test_merkle_tree_demo() {
        merkle_tree_demo().unwrap();
    }
    
    #[test]
    fn test_hmac_demo() {
        hmac_demo().unwrap();
    }
    
    #[test]
    fn test_field_operations_demo() {
        field_operations_demo().unwrap();
    }
    
    #[test]
    fn test_elliptic_curve_demo() {
        elliptic_curve_demo().unwrap();
    }
}

// 如果直接运行此文件，执行所有演示
fn main() -> Result<()> {
    run_simple_api_demos()
}