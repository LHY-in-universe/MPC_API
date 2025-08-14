//! # 基于 OLE 的 Beaver 三元组生成示例
//! 
//! 本示例展示了如何使用不经意线性求值 (Oblivious Linear Evaluation) 
//! 协议来生成和使用 Beaver 三元组进行安全多方乘法计算。

use mpc_api::{
    beaver_triples::{OLEBeaverGenerator, BeaverTripleGenerator, secure_multiply, batch_secure_multiply},
    secret_sharing::{ShamirSecretSharing, SecretSharing, field_mul, field_add},
    Result,
};

/// 基本的 OLE Beaver 三元组生成和使用示例
pub fn basic_ole_beaver_example() -> Result<()> {
    println!("=== 基于 OLE 的 Beaver 三元组生成示例 ===");
    
    // 1. 设置 MPC 参数
    let party_count = 3;    // 3 方 MPC
    let threshold = 2;      // 门限值为 2
    let party_id = 0;       // 当前是第 0 方
    
    println!("MPC 设置: {} 方参与，门限值 {}", party_count, threshold);
    
    // 2. 创建 OLE Beaver 生成器
    let mut ole_generator = OLEBeaverGenerator::new(party_count, threshold, party_id)?;
    println!("创建 OLE Beaver 三元组生成器成功");
    
    // 3. 生成单个 Beaver 三元组
    let beaver_triple = ole_generator.generate_single()?;
    println!("生成 Beaver 三元组成功");
    
    // 4. 验证三元组的正确性
    let is_valid = ole_generator.verify_triple(&beaver_triple)?;
    println!("三元组验证结果: {}", if is_valid { "通过" } else { "失败" });
    
    // 5. 展示三元组结构
    println!("三元组包含 {} 个参与方的分享", beaver_triple.shares.len());
    
    if let Some((a, b, c)) = beaver_triple.original_values {
        println!("原始值: a={}, b={}, c={}", a, b, c);
        println!("验证乘法关系: c = a * b = {}", field_mul(a, b));
        assert_eq!(c, field_mul(a, b));
    }
    
    println!("✓ 基本 OLE Beaver 生成测试通过\n");
    Ok(())
}

/// 使用 Beaver 三元组进行安全乘法的示例
pub fn secure_multiplication_example() -> Result<()> {
    println!("=== 使用 Beaver 三元组进行安全乘法 ===");
    
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    
    // 1. 生成 Beaver 三元组
    let mut ole_generator = OLEBeaverGenerator::new(party_count, threshold, party_id)?;
    let beaver_triple = ole_generator.generate_single()?;
    
    // 2. 创建要相乘的秘密值
    let x = 15u64;  // 第一个秘密值
    let y = 25u64;  // 第二个秘密值
    let expected_product = field_mul(x, y);
    
    println!("计算 {} × {} = {}", x, y, expected_product);
    
    // 3. 对秘密值进行秘密分享
    let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
    let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
    
    println!("对输入进行秘密分享:");
    for i in 0..party_count {
        println!("  方 {}: x_share=({},{}), y_share=({},{})", 
                i, x_shares[i].x, x_shares[i].y, y_shares[i].x, y_shares[i].y);
    }
    
    // 4. 执行安全乘法协议
    let product_shares = secure_multiply(&x_shares, &y_shares, &beaver_triple, threshold)?;
    
    println!("安全乘法生成的积分享:");
    for (i, share) in product_shares.iter().enumerate() {
        println!("  方 {}: product_share=({},{})", i, share.x, share.y);
    }
    
    // 5. 重构乘法结果
    let reconstructed_product = ShamirSecretSharing::reconstruct(
        &product_shares[0..threshold], 
        threshold
    )?;
    
    println!("重构的乘积结果: {}", reconstructed_product);
    println!("预期结果: {}", expected_product);
    
    // 6. 验证结果正确性
    assert_eq!(reconstructed_product, expected_product);
    println!("✓ 安全乘法验证通过\n");
    
    Ok(())
}

/// 批量生成和使用 Beaver 三元组的示例
pub fn batch_beaver_example() -> Result<()> {
    println!("=== 批量 Beaver 三元组操作示例 ===");
    
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    let batch_size = 5;
    
    // 1. 批量生成 Beaver 三元组
    let mut ole_generator = OLEBeaverGenerator::new(party_count, threshold, party_id)?;
    let beaver_triples = ole_generator.generate_batch(batch_size)?;
    
    println!("批量生成了 {} 个 Beaver 三元组", beaver_triples.len());
    
    // 2. 验证所有三元组
    let mut valid_count = 0;
    for (i, triple) in beaver_triples.iter().enumerate() {
        if ole_generator.verify_triple(triple)? {
            valid_count += 1;
        }
        
        if let Some((a, b, c)) = triple.original_values {
            println!("三元组 {}: a={}, b={}, c={}", i, a, b, c);
            assert_eq!(c, field_mul(a, b));
        }
    }
    
    println!("有效三元组数量: {}/{}", valid_count, batch_size);
    
    // 3. 使用批量三元组进行多个乘法运算
    let values = vec![
        (10u64, 20u64),
        (5u64, 30u64),
        (8u64, 12u64),
        (15u64, 7u64),
        (25u64, 4u64),
    ];
    
    println!("准备进行批量安全乘法:");
    for (i, (x, y)) in values.iter().enumerate() {
        println!("  乘法 {}: {} × {} = {}", i, x, y, field_mul(*x, *y));
    }
    
    // 创建输入分享
    let mut x_shares_batch = Vec::new();
    let mut y_shares_batch = Vec::new();
    
    for (x, y) in &values {
        let x_shares = ShamirSecretSharing::share(x, threshold, party_count)?;
        let y_shares = ShamirSecretSharing::share(y, threshold, party_count)?;
        x_shares_batch.push(x_shares);
        y_shares_batch.push(y_shares);
    }
    
    // 执行批量安全乘法
    let product_shares_batch = batch_secure_multiply(
        &x_shares_batch, 
        &y_shares_batch, 
        &beaver_triples, 
        threshold
    )?;
    
    // 验证批量结果
    for (i, (product_shares, (x, y))) in product_shares_batch.iter().zip(values.iter()).enumerate() {
        let reconstructed = ShamirSecretSharing::reconstruct(
            &product_shares[0..threshold], 
            threshold
        )?;
        let expected = field_mul(*x, *y);
        
        println!("批量乘法 {} 结果: {} (期望: {})", i, reconstructed, expected);
        assert_eq!(reconstructed, expected);
    }
    
    println!("✓ 批量 Beaver 三元组操作验证通过\n");
    
    Ok(())
}

/// 高性能批量生成示例
pub fn performance_batch_example() -> Result<()> {
    println!("=== 高性能批量生成示例 ===");
    
    use mpc_api::beaver_triples::BatchOLEBeaverGenerator;
    use std::time::Instant;
    
    let party_count = 3;
    let threshold = 2;  
    let party_id = 0;
    let batch_size = 50;
    let total_triples = 200;
    
    // 1. 创建批量生成器
    let mut batch_generator = BatchOLEBeaverGenerator::new(
        party_count, 
        threshold, 
        party_id, 
        batch_size
    )?;
    
    println!("创建批量 OLE 生成器，批量大小: {}", batch_size);
    
    // 2. 测量批量生成性能
    let start_time = Instant::now();
    let triples = batch_generator.generate_optimized_batch(total_triples)?;
    let duration = start_time.elapsed();
    
    println!("批量生成 {} 个三元组耗时: {:?}", total_triples, duration);
    println!("平均每个三元组耗时: {:?}", duration / total_triples as u32);
    
    // 3. 验证生成的三元组质量
    use mpc_api::beaver_triples::OLEBeaverVerifier;
    let verifier = OLEBeaverVerifier::new(party_count, threshold);
    let verification_results = verifier.batch_verify(&triples)?;
    
    let valid_count = verification_results.iter().filter(|&&x| x).count();
    println!("批量验证结果: {}/{} 个三元组有效", valid_count, total_triples);
    
    // 4. 预计算池示例
    println!("演示预计算池功能...");
    let pool_triples = batch_generator.precompute_pool(100)?;
    println!("预计算池生成了 {} 个三元组", pool_triples.len());
    
    println!("✓ 高性能批量生成测试通过\n");
    
    Ok(())
}

/// 完整的 OLE Beaver 三元组应用示例
pub fn comprehensive_ole_example() -> Result<()> {
    println!("=== 完整的 OLE Beaver 三元组应用示例 ===");
    
    // 模拟一个实际的 MPC 计算场景：
    // 三方想要计算表达式 (x1 * y1) + (x2 * y2) + (x3 * y3)
    // 但不想泄露各自的输入值
    
    let party_count = 3;
    let threshold = 2;
    
    // 各方的私有输入
    let inputs = vec![
        (12u64, 8u64),   // 方 0 的输入
        (15u64, 6u64),   // 方 1 的输入 
        (9u64, 11u64),   // 方 2 的输入
    ];
    
    println!("MPC 计算场景: 计算 (x1*y1) + (x2*y2) + (x3*y3)");
    println!("各方私有输入:");
    for (i, (x, y)) in inputs.iter().enumerate() {
        println!("  方 {}: x{}={}, y{}={}", i, i+1, x, i+1, y);
    }
    
    // 计算期望结果
    let expected_result = inputs.iter()
        .map(|(x, y)| field_mul(*x, *y))
        .fold(0u64, |acc, product| field_add(acc, product));
    
    println!("期望结果: {}", expected_result);
    
    // 为每一方创建生成器并进行计算
    let mut final_shares = Vec::new();
    
    for party_id in 0..party_count {
        let mut ole_generator = OLEBeaverGenerator::new(party_count, threshold, party_id)?;
        
        // 生成该方需要的 Beaver 三元组
        let beaver_triple = ole_generator.generate_single()?;
        
        // 获取该方的输入
        let (x, y) = inputs[party_id];
        
        // 创建输入分享 (在实际应用中，这会通过网络协议完成)
        let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
        let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
        
        // 执行安全乘法
        let product_shares = secure_multiply(&x_shares, &y_shares, &beaver_triple, threshold)?;
        
        // 保存结果分享
        final_shares.push(product_shares);
        
        println!("方 {} 完成安全乘法计算", party_id);
    }
    
    // 将所有乘积分享相加
    let mut sum_shares = final_shares[0].clone();
    for shares in final_shares.iter().skip(1) {
        for (i, share) in shares.iter().enumerate() {
            if i < sum_shares.len() {
                sum_shares[i].y = field_add(sum_shares[i].y, share.y);
            }
        }
    }
    
    // 重构最终结果
    let final_result = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
    
    println!("MPC 计算结果: {}", final_result);
    println!("验证结果: {}", if final_result == expected_result { "通过" } else { "失败" });
    
    assert_eq!(final_result, expected_result);
    println!("✓ 完整应用场景验证通过\n");
    
    Ok(())
}

/// 主示例函数，运行所有 OLE Beaver 三元组示例
pub fn run_all_ole_examples() -> Result<()> {
    println!("🚀 开始运行所有 OLE Beaver 三元组示例\n");
    
    // 运行各种示例
    basic_ole_beaver_example()?;
    secure_multiplication_example()?;
    batch_beaver_example()?;
    performance_batch_example()?;
    comprehensive_ole_example()?;
    
    println!("🎉 所有 OLE Beaver 三元组示例运行成功！");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_ole_beaver_example() {
        basic_ole_beaver_example().unwrap();
    }
    
    #[test]
    fn test_secure_multiplication_example() {
        secure_multiplication_example().unwrap();
    }
    
    #[test]
    fn test_batch_beaver_example() {
        batch_beaver_example().unwrap();
    }
    
    #[test]
    fn test_comprehensive_ole_example() {
        comprehensive_ole_example().unwrap();
    }
}

// 如果直接运行此文件，执行所有示例
#[allow(dead_code)]
fn main() -> Result<()> {
    run_all_ole_examples()
}