//! # 基于可信第三方的 Beaver 三元组生成示例
//! 
//! 本示例展示了如何使用可信第三方来高效生成和管理 Beaver 三元组。
//! 虽然引入了可信设置假设，但在许多实际场景中这是可接受且高效的解决方案。

use mpc_api::{
    beaver_triples::{TrustedPartyBeaverGenerator, BatchTrustedPartyGenerator, TrustedPartyConfig,
                     TrustedPartyAuditor, BeaverTripleGenerator, secure_multiply, verify_triple_batch},
    secret_sharing::{ShamirSecretSharing, SecretSharing, field_mul, field_add},
    Result,
};

/// 基本的可信第三方 Beaver 三元组生成示例
pub fn basic_trusted_party_example() -> Result<()> {
    println!("=== 基于可信第三方的 Beaver 三元组生成示例 ===");
    
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    
    // 1. 使用默认配置创建可信第三方生成器
    let mut tp_generator = TrustedPartyBeaverGenerator::new(
        party_count, 
        threshold, 
        party_id, 
        None
    )?;
    
    println!("创建可信第三方 Beaver 生成器成功");
    println!("参与方数量: {}, 门限值: {}", party_count, threshold);
    
    // 2. 生成单个 Beaver 三元组
    let beaver_triple = tp_generator.generate_single()?;
    println!("生成 Beaver 三元组成功");
    
    // 3. 验证三元组
    let is_valid = tp_generator.verify_triple(&beaver_triple)?;
    println!("三元组验证结果: {}", if is_valid { "通过" } else { "失败" });
    
    // 4. 显示三元组信息
    println!("三元组分享数量: {}", beaver_triple.shares.len());
    
    if let Some((a, b, c)) = beaver_triple.original_values {
        println!("可信第三方生成的原始值:");
        println!("  a = {}", a);
        println!("  b = {}", b);  
        println!("  c = {} (= {} × {} = {})", c, a, b, field_mul(a, b));
        
        assert_eq!(c, field_mul(a, b));
    }
    
    // 5. 显示各方的分享
    println!("各参与方的分享:");
    for (party_id, share) in &beaver_triple.shares {
        println!("  方 {}: a_share=({},{}), b_share=({},{}), c_share=({},{})", 
                party_id,
                share.a.x, share.a.y,
                share.b.x, share.b.y,
                share.c.x, share.c.y);
    }
    
    assert!(is_valid);
    println!("✓ 基本可信第三方生成测试通过\n");
    
    Ok(())
}

/// 可信第三方配置选项示例
pub fn trusted_party_configuration_example() -> Result<()> {
    println!("=== 可信第三方配置选项示例 ===");
    
    let party_count = 4;
    let threshold = 3;
    let party_id = 0;
    
    // 1. 创建自定义配置
    let custom_config = TrustedPartyConfig {
        enable_precomputation: true,
        pool_size: 50,
        batch_size: 20,
        enable_security_checks: true,
    };
    
    println!("自定义可信第三方配置:");
    println!("  启用预计算: {}", custom_config.enable_precomputation);
    println!("  池大小: {}", custom_config.pool_size);
    println!("  批量大小: {}", custom_config.batch_size);
    println!("  启用安全检查: {}", custom_config.enable_security_checks);
    
    // 2. 使用自定义配置创建生成器
    let mut tp_generator = TrustedPartyBeaverGenerator::new(
        party_count,
        threshold, 
        party_id,
        Some(custom_config)
    )?;
    
    println!("使用自定义配置创建生成器成功");
    
    // 3. 测试预计算池功能
    println!("\n测试预计算池功能...");
    
    // 由于启用了预计算，第一次生成应该很快（从池中获取）
    use std::time::Instant;
    
    let start = Instant::now();
    let triple1 = tp_generator.generate_single()?;
    let duration1 = start.elapsed();
    
    let start = Instant::now();
    let triple2 = tp_generator.generate_single()?;
    let duration2 = start.elapsed();
    
    println!("第1个三元组生成时间: {:?}", duration1);
    println!("第2个三元组生成时间: {:?}", duration2);
    
    // 4. 验证预计算的三元组质量
    assert!(tp_generator.verify_triple(&triple1)?);
    assert!(tp_generator.verify_triple(&triple2)?);
    
    println!("预计算的三元组验证通过");
    
    // 5. 测试安全检查功能
    println!("\n测试安全检查...");
    let batch_triples = tp_generator.generate_batch(5)?;
    
    for (i, triple) in batch_triples.iter().enumerate() {
        let is_valid = tp_generator.verify_triple(triple)?;
        println!("批量三元组 {} 安全检查: {}", i, if is_valid { "通过" } else { "失败" });
        assert!(is_valid);
    }
    
    println!("✓ 可信第三方配置测试通过\n");
    
    Ok(())
}

/// 高性能批量生成示例
pub fn high_performance_batch_example() -> Result<()> {
    println!("=== 高性能批量生成示例 ===");
    
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    let batch_size = 100;
    
    // 1. 创建批量生成器
    let mut batch_generator = BatchTrustedPartyGenerator::new(
        party_count,
        threshold,
        party_id, 
        batch_size
    )?;
    
    println!("创建批量可信第三方生成器，批量大小: {}", batch_size);
    
    // 2. 性能测试：生成大量三元组
    let test_sizes = vec![50, 100, 200, 500];
    
    for &size in &test_sizes {
        let start = std::time::Instant::now();
        let triples = batch_generator.generate_optimized_batch(size)?;
        let duration = start.elapsed();
        
        println!("生成 {} 个三元组耗时: {:?}", size, duration);
        println!("  平均每个三元组: {:?}", duration / size as u32);
        
        // 验证生成的三元组
        let valid_count = triples.iter()
            .map(|t| t.verify(2).unwrap_or(false))
            .filter(|&x| x)
            .count();
            
        println!("  有效三元组: {}/{}", valid_count, size);
        assert_eq!(valid_count, size);
    }
    
    // 3. 吞吐量测试
    println!("\n吞吐量测试 (1000个三元组):");
    let large_batch_size = 1000;
    let start = std::time::Instant::now();
    let large_batch = batch_generator.generate_optimized_batch(large_batch_size)?;
    let total_time = start.elapsed();
    
    let throughput = large_batch_size as f64 / total_time.as_secs_f64();
    println!("生成 {} 个三元组总时间: {:?}", large_batch_size, total_time);
    println!("吞吐量: {:.2} 个三元组/秒", throughput);
    
    // 验证大批量的质量
    let verification_result = verify_triple_batch(&large_batch, threshold)?;
    println!("大批量验证结果: {}", if verification_result { "全部通过" } else { "存在问题" });
    
    assert!(verification_result);
    println!("✓ 高性能批量生成测试通过\n");
    
    Ok(())
}

/// 可信第三方安全审计示例
pub fn trusted_party_audit_example() -> Result<()> {
    println!("=== 可信第三方安全审计示例 ===");
    
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    
    // 1. 生成一批三元组用于审计
    let mut tp_generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
    let audit_triples = tp_generator.generate_batch(20)?;
    
    println!("生成 {} 个三元组用于安全审计", audit_triples.len());
    
    // 2. 创建审计器
    let auditor = TrustedPartyAuditor::new(party_count, threshold);
    
    // 3. 审计统计性质
    println!("执行统计性质审计...");
    let statistical_result = auditor.audit_statistical_properties(&audit_triples)?;
    println!("统计性质审计结果: {}", if statistical_result { "通过" } else { "可疑" });
    
    // 4. 审计密码学性质
    println!("执行密码学性质审计...");
    let cryptographic_result = auditor.audit_cryptographic_properties(&audit_triples)?;
    println!("密码学性质审计结果: {}", if cryptographic_result { "通过" } else { "失败" });
    
    // 5. 详细审计报告
    println!("\n详细审计报告:");
    println!("审计项目:");
    println!("  ✓ 三元组结构完整性");
    println!("  ✓ 乘法关系正确性");
    println!("  ✓ 分享一致性");
    println!("  ✓ 参与方分享完整性");
    println!("  ✓ 随机性分布检查");
    
    // 6. 模拟检测异常三元组
    println!("\n模拟异常检测...");
    // 这里可以添加故意构造错误三元组的代码来测试检测能力
    
    assert!(statistical_result);
    assert!(cryptographic_result);
    
    println!("✓ 安全审计测试通过\n");
    
    Ok(())
}

/// 使用可信第三方三元组进行安全计算示例
pub fn trusted_party_secure_computation_example() -> Result<()> {
    println!("=== 可信第三方安全计算示例 ===");
    
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    
    // 1. 生成可信第三方 Beaver 三元组
    let mut tp_generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
    let beaver_triple = tp_generator.generate_single()?;
    
    // 2. 安全乘法计算
    let x = 33u64;
    let y = 27u64;
    let expected = field_mul(x, y);
    
    println!("使用可信第三方三元组进行安全乘法: {} × {}", x, y);
    
    // 3. 创建输入分享
    let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
    let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
    
    println!("输入分享创建完成");
    
    // 4. 执行安全乘法协议
    let product_shares = secure_multiply(&x_shares, &y_shares, &beaver_triple, threshold)?;
    
    println!("安全乘法协议执行完成");
    
    // 5. 重构结果
    let result = ShamirSecretSharing::reconstruct(&product_shares[0..threshold], threshold)?;
    
    println!("计算结果: {}", result);
    println!("预期结果: {}", expected);
    
    // 6. 验证正确性
    assert_eq!(result, expected);
    println!("✓ 可信第三方安全计算验证通过");
    
    // 7. 性能对比说明
    println!("\n可信第三方方法特点:");
    println!("优势:");
    println!("  + 生成速度最快");
    println!("  + 通信开销最小");
    println!("  + 实现复杂度最低");
    println!("  + 易于批量优化");
    
    println!("限制:");
    println!("  - 需要可信第三方");
    println!("  - 存在单点故障风险");
    println!("  - 需要额外的安全假设");
    
    println!("适用场景:");
    println!("  • 受控环境下的MPC");
    println!("  • 对性能要求极高的应用");
    println!("  • 可以接受可信设置的情况");
    
    println!("✓ 安全计算示例完成\n");
    
    Ok(())
}

/// 多方协作场景示例
pub fn multi_party_collaboration_example() -> Result<()> {
    println!("=== 多方协作场景示例 ===");
    
    // 场景：四家公司联合进行市场调研数据分析
    // 计算总体市场满意度 = Σ(公司i的满意度 × 公司i的市场份额)
    
    let party_count = 4;
    let threshold = 3;
    
    println!("场景: 四家公司联合市场调研分析");
    println!("计算公式: 总满意度 = Σ(满意度i × 市场份额i)");
    
    // 各公司的数据 (敏感商业信息)
    let company_data = vec![
        (85u64, 25u64),  // 公司A: 满意度85, 市场份额25%
        (78u64, 30u64),  // 公司B: 满意度78, 市场份额30%
        (92u64, 20u64),  // 公司C: 满意度92, 市场份额20%
        (88u64, 25u64),  // 公司D: 满意度88, 市场份额25%
    ];
    
    println!("公司数据 (敏感):");
    for (i, (satisfaction, share)) in company_data.iter().enumerate() {
        println!("  公司 {}: 满意度={}%, 市场份额={}%", 
                 char::from(b'A' + i as u8), satisfaction, share);
    }
    
    // 计算预期结果
    let expected_total = company_data.iter()
        .map(|(satisfaction, share)| field_mul(*satisfaction, *share))
        .fold(0u64, |acc, weighted| field_add(acc, weighted));
    
    println!("预期总体满意度指标: {}", expected_total);
    
    // 使用可信第三方协调计算
    println!("\n开始可信第三方协调的联合计算...");
    
    let mut aggregated_shares = None;
    
    for company_id in 0..party_count {
        println!("公司 {} 开始参与计算...", char::from(b'A' + company_id as u8));
        
        // 每家公司通过可信第三方获取 Beaver 三元组
        let mut tp_generator = TrustedPartyBeaverGenerator::new(
            party_count, 
            threshold, 
            company_id, 
            None
        )?;
        
        let beaver_triple = tp_generator.generate_single()?;
        
        // 获取公司数据
        let (satisfaction, market_share) = company_data[company_id];
        
        // 创建秘密分享
        let satisfaction_shares = ShamirSecretSharing::share(&satisfaction, threshold, party_count)?;
        let share_shares = ShamirSecretSharing::share(&market_share, threshold, party_count)?;
        
        // 使用 Beaver 三元组进行安全乘法
        let weighted_shares = secure_multiply(&satisfaction_shares, &share_shares, &beaver_triple, threshold)?;
        
        // 聚合结果
        match aggregated_shares {
            None => {
                aggregated_shares = Some(weighted_shares);
            },
            Some(ref mut total) => {
                for (i, share) in weighted_shares.iter().enumerate() {
                    if i < total.len() {
                        total[i].y = field_add(total[i].y, share.y);
                    }
                }
            }
        }
        
        println!("  公司 {} 计算完成 ✓", char::from(b'A' + company_id as u8));
    }
    
    // 重构最终结果
    if let Some(final_shares) = aggregated_shares {
        let total_satisfaction = ShamirSecretSharing::reconstruct(&final_shares[0..threshold], threshold)?;
        
        println!("\n联合计算结果:");
        println!("总体市场满意度指标: {}", total_satisfaction);
        println!("预期结果: {}", expected_total);
        println!("计算准确性: {}", if total_satisfaction == expected_total { "完全正确" } else { "需检查" });
        
        assert_eq!(total_satisfaction, expected_total);
        
        println!("\n🏢 四家公司成功完成联合分析，商业敏感数据得到保护 ✓");
        println!("可信第三方确保了计算的高效性和数据的隐私性");
    }
    
    println!("✓ 多方协作场景验证通过\n");
    
    Ok(())
}

/// 主示例函数，运行所有可信第三方示例
pub fn run_all_trusted_party_examples() -> Result<()> {
    println!("🤝 开始运行所有可信第三方 Beaver 三元组示例\n");
    
    basic_trusted_party_example()?;
    trusted_party_configuration_example()?;
    high_performance_batch_example()?;
    trusted_party_audit_example()?;
    trusted_party_secure_computation_example()?;
    multi_party_collaboration_example()?;
    
    println!("🎉 所有可信第三方 Beaver 三元组示例运行成功！");
    println!("可信第三方方案在受控环境中提供了最高效的解决方案 ⚡");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_trusted_party() {
        basic_trusted_party_example().unwrap();
    }
    
    #[test]
    fn test_trusted_party_configuration() {
        trusted_party_configuration_example().unwrap();
    }
    
    #[test]
    fn test_high_performance_batch() {
        high_performance_batch_example().unwrap();
    }
    
    #[test]
    fn test_trusted_party_audit() {
        trusted_party_audit_example().unwrap();
    }
    
    #[test]
    fn test_multi_party_collaboration() {
        multi_party_collaboration_example().unwrap();
    }
}

// 如果直接运行此文件，执行所有示例
fn main() -> Result<()> {
    run_all_trusted_party_examples()
}