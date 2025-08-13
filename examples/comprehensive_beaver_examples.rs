//! # 综合 Beaver 三元组方法对比示例
//! 
//! 本示例综合展示和对比了三种 Beaver 三元组生成方法：
//! 1. OLE (不经意线性求值) 方法
//! 2. BFV (同态加密) 方法  
//! 3. 可信第三方方法
//! 
//! 通过同一个应用场景来展示各种方法的特点和适用性。

use std::time::Instant;
use mpc_api::{
    beaver_triples::*,
    secret_sharing::{ShamirSecretSharing, SecretSharing, field_mul, field_add, FIELD_PRIME},
    Result,
};

/// 方法性能对比结构
#[derive(Debug)]
pub struct MethodPerformance {
    pub method_name: String,
    pub generation_time: std::time::Duration,
    pub verification_time: std::time::Duration,
    pub computation_time: std::time::Duration,
    pub security_level: String,
    pub setup_complexity: String,
}

/// 综合性能对比示例
pub fn comprehensive_performance_comparison() -> Result<()> {
    println!("🔄 === 三种 Beaver 三元组方法综合对比 ===\n");
    
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    let test_iterations = 5;
    
    println!("测试参数:");
    println!("  参与方数量: {}", party_count);
    println!("  门限值: {}", threshold);
    println!("  测试轮次: {}", test_iterations);
    println!();
    
    let mut performances = Vec::new();
    
    // 1. 测试 OLE 方法
    println!("📊 测试 OLE (不经意线性求值) 方法...");
    {
        let mut total_gen_time = std::time::Duration::new(0, 0);
        let mut total_ver_time = std::time::Duration::new(0, 0);
        let mut total_comp_time = std::time::Duration::new(0, 0);
        
        for i in 0..test_iterations {
            println!("  OLE 测试轮次 {}/{}", i + 1, test_iterations);
            
            // 生成时间
            let start = Instant::now();
            let mut ole_generator = OLEBeaverGenerator::new(party_count, threshold, party_id)?;
            let ole_triple = ole_generator.generate_single()?;
            total_gen_time += start.elapsed();
            
            // 验证时间
            let start = Instant::now();
            let _is_valid = ole_generator.verify_triple(&ole_triple)?;
            total_ver_time += start.elapsed();
            
            // 计算时间 (安全乘法)
            let x = 123u64;
            let y = 456u64;
            let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
            let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
            
            let start = Instant::now();
            let _result = secure_multiply(&x_shares, &y_shares, &ole_triple, threshold)?;
            total_comp_time += start.elapsed();
        }
        
        performances.push(MethodPerformance {
            method_name: "OLE (不经意线性求值)".to_string(),
            generation_time: total_gen_time / test_iterations as u32,
            verification_time: total_ver_time / test_iterations as u32,
            computation_time: total_comp_time / test_iterations as u32,
            security_level: "标准安全 (~80-128位)".to_string(),
            setup_complexity: "中等 (需要OT协议)".to_string(),
        });
    }
    
    // 2. 测试 BFV 方法
    println!("🔐 测试 BFV (同态加密) 方法...");
    {
        let mut total_gen_time = std::time::Duration::new(0, 0);
        let mut total_ver_time = std::time::Duration::new(0, 0);
        let mut total_comp_time = std::time::Duration::new(0, 0);
        
        for i in 0..test_iterations {
            println!("  BFV 测试轮次 {}/{}", i + 1, test_iterations);
            
            // 生成时间
            let start = Instant::now();
            let mut bfv_generator = BFVBeaverGenerator::new(party_count, threshold, party_id, None)?;
            let bfv_triple = bfv_generator.generate_single()?;
            total_gen_time += start.elapsed();
            
            // 验证时间
            let start = Instant::now();
            let _is_valid = bfv_generator.verify_triple(&bfv_triple)?;
            total_ver_time += start.elapsed();
            
            // 计算时间
            let x = 123u64;
            let y = 456u64;
            let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
            let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
            
            let start = Instant::now();
            let _result = secure_multiply(&x_shares, &y_shares, &bfv_triple, threshold)?;
            total_comp_time += start.elapsed();
        }
        
        performances.push(MethodPerformance {
            method_name: "BFV (同态加密)".to_string(),
            generation_time: total_gen_time / test_iterations as u32,
            verification_time: total_ver_time / test_iterations as u32,
            computation_time: total_comp_time / test_iterations as u32,
            security_level: "高安全 (~128-256位)".to_string(),
            setup_complexity: "高 (需要密钥分发)".to_string(),
        });
    }
    
    // 3. 测试可信第三方方法
    println!("🤝 测试可信第三方方法...");
    {
        let mut total_gen_time = std::time::Duration::new(0, 0);
        let mut total_ver_time = std::time::Duration::new(0, 0);
        let mut total_comp_time = std::time::Duration::new(0, 0);
        
        for i in 0..test_iterations {
            println!("  可信第三方测试轮次 {}/{}", i + 1, test_iterations);
            
            // 生成时间
            let start = Instant::now();
            let mut tp_generator = TrustedPartyBeaverGenerator::new(party_count, threshold, party_id, None)?;
            let tp_triple = tp_generator.generate_single()?;
            total_gen_time += start.elapsed();
            
            // 验证时间
            let start = Instant::now();
            let _is_valid = tp_generator.verify_triple(&tp_triple)?;
            total_ver_time += start.elapsed();
            
            // 计算时间
            let x = 123u64;
            let y = 456u64;
            let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
            let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
            
            let start = Instant::now();
            let _result = secure_multiply(&x_shares, &y_shares, &tp_triple, threshold)?;
            total_comp_time += start.elapsed();
        }
        
        performances.push(MethodPerformance {
            method_name: "可信第三方".to_string(),
            generation_time: total_gen_time / test_iterations as u32,
            verification_time: total_ver_time / test_iterations as u32,
            computation_time: total_comp_time / test_iterations as u32,
            security_level: "依赖可信设置".to_string(),
            setup_complexity: "低 (需要可信方)".to_string(),
        });
    }
    
    // 4. 输出对比结果
    println!("\n📈 === 性能对比结果 ===");
    println!("{:20} {:15} {:15} {:15} {:20} {:25}", 
             "方法", "生成时间", "验证时间", "计算时间", "安全级别", "设置复杂度");
    println!("{}", "-".repeat(110));
    
    for perf in &performances {
        println!("{:20} {:13?} {:13?} {:13?} {:20} {:25}",
                 perf.method_name,
                 perf.generation_time,
                 perf.verification_time,
                 perf.computation_time,
                 perf.security_level,
                 perf.setup_complexity);
    }
    
    // 5. 方法特点总结
    println!("\n🎯 === 方法特点总结 ===");
    
    println!("\n📊 OLE (不经意线性求值) 方法:");
    println!("  优势: 平衡的安全性和性能，标准的密码学构造");
    println!("  劣势: 需要复杂的 OT 协议实现");
    println!("  适用: 标准MPC应用，对性能和安全都有要求的场景");
    
    println!("\n🔐 BFV (同态加密) 方法:");
    println!("  优势: 最高安全级别，抗量子攻击，计算完全隐私");
    println!("  劣势: 性能相对较慢，实现复杂度高");
    println!("  适用: 高安全要求场景，如金融、医疗等关键应用");
    
    println!("\n🤝 可信第三方方法:");
    println!("  优势: 最高性能，实现简单，易于批量优化");
    println!("  劣势: 需要可信设置，存在单点故障风险");
    println!("  适用: 受控环境，性能优先场景，可接受可信假设的应用");
    
    println!("\n✓ 综合对比测试完成\n");
    Ok(())
}

/// 实际应用场景：联合数据分析
pub fn joint_data_analysis_scenario() -> Result<()> {
    println!("💼 === 实际应用场景：三方联合数据分析 ===\n");
    
    // 场景：三家医院联合分析患者康复率，但不能泄露各自的患者数据
    // 计算总体康复率 = (医院1康复数×权重1 + 医院2康复数×权重2 + 医院3康复数×权重3) / 总权重
    
    let party_count = 3;
    let threshold = 2;
    
    // 各医院的敏感数据 (康复病例数, 权重)
    let hospital_data = vec![
        (85u64, 40u64),  // 医院A: 85例康复，权重40
        (92u64, 35u64),  // 医院B: 92例康复，权重35
        (78u64, 25u64),  // 医院C: 78例康复，权重25
    ];
    
    let total_weight = hospital_data.iter().map(|(_, w)| *w).sum::<u64>();
    
    println!("场景：三家医院联合康复率分析");
    println!("各医院数据 (敏感):");
    for (i, (recovery, weight)) in hospital_data.iter().enumerate() {
        println!("  医院 {}: 康复病例={}, 权重={}", 
                 char::from(b'A' + i as u8), recovery, weight);
    }
    println!("总权重: {}", total_weight);
    
    // 预期结果 (用于验证)
    let expected_numerator = hospital_data.iter()
        .map(|(recovery, weight)| field_mul(*recovery, *weight))
        .fold(0u64, |acc, weighted| field_add(acc, weighted));
    
    println!("预期加权康复病例总数: {}", expected_numerator);
    println!("预期康复率: {:.2}%", expected_numerator as f64 / total_weight as f64 * 100.0);
    
    println!("\n🔄 使用不同方法进行联合计算...\n");
    
    // 方法1: 使用 OLE 方法
    println!("📊 方法1: 使用 OLE 方法");
    let ole_result = {
        let mut ole_total = None;
        
        for (hospital_id, (recovery, weight)) in hospital_data.iter().enumerate() {
            let mut ole_gen = OLEBeaverGenerator::new(party_count, threshold, hospital_id)?;
            let triple = ole_gen.generate_single()?;
            
            let recovery_shares = ShamirSecretSharing::share(recovery, threshold, party_count)?;
            let weight_shares = ShamirSecretSharing::share(weight, threshold, party_count)?;
            
            let weighted_shares = secure_multiply(&recovery_shares, &weight_shares, &triple, threshold)?;
            
            match ole_total {
                None => ole_total = Some(weighted_shares),
                Some(ref mut total) => {
                    for (i, share) in weighted_shares.iter().enumerate() {
                        if i < total.len() {
                            total[i].y = field_add(total[i].y, share.y);
                        }
                    }
                }
            }
        }
        
        if let Some(shares) = ole_total {
            ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?
        } else { 0 }
    };
    
    println!("  OLE 方法计算结果: {}", ole_result);
    assert_eq!(ole_result, expected_numerator);
    
    // 方法2: 使用 BFV 方法
    println!("🔐 方法2: 使用 BFV 方法");
    let bfv_result = {
        let mut bfv_total = None;
        
        for (hospital_id, (recovery, weight)) in hospital_data.iter().enumerate() {
            let mut bfv_gen = BFVBeaverGenerator::new(party_count, threshold, hospital_id, None)?;
            let triple = bfv_gen.generate_single()?;
            
            let recovery_shares = ShamirSecretSharing::share(recovery, threshold, party_count)?;
            let weight_shares = ShamirSecretSharing::share(weight, threshold, party_count)?;
            
            let weighted_shares = secure_multiply(&recovery_shares, &weight_shares, &triple, threshold)?;
            
            match bfv_total {
                None => bfv_total = Some(weighted_shares),
                Some(ref mut total) => {
                    for (i, share) in weighted_shares.iter().enumerate() {
                        if i < total.len() {
                            total[i].y = field_add(total[i].y, share.y);
                        }
                    }
                }
            }
        }
        
        if let Some(shares) = bfv_total {
            ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?
        } else { 0 }
    };
    
    println!("  BFV 方法计算结果: {}", bfv_result);
    assert_eq!(bfv_result, expected_numerator);
    
    // 方法3: 使用可信第三方方法
    println!("🤝 方法3: 使用可信第三方方法");
    let tp_result = {
        let mut tp_total = None;
        
        for (hospital_id, (recovery, weight)) in hospital_data.iter().enumerate() {
            let mut tp_gen = TrustedPartyBeaverGenerator::new(party_count, threshold, hospital_id, None)?;
            let triple = tp_gen.generate_single()?;
            
            let recovery_shares = ShamirSecretSharing::share(recovery, threshold, party_count)?;
            let weight_shares = ShamirSecretSharing::share(weight, threshold, party_count)?;
            
            let weighted_shares = secure_multiply(&recovery_shares, &weight_shares, &triple, threshold)?;
            
            match tp_total {
                None => tp_total = Some(weighted_shares),
                Some(ref mut total) => {
                    for (i, share) in weighted_shares.iter().enumerate() {
                        if i < total.len() {
                            total[i].y = field_add(total[i].y, share.y);
                        }
                    }
                }
            }
        }
        
        if let Some(shares) = tp_total {
            ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?
        } else { 0 }
    };
    
    println!("  可信第三方方法计算结果: {}", tp_result);
    assert_eq!(tp_result, expected_numerator);
    
    // 结果汇总
    println!("\n📋 === 计算结果汇总 ===");
    println!("OLE 方法结果:      {}", ole_result);
    println!("BFV 方法结果:      {}", bfv_result);
    println!("可信第三方结果:    {}", tp_result);
    println!("预期结果:          {}", expected_numerator);
    println!();
    
    let final_rate = expected_numerator as f64 / total_weight as f64 * 100.0;
    println!("🏥 联合康复率分析结果: {:.2}%", final_rate);
    println!("✅ 所有方法计算结果一致，患者隐私得到保护");
    
    println!("✓ 联合数据分析场景验证通过\n");
    Ok(())
}

/// 安全性对比分析
pub fn security_comparison_analysis() -> Result<()> {
    println!("🔒 === 安全性对比分析 ===\n");
    
    println!("🛡️ 各方法安全性分析:");
    
    println!("\n📊 OLE (不经意线性求值) 方法:");
    println!("  ✓ 半诚实安全 (Honest-but-curious secure)");
    println!("  ✓ 基于标准困难假设 (OT security)");
    println!("  ✓ 计算安全 (~80-128位安全级别)");
    println!("  • 抗窃听: 中等 (依赖OT协议安全性)");
    println!("  • 抗篡改: 中等 (需要额外MAC验证)");
    println!("  • 抗量子: 否 (基于传统困难问题)");
    
    println!("\n🔐 BFV (同态加密) 方法:");
    println!("  ✓ 信息论/计算安全 (~128-256位安全级别)");
    println!("  ✓ 基于格困难问题 (Learning With Errors)");
    println!("  ✓ 完全隐私保护 (计算过程完全加密)");
    println!("  • 抗窃听: 高 (所有中间计算都加密)");
    println!("  • 抗篡改: 高 (密文完整性保护)");
    println!("  • 抗量子: 是 (基于格密码学)");
    
    println!("\n🤝 可信第三方方法:");
    println!("  ✓ 依赖可信设置安全");
    println!("  ✓ 半诚实第三方假设");
    println!("  ✓ 参与方间隐私保护");
    println!("  • 抗窃听: 高 (第三方处可能泄露)");
    println!("  • 抗篡改: 中等 (依赖第三方诚实)");
    println!("  • 抗量子: 依赖底层秘密分享方案");
    
    println!("\n🎯 威胁模型对比:");
    
    println!("\n敌手类型        | OLE方法  | BFV方法  | 可信第三方");
    println!("----------------|---------|---------|----------");
    println!("半诚实敌手       | ✅       | ✅       | ✅");
    println!("恶意敌手         | 🔸       | ✅       | 🔸");
    println!("合谋攻击         | 🔸       | ✅       | ⚠️");
    println!("量子攻击         | ❌       | ✅       | 🔸");
    
    println!("\n图例:");
    println!("✅ = 完全防护    🔸 = 部分防护    ⚠️ = 有风险    ❌ = 无防护");
    
    println!("\n🔍 安全性权衡分析:");
    
    println!("\n性能 vs 安全性:");
    println!("  可信第三方 > OLE > BFV  (性能排序)");
    println!("  BFV > OLE > 可信第三方  (安全性排序)");
    
    println!("\n实施复杂度 vs 安全保证:");
    println!("  可信第三方: 低复杂度，需要信任假设");
    println!("  OLE: 中等复杂度，标准安全假设");
    println!("  BFV: 高复杂度，最强安全保证");
    
    // 具体安全参数展示
    println!("\n📊 具体安全参数 (示例):");
    
    let security_params = vec![
        ("OLE", "128位", "椭圆曲线离散对数", "否"),
        ("BFV", "256位", "格上困难问题", "是"),
        ("可信第三方", "依赖设置", "秘密分享", "部分"),
    ];
    
    println!("{:12} {:10} {:20} {:8}", "方法", "安全级别", "数学基础", "抗量子");
    println!("{}", "-".repeat(52));
    for (method, level, basis, quantum) in security_params {
        println!("{:12} {:10} {:20} {:8}", method, level, basis, quantum);
    }
    
    println!("\n✓ 安全性对比分析完成\n");
    Ok(())
}

/// 使用建议和最佳实践
pub fn usage_recommendations() -> Result<()> {
    println!("💡 === 使用建议和最佳实践 ===\n");
    
    println!("🎯 方法选择指南:");
    
    println!("\n📊 选择 OLE 方法的场景:");
    println!("  ✅ 需要平衡性能和安全性");
    println!("  ✅ 标准的MPC应用");
    println!("  ✅ 有经验的密码学团队");
    println!("  ✅ 中等安全要求 (80-128位)");
    println!("  例子: 联合机器学习、隐私广告拍卖");
    
    println!("\n🔐 选择 BFV 方法的场景:");
    println!("  ✅ 最高安全要求 (>128位)");
    println!("  ✅ 需要抗量子保护");
    println!("  ✅ 金融、医疗等关键应用");
    println!("  ✅ 可以接受较低性能");
    println!("  例子: 金融风控、医疗数据分析、政府应用");
    
    println!("\n🤝 选择可信第三方方法的场景:");
    println!("  ✅ 性能要求极高");
    println!("  ✅ 受控环境部署");
    println!("  ✅ 可以接受可信设置");
    println!("  ✅ 快速原型开发");
    println!("  例子: 内部数据分析、研究原型、受控联合计算");
    
    println!("\n🛠️ 实施最佳实践:");
    
    println!("\n通用最佳实践:");
    println!("  • 始终使用足够大的有限域 (至少 2^61-1)");
    println!("  • 实施完整的错误处理和恢复机制");
    println!("  • 进行充分的安全测试和审计");
    println!("  • 使用安全的随机数生成器");
    println!("  • 实施访问控制和审计日志");
    
    println!("\nOLE 方法特定实践:");
    println!("  • 确保 OT 协议的正确实现");
    println!("  • 使用 OT 扩展优化大规模应用");
    println!("  • 实施消息认证防止篡改");
    println!("  • 考虑网络延迟对性能的影响");
    
    println!("\nBFV 方法特定实践:");
    println!("  • 选择适当的安全参数 (n, q, t)");
    println!("  • 实施噪声管理和刷新机制");
    println!("  • 使用批处理技术提高效率");
    println!("  • 进行密钥管理和分发协议");
    
    println!("\n可信第三方方法特定实践:");
    println!("  • 确保第三方的物理和网络安全");
    println!("  • 实施多重验证和审计机制");
    println!("  • 考虑第三方的高可用性部署");
    println!("  • 准备应急和恢复方案");
    
    println!("\n⚠️ 常见陷阱和注意事项:");
    
    println!("\n安全陷阱:");
    println!("  ❌ 使用不安全的随机数生成");
    println!("  ❌ 忽略侧信道攻击防护");
    println!("  ❌ 不当的错误处理泄露信息");
    println!("  ❌ 重复使用一次性密钥材料");
    
    println!("\n性能陷阱:");
    println!("  ❌ 过度的网络通信");
    println!("  ❌ 不必要的密码学运算");
    println!("  ❌ 缺乏批处理优化");
    println!("  ❌ 内存管理不当");
    
    println!("\n🚀 性能优化建议:");
    
    println!("\n通用优化:");
    println!("  • 使用预计算和缓存机制");
    println!("  • 实施并行计算");
    println!("  • 优化网络通信模式");
    println!("  • 使用专用硬件加速 (如GPU)");
    
    println!("\n方法特定优化:");
    println!("  OLE: OT扩展、批量OLE、流水线处理");
    println!("  BFV: SIMD批处理、NTT优化、密钥切换优化");
    println!("  可信第三方: 预计算池、批量分发、负载均衡");
    
    println!("\n📊 部署架构建议:");
    
    println!("\n小规模部署 (2-5方):");
    println!("  • 推荐: 可信第三方或OLE方法");
    println!("  • 重点: 快速部署和使用便利性");
    
    println!("\n中规模部署 (5-20方):");
    println!("  • 推荐: OLE方法");
    println!("  • 重点: 性能和安全性平衡");
    
    println!("\n大规模部署 (20+方):");
    println!("  • 推荐: 混合方案 (不同阶段使用不同方法)");
    println!("  • 重点: 可扩展性和容错能力");
    
    println!("✓ 使用建议和最佳实践完成\n");
    Ok(())
}

/// 运行所有综合示例
pub fn run_all_comprehensive_examples() -> Result<()> {
    println!("🌟 === 开始运行综合 Beaver 三元组示例 ===\n");
    
    comprehensive_performance_comparison()?;
    joint_data_analysis_scenario()?;
    security_comparison_analysis()?;
    usage_recommendations()?;
    
    println!("🎉 === 所有综合示例运行完成 ===");
    println!("📚 通过这些示例，你已经全面了解了三种 Beaver 三元组生成方法");
    println!("🔧 可以根据具体需求选择最适合的方法进行实际部署");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_comprehensive_performance_comparison() {
        comprehensive_performance_comparison().unwrap();
    }
    
    #[test] 
    fn test_joint_data_analysis_scenario() {
        joint_data_analysis_scenario().unwrap();
    }
    
    #[test]
    fn test_security_comparison_analysis() {
        security_comparison_analysis().unwrap();
    }
}

// 如果直接运行此文件，执行所有示例
fn main() -> Result<()> {
    run_all_comprehensive_examples()
}