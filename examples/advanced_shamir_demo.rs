//! 高级Shamir秘密分享演示程序
//! 
//! 演示新的高性能多项式更新和优化功能，包括：
//! - 霍纳方法多项式计算
//! - 批量操作优化
//! - 增量式更新
//! - 预计算优化
//! - 动态阈值调整
//! - 压缩存储

use mpc_api::secret_sharing::{ShamirSecretSharing, SecretSharing, Share};
use mpc_api::Result;
use std::time::Instant;

fn main() -> Result<()> {
    println!("🚀 高级Shamir秘密分享演示");
    println!("==========================================");

    let scheme = ShamirSecretSharing::new();

    // 1. 演示霍纳方法多项式计算
    demo_horner_method(&scheme);

    // 2. 演示批量操作
    demo_batch_operations(&scheme)?;

    // 3. 演示增量更新
    demo_incremental_updates(&scheme);

    // 4. 演示预计算优化
    demo_precomputation_optimization(&scheme)?;

    // 5. 演示动态阈值调整
    demo_threshold_adjustment(&scheme)?;

    // 6. 演示压缩存储
    demo_compression(&scheme);

    // 7. 性能对比测试
    performance_comparison(&scheme)?;

    Ok(())
}

/// 演示霍纳方法的多项式计算优化
fn demo_horner_method(scheme: &ShamirSecretSharing) {
    println!("\n📊 1. 霍纳方法多项式计算");
    println!("------------------------------------------");

    // 构造多项式 f(x) = 42 + 17x + 8x² + 3x³
    let coefficients = vec![42, 17, 8, 3];
    println!("多项式: f(x) = 42 + 17x + 8x² + 3x³");

    // 计算几个点的值
    for x in [0, 1, 2, 5] {
        let result = scheme.evaluate_polynomial(&coefficients, x);
        println!("f({}) = {}", x, result);
    }

    // 分别计算每个点的值
    let x_values = vec![0, 1, 2, 3, 4, 5];
    let mut results = Vec::new();
    for &x in &x_values {
        results.push(scheme.evaluate_polynomial(&coefficients, x));
    }
    println!("计算结果: {:?}", results);
}

/// 演示多个秘密的分享
#[allow(unused_variables)]
fn demo_batch_operations(scheme: &ShamirSecretSharing) -> Result<()> {
    println!("\n🔄 2. 多秘密分享演示");
    println!("------------------------------------------");

    // 准备多个秘密进行分享
    let secrets = vec![100, 200, 300, 400, 500];
    println!("要分享的秘密: {:?}", secrets);

    let start = Instant::now();
    // 分别生成每个秘密的份额
    let mut all_shares = Vec::new();
    for &secret in &secrets {
        let shares = ShamirSecretSharing::share(&secret, 3, 5)?;
        all_shares.push(shares);
    }
    let multi_time = start.elapsed();

    println!("生成{}个秘密的份额用时: {:?}", secrets.len(), multi_time);
    
    // 验证每个秘密都能正确重构
    for (i, shares) in all_shares.iter().enumerate() {
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[..3], 3)?;
        println!("秘密 {} 重构结果: {} ✓", i + 1, reconstructed);
        assert_eq!(reconstructed, secrets[i]);
    }

    Ok(())
}

/// 演示增量式更新
fn demo_incremental_updates(scheme: &ShamirSecretSharing) {
    println!("\n⚡ 3. 增量式多项式更新");
    println!("------------------------------------------");

    // 原始多项式系数
    let original_poly = vec![50, 10]; // f(x) = 50 + 10x
    println!("原始多项式: f(x) = 50 + 10x");

    // 生成初始份额
    let original_shares = vec![
        Share::new(1, scheme.evaluate_polynomial(&original_poly, 1)),
        Share::new(2, scheme.evaluate_polynomial(&original_poly, 2)),
        Share::new(3, scheme.evaluate_polynomial(&original_poly, 3)),
    ];
    println!("原始份额: {:?}", original_shares);

    // 增量更新：添加 5x² 项
    let delta_coeffs = vec![0, 0, 5]; // Δf(x) = 5x²
    let updated_shares = scheme.incremental_share_update(&original_shares, &delta_coeffs);
    println!("增量更新后的份额: {:?}", updated_shares);

    // 验证更新的多项式：f(x) = 50 + 10x + 5x²
    let updated_poly = scheme.merge_polynomials(&original_poly, &delta_coeffs);
    println!("更新后的多项式系数: {:?}", updated_poly);

    for share in &updated_shares {
        let expected = scheme.evaluate_polynomial(&updated_poly, share.x);
        println!("Share x={}: 期望值={}, 实际值={} ✓", share.x, expected, share.y);
        assert_eq!(expected, share.y);
    }
}

/// 演示预计算优化
fn demo_precomputation_optimization(scheme: &ShamirSecretSharing) -> Result<()> {
    println!("\n⚡ 4. 预计算优化");
    println!("------------------------------------------");

    // 创建测试份额
    let secret = 12345u64;
    let shares = ShamirSecretSharing::share(&secret, 3, 5)?;
    let reconstruction_shares = &shares[..3];

    println!("原始秘密: {}", secret);
    println!("用于重构的份额: {:?}", reconstruction_shares);

    // 传统重构方法
    let start = Instant::now();
    let reconstructed1 = scheme.lagrange_interpolation(reconstruction_shares)?;
    let traditional_time = start.elapsed();

    // 预计算优化方法
    let x_coords: Vec<u64> = reconstruction_shares.iter().map(|s| s.x).collect();
    let start = Instant::now();
    let lagrange_coeffs = scheme.precompute_lagrange_coefficients(&x_coords)?;
    let precompute_time = start.elapsed();

    let start = Instant::now();
    let reconstructed2 = scheme.fast_reconstruct_with_coeffs(reconstruction_shares, &lagrange_coeffs);
    let fast_time = start.elapsed();

    println!("传统重构时间: {:?}", traditional_time);
    println!("预计算时间: {:?}", precompute_time);
    println!("快速重构时间: {:?}", fast_time);
    println!("重构结果1: {} ✓", reconstructed1);
    println!("重构结果2: {} ✓", reconstructed2);

    assert_eq!(reconstructed1, reconstructed2);
    assert_eq!(reconstructed1, secret);

    Ok(())
}

/// 演示动态阈值调整
fn demo_threshold_adjustment(scheme: &ShamirSecretSharing) -> Result<()> {
    println!("\n🔧 5. 动态阈值调整");
    println!("------------------------------------------");

    let secret = 98765u64;
    println!("原始秘密: {}", secret);

    // 创建 (2,3) 方案
    let original_shares = ShamirSecretSharing::share(&secret, 2, 3)?;
    println!("原始方案: (2,3) - 需要2个份额重构，共3个参与方");
    println!("原始份额数量: {}", original_shares.len());

    // 调整为 (3,5) 方案
    let adjusted_shares = scheme.adjust_threshold(&original_shares, 2, 3, 5)?;
    println!("调整后方案: (3,5) - 需要3个份额重构，共5个参与方");
    println!("调整后份额数量: {}", adjusted_shares.len());

    // 验证调整后的份额能正确重构
    let reconstructed = ShamirSecretSharing::reconstruct(&adjusted_shares[..3], 3)?;
    println!("重构验证: {} ✓", reconstructed);
    assert_eq!(reconstructed, secret);

    // 再次调整为 (4,7) 方案
    let final_shares = scheme.adjust_threshold(&adjusted_shares, 3, 4, 7)?;
    println!("最终方案: (4,7) - 需要4个份额重构，共7个参与方");
    println!("最终份额数量: {}", final_shares.len());

    let final_reconstructed = ShamirSecretSharing::reconstruct(&final_shares[..4], 4)?;
    println!("最终重构验证: {} ✓", final_reconstructed);
    assert_eq!(final_reconstructed, secret);

    Ok(())
}

/// 演示压缩存储功能
fn demo_compression(scheme: &ShamirSecretSharing) {
    println!("\n🗜️  6. 份额压缩存储");
    println!("------------------------------------------");

    // 创建测试份额
    let shares = vec![
        Share::new(1, 123456789),
        Share::new(2, 234567890),
        Share::new(3, 345678901),
        Share::new(4, 456789012),
        Share::new(5, 567890123),
    ];

    println!("原始份额: {:?}", shares);
    println!("原始份额数量: {}", shares.len());

    // 压缩份额
    let compressed = scheme.compress_shares(&shares);
    println!("压缩后大小: {} 字节", compressed.len());
    println!("平均每份额: {} 字节", compressed.len() / shares.len());

    // 解压缩
    let decompressed = scheme.decompress_shares(&compressed).unwrap();
    println!("解压缩后份额: {:?}", decompressed);

    // 验证完整性
    assert_eq!(shares, decompressed);
    println!("压缩/解压缩完整性验证: ✓");

    // 计算压缩率
    let original_size = shares.len() * std::mem::size_of::<Share>();
    let compression_ratio = compressed.len() as f64 / original_size as f64;
    println!("理论原始大小: {} 字节", original_size);
    println!("压缩率: {:.2}%", compression_ratio * 100.0);
}

/// 性能对比测试
fn performance_comparison(scheme: &ShamirSecretSharing) -> Result<()> {
    println!("\n📈 7. 性能对比测试");
    println!("------------------------------------------");

    let iterations = 1000;
    println!("测试迭代次数: {}", iterations);

    // 准备测试数据
    let secret = 555555u64;
    let shares = ShamirSecretSharing::share(&secret, 3, 5)?;
    let test_shares = &shares[..3];
    let x_coords: Vec<u64> = test_shares.iter().map(|s| s.x).collect();

    // 测试传统拉格朗日插值
    let start = Instant::now();
    for _ in 0..iterations {
        let _result = scheme.lagrange_interpolation(test_shares).unwrap();
    }
    let traditional_total = start.elapsed();

    // 测试预计算优化
    let lagrange_coeffs = scheme.precompute_lagrange_coefficients(&x_coords)?;
    let start = Instant::now();
    for _ in 0..iterations {
        let _result = scheme.fast_reconstruct_with_coeffs(test_shares, &lagrange_coeffs);
    }
    let optimized_total = start.elapsed();

    println!("传统方法总时间: {:?}", traditional_total);
    println!("优化方法总时间: {:?}", optimized_total);
    
    let speedup = traditional_total.as_nanos() as f64 / optimized_total.as_nanos() as f64;
    println!("性能提升倍数: {:.2}x", speedup);

    // 测试批量操作性能
    let secrets: Vec<u64> = (1..=100).collect();
    
    // 单独分享
    let start = Instant::now();
    let mut individual_shares = Vec::new();
    for &secret in &secrets {
        let shares = ShamirSecretSharing::share(&secret, 3, 5)?;
        individual_shares.push(shares);
    }
    let individual_time = start.elapsed();

    // 优化分享（使用确定性坐标）
    let start = Instant::now();
    let mut optimized_shares = Vec::new();
    for &secret in &secrets {
        let shares = scheme.deterministic_share(&secret, 3, 5, 12345)?;
        optimized_shares.push(shares);
    }
    let optimized_time = start.elapsed();

    println!("单独分享100个秘密时间: {:?}", individual_time);
    println!("优化分享100个秘密时间: {:?}", optimized_time);
    
    let speedup_ratio = individual_time.as_nanos() as f64 / optimized_time.as_nanos() as f64;
    println!("优化操作性能对比: {:.2}x", speedup_ratio);

    Ok(())
}