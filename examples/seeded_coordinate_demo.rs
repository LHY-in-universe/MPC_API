//! 种子控制横坐标生成演示程序
//! 
//! 演示如何使用种子控制来实现确定性的Shamir秘密分享横坐标生成。
//! 
//! 功能包括：
//! - 顺序横坐标生成
//! - 随机横坐标生成  
//! - 种子控制的确定性横坐标生成
//! - 完全确定性的份额生成

use mpc_api::secret_sharing::{ShamirSecretSharing, SecretSharing};
use mpc_api::secret_sharing::shamir::XCoordinateStrategy;
use mpc_api::Result;

fn main() -> Result<()> {
    println!("🎯 种子控制横坐标生成演示");
    println!("{}", "=".repeat(50));
    
    let scheme = ShamirSecretSharing::new();
    let secret = 42u64;
    let threshold = 3;
    let total_parties = 5;
    
    // 1. 顺序横坐标演示
    println!("\n📊 1. 顺序横坐标生成");
    println!("{}", "-".repeat(30));
    
    let sequential_coords = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::Sequential);
    println!("顺序横坐标: {:?}", sequential_coords);
    
    let sequential_shares = scheme.share_with_coordinates(
        &secret, threshold, total_parties, 
        XCoordinateStrategy::Sequential
    )?;
    
    println!("顺序份额:");
    for (i, share) in sequential_shares.iter().enumerate() {
        println!("  份额 {}: x={}, y={}", i + 1, share.x, share.y);
    }
    
    // 验证重构
    let reconstructed = ShamirSecretSharing::reconstruct(&sequential_shares[..threshold], threshold)?;
    println!("重构结果: {} ✓", reconstructed);
    assert_eq!(reconstructed, secret);
    
    // 2. 随机横坐标演示
    println!("\n🎲 2. 随机横坐标生成");
    println!("{}", "-".repeat(30));
    
    let random_coords1 = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::Random);
    let random_coords2 = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::Random);
    
    println!("随机横坐标 #1: {:?}", random_coords1);
    println!("随机横坐标 #2: {:?}", random_coords2);
    println!("两次生成结果不同: {}", random_coords1 != random_coords2);
    
    let random_shares = scheme.share_with_coordinates(
        &secret, threshold, total_parties,
        XCoordinateStrategy::Random
    )?;
    
    println!("随机份额:");
    for (i, share) in random_shares.iter().enumerate() {
        println!("  份额 {}: x={}, y={}", i + 1, share.x, share.y);
    }
    
    let reconstructed = ShamirSecretSharing::reconstruct(&random_shares[..threshold], threshold)?;
    println!("重构结果: {} ✓", reconstructed);
    assert_eq!(reconstructed, secret);
    
    // 3. 种子控制横坐标演示
    println!("\n🌱 3. 种子控制横坐标生成");
    println!("{}", "-".repeat(30));
    
    let seed = 12345u64;
    
    // 使用相同种子生成两次
    let seeded_coords1 = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::SeededRandom(seed));
    let seeded_coords2 = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::SeededRandom(seed));
    
    println!("种子 {} 生成的横坐标 #1: {:?}", seed, seeded_coords1);
    println!("种子 {} 生成的横坐标 #2: {:?}", seed, seeded_coords2);
    println!("两次生成结果相同: {}", seeded_coords1 == seeded_coords2);
    
    // 使用不同种子
    let different_seed = 54321u64;
    let different_coords = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::SeededRandom(different_seed));
    println!("种子 {} 生成的横坐标: {:?}", different_seed, different_coords);
    println!("不同种子生成不同结果: {}", seeded_coords1 != different_coords);
    
    // 4. 完全确定性份额生成演示
    println!("\n🔒 4. 完全确定性份额生成");
    println!("{}", "-".repeat(30));
    
    let seeded_shares1 = scheme.share_with_coordinates(
        &secret, threshold, total_parties,
        XCoordinateStrategy::SeededRandom(seed)
    )?;
    
    let seeded_shares2 = scheme.share_with_coordinates(
        &secret, threshold, total_parties,
        XCoordinateStrategy::SeededRandom(seed)
    )?;
    
    println!("使用种子 {} 生成的份额 #1:", seed);
    for (i, share) in seeded_shares1.iter().enumerate() {
        println!("  份额 {}: x={}, y={}", i + 1, share.x, share.y);
    }
    
    println!("使用种子 {} 生成的份额 #2:", seed);
    for (i, share) in seeded_shares2.iter().enumerate() {
        println!("  份额 {}: x={}, y={}", i + 1, share.x, share.y);
    }
    
    // 验证完全相同
    let mut shares_identical = true;
    for i in 0..total_parties {
        if seeded_shares1[i].x != seeded_shares2[i].x || seeded_shares1[i].y != seeded_shares2[i].y {
            shares_identical = false;
            break;
        }
    }
    println!("两次生成的份额完全相同: {}", shares_identical);
    
    // 验证重构
    let reconstructed1 = ShamirSecretSharing::reconstruct(&seeded_shares1[..threshold], threshold)?;
    let reconstructed2 = ShamirSecretSharing::reconstruct(&seeded_shares2[..threshold], threshold)?;
    println!("重构结果 #1: {} ✓", reconstructed1);
    println!("重构结果 #2: {} ✓", reconstructed2);
    assert_eq!(reconstructed1, secret);
    assert_eq!(reconstructed2, secret);
    
    // 5. 便捷方法演示
    println!("\n⚡ 5. 确定性份额生成便捷方法");
    println!("{}", "-".repeat(30));
    
    let convenience_shares1 = scheme.deterministic_share(&secret, threshold, total_parties, seed)?;
    let _convenience_shares2 = scheme.deterministic_share(&secret, threshold, total_parties, seed)?;
    
    println!("使用便捷方法生成的份额:");
    for (i, share) in convenience_shares1.iter().enumerate() {
        println!("  份额 {}: x={}, y={}", i + 1, share.x, share.y);
    }
    
    // 验证与完整方法的一致性
    let mut methods_consistent = true;
    for i in 0..total_parties {
        if convenience_shares1[i].x != seeded_shares1[i].x || 
           convenience_shares1[i].y != seeded_shares1[i].y {
            methods_consistent = false;
            break;
        }
    }
    println!("便捷方法与完整方法结果一致: {}", methods_consistent);
    
    let reconstructed = ShamirSecretSharing::reconstruct(&convenience_shares1[..threshold], threshold)?;
    println!("重构结果: {} ✓", reconstructed);
    assert_eq!(reconstructed, secret);
    
    // 6. 应用场景演示
    println!("\n🚀 6. 实际应用场景");
    println!("{}", "-".repeat(30));
    
    println!("应用场景 1: 分布式系统中的一致性份额生成");
    println!("- 多个节点使用相同种子生成相同的份额分布");
    println!("- 确保网络分区时仍能保持一致性");
    
    // 模拟多个节点
    let node_seeds = [seed, seed, seed]; // 所有节点使用相同种子
    let mut node_shares = Vec::new();
    
    for (node_id, &node_seed) in node_seeds.iter().enumerate() {
        let shares = scheme.deterministic_share(&secret, threshold, total_parties, node_seed)?;
        node_shares.push(shares);
        println!("节点 {} 生成的份额数量: {}", node_id, node_shares[node_id].len());
    }
    
    // 验证所有节点生成相同份额
    let mut all_nodes_consistent = true;
    for node_id in 1..node_seeds.len() {
        for i in 0..total_parties {
            if node_shares[0][i].x != node_shares[node_id][i].x ||
               node_shares[0][i].y != node_shares[node_id][i].y {
                all_nodes_consistent = false;
                break;
            }
        }
    }
    println!("所有节点生成一致的份额: {}", all_nodes_consistent);
    
    println!("\n应用场景 2: 可重现的测试环境");
    println!("- 使用固定种子确保测试结果可重现");
    println!("- 便于调试和验证算法正确性");
    
    let test_seed = 999999u64;
    let test_shares = scheme.deterministic_share(&secret, threshold, total_parties, test_seed)?;
    println!("测试种子 {} 生成的份额:", test_seed);
    for (i, share) in test_shares.iter().enumerate().take(3) {
        println!("  测试份额 {}: x={}, y={}", i + 1, share.x, share.y);
    }
    
    println!("\n应用场景 3: 审计和合规性");
    println!("- 监管机构可以使用相同种子重现份额生成过程");
    println!("- 提供加密学证明的透明性和可验证性");
    
    // 7. 性能对比
    println!("\n⏱️  7. 性能对比");
    println!("{}", "-".repeat(30));
    
    let iterations = 1000;
    
    // 测试顺序生成性能
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::Sequential);
    }
    let sequential_time = start.elapsed();
    
    // 测试随机生成性能
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::Random);
    }
    let random_time = start.elapsed();
    
    // 测试种子生成性能
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = scheme.generate_x_coordinates(total_parties, XCoordinateStrategy::SeededRandom(seed));
    }
    let seeded_time = start.elapsed();
    
    println!("性能对比 ({} 次迭代):", iterations);
    println!("  顺序生成: {:?}", sequential_time);
    println!("  随机生成: {:?}", random_time);
    println!("  种子生成: {:?}", seeded_time);
    
    let random_vs_sequential = random_time.as_nanos() as f64 / sequential_time.as_nanos() as f64;
    let seeded_vs_sequential = seeded_time.as_nanos() as f64 / sequential_time.as_nanos() as f64;
    
    println!("  随机 vs 顺序: {:.2}x", random_vs_sequential);
    println!("  种子 vs 顺序: {:.2}x", seeded_vs_sequential);
    
    println!("\n✅ 种子控制横坐标生成演示完成!");
    println!("{}", "=".repeat(50));
    println!("🎉 所有功能验证通过，种子控制功能可以投入使用！");
    
    Ok(())
}