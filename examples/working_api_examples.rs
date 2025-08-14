//! # MPC API 实际可用示例
//! 
//! 本文档展示了当前MPC API中实际可用的组件使用方法，
//! 这些示例都是可以编译和运行的。

use mpc_api::{
    secret_sharing::{ShamirSecretSharing, SecretSharing, AdditiveSecretSharing, AdditiveSecretSharingScheme, field_add, field_mul, field_sub, field_inv, FIELD_PRIME},
    beaver_triples::{TrustedPartyBeaverGenerator, BeaverTripleGenerator, secure_multiply, verify_triple_batch},
    Result
};

/// 1. 秘密分享实际使用示例
pub mod secret_sharing_examples {
    use super::*;
    
    /// Shamir 秘密分享完整示例
    pub fn complete_shamir_example() -> Result<()> {
        use mpc_api::secret_sharing::AdditiveSecretSharing;
        
        println!("=== 1. Shamir 秘密分享完整示例 ===");
        
        // 步骤1: 设置参数
        let secret = 123456u64;    // 要分享的秘密
        let threshold = 3;         // 门限值
        let total_parties = 5;     // 总参与方数
        
        println!("原始秘密: {}", secret);
        println!("参数设置: {}/{} 门限秘密分享", threshold, total_parties);
        
        // 步骤2: 生成秘密分享
        let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
        
        println!("生成的分享:");
        for (i, share) in shares.iter().enumerate() {
            println!("  参与方 {}: Share(x={}, y={})", i, share.x, share.y);
        }
        
        // 步骤3: 使用最小数量的分享重构秘密
        println!("\n使用 {} 个分享重构秘密:", threshold);
        for i in 0..=threshold {
            println!("  使用分享 0 到 {}", i);
        }
        
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
        println!("重构的秘密: {}", reconstructed);
        assert_eq!(secret, reconstructed);
        
        // 步骤4: 验证安全性 - 少于门限的分享无法重构
        if threshold > 1 {
            println!("\n安全性验证:");
            match ShamirSecretSharing::reconstruct(&shares[0..threshold-1], threshold) {
                Ok(_) => println!("  警告: 用 {} 个分享也能重构!", threshold-1),
                Err(_) => println!("  ✓ {} 个分享无法重构秘密", threshold-1),
            }
        }
        
        // 步骤5: 同态加法运算
        println!("\n同态运算演示:");
        let secret2 = 654321u64;
        let shares2 = ShamirSecretSharing::share(&secret2, threshold, total_parties)?;
        
        println!("第二个秘密: {}", secret2);
        
        // 分享相加
        let sum_shares: Vec<_> = shares.iter()
            .zip(shares2.iter())
            .map(|(s1, s2)| ShamirSecretSharing::add_shares(s1, s2))
            .collect::<Result<Vec<_>>>()?;
        
        let sum = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
        let expected_sum = field_add(secret, secret2);
        
        println!("同态加法: {} + {} = {}", secret, secret2, sum);
        println!("预期结果: {}", expected_sum);
        assert_eq!(sum, expected_sum);
        
        // 步骤6: 标量乘法
        let scalar = 7u64;
        let scalar_shares: Vec<_> = shares.iter()
            .map(|s| ShamirSecretSharing::scalar_mul(s, &scalar))
            .collect::<Result<Vec<_>>>()?;
        
        let scalar_result = ShamirSecretSharing::reconstruct(&scalar_shares[0..threshold], threshold)?;
        let expected_scalar = field_mul(secret, scalar);
        
        println!("标量乘法: {} × {} = {}", secret, scalar, scalar_result);
        println!("预期结果: {}", expected_scalar);
        assert_eq!(scalar_result, expected_scalar);
        
        println!("✓ Shamir 秘密分享演示完成\n");
        Ok(())
    }
    
    /// 加法秘密分享示例
    pub fn additive_sharing_example() -> Result<()> {
        println!("=== 2. 加法秘密分享示例 ===");
        
        let secret = 999999u64;
        let parties = 4;
        
        println!("秘密值: {}", secret);
        println!("参与方数: {}", parties);
        
        // 加法分享
        let scheme = AdditiveSecretSharingScheme::new();
        let shares = scheme.share_additive(&secret, parties)?;
        
        println!("加法分享结果:");
        let mut manual_sum = 0u64;
        for (i, share) in shares.iter().enumerate() {
            println!("  方 {}: {}", i, share.value);
            manual_sum = field_add(manual_sum, share.value);
        }
        
        println!("手动验证和: {}", manual_sum);
        
        // 重构
        let reconstructed = scheme.reconstruct_additive(&shares)?;
        println!("重构结果: {}", reconstructed);
        
        assert_eq!(secret, reconstructed);
        assert_eq!(secret, manual_sum);
        
        println!("✓ 加法秘密分享演示完成\n");
        Ok(())
    }
}

/// 2. Beaver 三元组实际使用示例
pub mod beaver_triples_examples {
    use super::*;
    
    /// 可信第三方 Beaver 三元组示例
    pub fn trusted_party_beaver_example() -> Result<()> {
        println!("=== 3. 可信第三方 Beaver 三元组示例 ===");
        
        let party_count = 3;
        let threshold = 2;
        let party_id = 0;
        
        // 创建生成器
        let mut generator = TrustedPartyBeaverGenerator::new(
            party_count, 
            threshold, 
            party_id, 
            None
        )?;
        
        println!("创建可信第三方生成器成功");
        
        // 生成单个三元组
        let beaver_triple = generator.generate_single()?;
        
        println!("生成 Beaver 三元组成功");
        println!("三元组包含 {} 个参与方的分享", beaver_triple.shares.len());
        
        // 显示原始值 (仅用于验证)
        if let Some((a, b, c)) = beaver_triple.original_values {
            println!("原始值: a={}, b={}, c={}", a, b, c);
            println!("验证: {} × {} = {} ✓", a, b, field_mul(a, b));
            assert_eq!(c, field_mul(a, b));
        }
        
        // 验证三元组
        let is_valid = generator.verify_triple(&beaver_triple)?;
        println!("三元组验证: {}", if is_valid { "有效" } else { "无效" });
        assert!(is_valid);
        
        // 展示安全乘法
        println!("\n安全乘法演示:");
        let x = 25u64;
        let y = 16u64;
        let expected_product = field_mul(x, y);
        
        println!("计算 {} × {} = {} (期望)", x, y, expected_product);
        
        // 创建输入的秘密分享
        let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
        let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
        
        // 使用 Beaver 三元组进行安全乘法
        let product_shares = secure_multiply(&x_shares, &y_shares, &beaver_triple, threshold)?;
        
        // 重构结果
        let result = ShamirSecretSharing::reconstruct(&product_shares[0..threshold], threshold)?;
        
        println!("安全乘法结果: {}", result);
        assert_eq!(result, expected_product);
        
        println!("✓ 可信第三方 Beaver 三元组演示完成\n");
        Ok(())
    }
    
    /// 批量 Beaver 三元组示例
    pub fn batch_beaver_example() -> Result<()> {
        println!("=== 4. 批量 Beaver 三元组示例 ===");
        
        let party_count = 3;
        let threshold = 2;
        let party_id = 0;
        let batch_size = 5;
        
        let mut generator = TrustedPartyBeaverGenerator::new(
            party_count, 
            threshold, 
            party_id, 
            None
        )?;
        
        println!("批量生成 {} 个 Beaver 三元组...", batch_size);
        
        let triples = generator.generate_batch(batch_size)?;
        assert_eq!(triples.len(), batch_size);
        
        // 验证每个三元组
        for (i, triple) in triples.iter().enumerate() {
            let is_valid = generator.verify_triple(triple)?;
            println!("三元组 {}: {}", i, if is_valid { "✓" } else { "✗" });
            assert!(is_valid);
            
            if let Some((a, b, c)) = triple.original_values {
                assert_eq!(c, field_mul(a, b));
            }
        }
        
        // 批量验证
        let batch_valid = verify_triple_batch(&triples, threshold)?;
        println!("批量验证结果: {}", if batch_valid { "全部有效" } else { "存在问题" });
        assert!(batch_valid);
        
        println!("✓ 批量 Beaver 三元组演示完成\n");
        Ok(())
    }
}

/// 3. 实际应用场景示例
pub mod application_examples {
    use super::*;
    
    /// 多方联合计算示例
    pub fn multi_party_computation_example() -> Result<()> {
        println!("=== 5. 多方联合计算示例 ===");
        
        // 场景：三家公司想要计算平均工资，但不想泄露各自的具体工资数据
        let companies = vec!["公司A", "公司B", "公司C"];
        let salaries = vec![50000u64, 60000u64, 55000u64]; // 各公司平均工资
        
        println!("场景: 计算三家公司的平均工资");
        for (company, &salary) in companies.iter().zip(salaries.iter()) {
            println!("  {} 工资: {} (保密)", company, salary);
        }
        
        let party_count = 3;
        let threshold = 2;
        
        // 步骤1: 各公司对工资进行秘密分享
        let mut all_shares = Vec::new();
        
        for (i, &salary) in salaries.iter().enumerate() {
            let shares = ShamirSecretSharing::share(&salary, threshold, party_count)?;
            all_shares.push(shares);
            println!("{} 完成工资数据的秘密分享", companies[i]);
        }
        
        // 步骤2: 计算总和（同态加法）
        let mut sum_shares = all_shares[0].clone();
        
        for shares in &all_shares[1..] {
            for (i, share) in shares.iter().enumerate() {
                sum_shares[i] = ShamirSecretSharing::add_shares(&sum_shares[i], share)?;
            }
        }
        
        // 步骤3: 重构总和
        let total_salary = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
        
        // 步骤4: 计算平均值
        let company_count = salaries.len() as u64;
        let average_salary = total_salary / company_count; // 简化的除法
        
        println!("\n联合计算结果:");
        println!("总工资: {}", total_salary);
        println!("平均工资: {}", average_salary);
        
        // 验证结果
        let expected_total: u64 = salaries.iter().sum();
        let expected_average = expected_total / company_count;
        
        println!("验证 - 期望总和: {}", expected_total);
        println!("验证 - 期望平均: {}", expected_average);
        
        assert_eq!(total_salary, expected_total);
        assert_eq!(average_salary, expected_average);
        
        println!("✓ 多方联合计算成功，各公司数据保持隐私");
        
        println!("✓ 多方联合计算示例完成\n");
        Ok(())
    }
    
    /// 隐私保护拍卖示例
    pub fn private_auction_example() -> Result<()> {
        println!("=== 6. 隐私保护拍卖示例 ===");
        
        // 场景：三个投标者参与拍卖，想要找出最高出价但不泄露具体金额
        let bidders = vec!["投标者A", "投标者B", "投标者C"];
        let bids = vec![1000u64, 1500u64, 1200u64];
        
        println!("隐私保护拍卖场景:");
        for (bidder, &bid) in bidders.iter().zip(bids.iter()) {
            println!("  {} 出价: {} (保密)", bidder, bid);
        }
        
        let party_count = 3;
        let threshold = 2;
        
        // 步骤1: 对出价进行秘密分享
        let mut bid_shares = Vec::new();
        
        for (i, &bid) in bids.iter().enumerate() {
            let shares = ShamirSecretSharing::share(&bid, threshold, party_count)?;
            bid_shares.push(shares);
            println!("{} 提交出价分享", bidders[i]);
        }
        
        // 步骤2: 使用 Beaver 三元组进行比较（简化版）
        // 在实际应用中，这里会使用更复杂的比较协议
        
        // 为了简化，我们重构所有出价进行比较
        println!("\n拍卖结果计算中...");
        
        let mut max_bid = 0u64;
        let mut winner_index = 0;
        
        for (i, shares) in bid_shares.iter().enumerate() {
            let bid = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
            if bid > max_bid {
                max_bid = bid;
                winner_index = i;
            }
        }
        
        println!("拍卖结果:");
        println!("获胜者: {}", bidders[winner_index]);
        println!("最高出价: {}", max_bid);
        
        // 验证
        let expected_max = *bids.iter().max().unwrap();
        let expected_winner = bids.iter().position(|&x| x == expected_max).unwrap();
        
        assert_eq!(max_bid, expected_max);
        assert_eq!(winner_index, expected_winner);
        
        println!("✓ 隐私保护拍卖示例完成\n");
        Ok(())
    }
}

/// 4. 有限域运算示例
pub mod field_operations_examples {
    use super::*;
    
    /// 有限域基本运算演示
    pub fn basic_field_operations() -> Result<()> {
        println!("=== 7. 有限域运算示例 ===");
        
        println!("有限域模数: {}", FIELD_PRIME);
        println!("模数二进制位数: {} 位", 64 - FIELD_PRIME.leading_zeros());
        
        // 基本运算
        let a = 12345678901234567u64;
        let b = 98765432109876543u64;
        
        println!("\n基本运算:");
        println!("a = {}", a);
        println!("b = {}", b);
        
        let sum = field_add(a, b);
        let diff = field_sub(a, b);
        let product = field_mul(a, b);
        
        println!("a + b = {}", sum);
        println!("a - b = {}", diff);
        println!("a × b = {}", product);
        
        // 逆元运算
        if let Some(a_inv) = field_inv(a) {
            let should_be_one = field_mul(a, a_inv);
            println!("a^(-1) = {}", a_inv);
            println!("a × a^(-1) = {} (应该是1)", should_be_one);
            
            // 由于有限域运算，结果应该是1
            assert_eq!(should_be_one, 1);
        }
        
        // 运算属性验证
        println!("\n运算属性验证:");
        
        // 加法交换律
        let ab = field_add(a, b);
        let ba = field_add(b, a);
        println!("加法交换律: a+b={}, b+a={} ({})", ab, ba, ab == ba);
        assert_eq!(ab, ba);
        
        // 乘法交换律
        let ab_mul = field_mul(a, b);
        let ba_mul = field_mul(b, a);
        println!("乘法交换律: a×b={}, b×a={} ({})", ab_mul, ba_mul, ab_mul == ba_mul);
        assert_eq!(ab_mul, ba_mul);
        
        // 加法单位元
        let a_plus_zero = field_add(a, 0);
        println!("加法单位元: a+0={}, a={} ({})", a_plus_zero, a, a_plus_zero == a);
        assert_eq!(a_plus_zero, a);
        
        // 乘法单位元
        let a_times_one = field_mul(a, 1);
        println!("乘法单位元: a×1={}, a={} ({})", a_times_one, a, a_times_one == a);
        assert_eq!(a_times_one, a);
        
        println!("✓ 有限域运算验证完成\n");
        Ok(())
    }
    
    /// 大数运算示例
    pub fn large_number_operations() -> Result<()> {
        println!("=== 8. 大数运算示例 ===");
        
        // 接近模数的大数
        let large_a = FIELD_PRIME - 1;
        let large_b = FIELD_PRIME - 2;
        
        println!("大数 a = {} (FIELD_PRIME - 1)", large_a);
        println!("大数 b = {} (FIELD_PRIME - 2)", large_b);
        
        // 大数加法（会发生模运算）
        let sum = field_add(large_a, large_b);
        println!("a + b = {} (模运算结果)", sum);
        
        // 预期结果：(FIELD_PRIME-1) + (FIELD_PRIME-2) = 2*FIELD_PRIME - 3 ≡ FIELD_PRIME - 3 (mod FIELD_PRIME)
        let expected_sum = FIELD_PRIME - 3;
        println!("预期结果: {}", expected_sum);
        assert_eq!(sum, expected_sum);
        
        // 大数乘法
        let product = field_mul(large_a, large_b);
        println!("a × b = {} (模运算结果)", product);
        
        // 溢出处理演示
        println!("\n溢出处理演示:");
        let max_u64 = u64::MAX;
        let safe_in_field = max_u64 % FIELD_PRIME;
        
        println!("u64::MAX = {}", max_u64);
        println!("u64::MAX mod FIELD_PRIME = {}", safe_in_field);
        
        let safe_product = field_mul(safe_in_field, safe_in_field);
        println!("安全乘法结果: {}", safe_product);
        
        println!("✓ 大数运算示例完成\n");
        Ok(())
    }
}

/// 运行所有工作示例
pub fn run_all_working_examples() -> Result<()> {
    println!("🌟 === MPC API 实际可用示例集合 ===\n");
    
    secret_sharing_examples::complete_shamir_example()?;
    secret_sharing_examples::additive_sharing_example()?;
    
    beaver_triples_examples::trusted_party_beaver_example()?;
    beaver_triples_examples::batch_beaver_example()?;
    
    application_examples::multi_party_computation_example()?;
    application_examples::private_auction_example()?;
    
    field_operations_examples::basic_field_operations()?;
    field_operations_examples::large_number_operations()?;
    
    println!("🎉 === 所有实际可用示例运行完成 ===");
    println!("📝 示例总结:");
    println!("  ✓ Shamir 秘密分享 - 完整的分享和重构流程");
    println!("  ✓ 加法秘密分享 - 简单高效的分享方案");
    println!("  ✓ Beaver 三元组 - 可信第三方生成和安全乘法");
    println!("  ✓ 多方计算应用 - 隐私保护的联合计算");
    println!("  ✓ 有限域运算 - 底层数学运算基础");
    println!("\n这些示例展示了 MPC API 的核心功能和实际应用场景。");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_complete_shamir_example() {
        secret_sharing_examples::complete_shamir_example().unwrap();
    }
    
    #[test]
    fn test_additive_sharing_example() {
        secret_sharing_examples::additive_sharing_example().unwrap();
    }
    
    #[test]
    fn test_trusted_party_beaver_example() {
        beaver_triples_examples::trusted_party_beaver_example().unwrap();
    }
    
    #[test]
    fn test_batch_beaver_example() {
        beaver_triples_examples::batch_beaver_example().unwrap();
    }
    
    #[test]
    fn test_multi_party_computation_example() {
        application_examples::multi_party_computation_example().unwrap();
    }
    
    #[test]
    fn test_private_auction_example() {
        application_examples::private_auction_example().unwrap();
    }
    
    #[test]
    fn test_basic_field_operations() {
        field_operations_examples::basic_field_operations().unwrap();
    }
    
    #[test]
    fn test_large_number_operations() {
        field_operations_examples::large_number_operations().unwrap();
    }
}

// 如果直接运行此文件，执行所有示例
fn main() -> Result<()> {
    run_all_working_examples()
}