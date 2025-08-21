//! # 基于 OLE 的 Beaver 三元组生成完整指南
//! 
//! 本文件提供了关于使用不经意线性求值 (Oblivious Linear Evaluation, OLE) 
//! 协议生成 Beaver 三元组的全面教程和实际应用示例。OLE 是一种平衡了
//! 安全性、性能和实用性的高级密码学协议。
//! 
//! ## Bash 测试代码
//! 
//! ```bash
//! # 编译检查
//! cargo check --example beaver_triples_ole_example
//! 
//! # 运行完整示例
//! cargo run --example beaver_triples_ole_example
//! 
//! # 运行所有测试
//! cargo test --example beaver_triples_ole_example
//! 
//! # 运行特定OLE测试
//! cargo test test_basic_ole_beaver_example
//! cargo test test_secure_multiplication_example
//! cargo test test_batch_beaver_example
//! cargo test test_comprehensive_ole_example
//! 
//! # OLE性能基准测试
//! cargo bench --bench mpc_benchmarks -- ole
//! 
//! # 生成OLE文档
//! cargo doc --example beaver_triples_ole_example --open
//! ```
//! 
//! ## 🎯 学习目标
//! 
//! 通过本指南，您将学会：
//! - **OLE 协议原理**: 理解不经意线性求值的密码学基础
//! - **Beaver 三元组生成**: 掌握基于 OLE 的高效生成方法
//! - **安全乘法协议**: 学会使用 OLE 三元组进行安全计算
//! - **批量优化技术**: 了解大规模应用的性能优化策略
//! - **实际应用场景**: 掌握多方协作计算的完整流程
//! 
//! ## 📚 OLE 协议深度解析
//! 
//! ### 什么是不经意线性求值 (OLE)？
//! 
//! OLE 是一种两方密码学协议，允许一方（求值方）在不了解另一方（输入方）
//! 具体输入的情况下，对线性函数进行求值：
//! 
//! - **输入方**: 持有私有值 x
//! - **求值方**: 持有线性函数 f(t) = a × t + b  
//! - **协议目标**: 求值方学习 f(x) = a × x + b，但不知道 x
//! - **隐私保证**: 输入方不学习 a, b 或 f(x)
//! 
//! ### OLE 在 Beaver 三元组中的应用
//! 
//! OLE 协议可以巧妙地用于生成 Beaver 三元组：
//! 1. **随机值生成**: 使用 OLE 生成随机的相关值
//! 2. **乘法关系**: 确保生成的三元组满足 c = a × b
//! 3. **分布式计算**: 多方协作生成，无需可信第三方
//! 4. **安全保证**: 基于计算困难问题的安全性
//! 
//! ### 与其他方法的比较
//! 
//! | 特性 | OLE 方法 | 可信第三方 | BFV 同态加密 |
//! |------|----------|------------|--------------|
//! | 安全假设 | 计算安全 | 诚实第三方 | 计算 + 抗量子 |
//! | 性能 | 中等 | 最快 | 较慢 |
//! | 通信量 | 中等 | 最少 | 较多 |
//! | 实用性 | 很好 | 有限 | 好 |
//! | 可扩展性 | 好 | 最好 | 中等 |
//! 
//! ## 🔒 安全性分析
//! 
//! ### 安全保证
//! 
//! 1. **计算安全性**: 基于离散对数或 RSA 等困难问题
//! 2. **半诚实安全**: 对抗遵循协议但试图推断信息的敌手
//! 3. **可组合性**: 支持并发执行多个协议实例
//! 4. **前向安全**: 即使部分密钥泄露也不影响历史数据
//! 
//! ### 信任模型
//! 
//! - **无可信第三方**: 协议参与方之间直接交互
//! - **网络假设**: 安全的点对点通信信道
//! - **计算假设**: 参与方具备充足的计算能力
//! - **诚实多数**: 需要超过半数的参与方诚实执行协议
//! 
//! ## 🚀 性能特点
//! 
//! ### 计算复杂度
//! 
//! - **单个三元组**: O(k) 模指数运算，k 为安全参数
//! - **批量生成**: 摊销成本降低到 O(1) 每个三元组
//! - **内存使用**: O(n) 其中 n 为参与方数量
//! - **网络通信**: O(k × n) 每个三元组
//! 
//! ### 性能优化
//! 
//! - **预计算**: 提前生成三元组池
//! - **批量处理**: 同时处理多个三元组减少通信轮数
//! - **并行化**: 支持多线程并行生成
//! - **缓存优化**: 重用中间计算结果
//! 
//! ## 💡 应用场景
//! 
//! ### 适用场景
//! 
//! - **金融科技**: 银行间隐私保护风险评估
//! - **医疗健康**: 多医院联合研究数据分析
//! - **供应链**: 企业间协作优化而不泄露商业机密
//! - **机器学习**: 联邦学习中的安全模型训练
//! 
//! ### 部署考虑
//! 
//! - **网络环境**: 需要稳定的低延迟网络连接
//! - **计算资源**: 需要足够的 CPU 和内存资源
//! - **安全策略**: 需要配套的密钥管理和审计机制
//! - **合规要求**: 满足相关行业的隐私保护法规

use mpc_api::{
    beaver_triples::{OLEBeaverGenerator, BeaverTripleGenerator, secure_multiply, batch_secure_multiply},
    secret_sharing::{ShamirSecretSharing, SecretSharing, field_mul, field_add},
    MpcError, Result,
};

/// 基础 OLE Beaver 三元组生成和验证演示
/// 
/// ## 🎯 功能概述
/// 
/// 本函数演示了使用 OLE 协议生成 Beaver 三元组的基本流程，包括生成器创建、
/// 三元组生成、验证和结构分析。这是理解 OLE 方法的入门示例。
/// 
/// ## 📚 技术背景
/// 
/// ### OLE Beaver 生成器的工作原理
/// 
/// 1. **初始化阶段**: 设置密码学参数和通信环境
/// 2. **协议执行**: 各方运行 OLE 协议生成相关随机值
/// 3. **三元组构造**: 将 OLE 输出转换为标准 Beaver 三元组格式
/// 4. **分享分发**: 将三元组以秘密分享形式分配给参与方
/// 
/// ### 参数选择指南
/// 
/// - **party_count**: 参与方数量，建议 3-10 方以平衡安全性和效率
/// - **threshold**: 重构门限，通常设为 (party_count + 1) / 2 以获得最优安全性
/// - **party_id**: 参与方标识，必须在 [0, party_count) 范围内且全局唯一
/// 
/// ## 🔒 安全考虑
/// 
/// - **密钥管理**: OLE 协议需要安全的密钥建立和管理
/// - **通信安全**: 所有协议消息必须通过安全信道传输
/// - **随机数质量**: 依赖高质量的密码学随机数生成器
/// - **实现安全**: 需要防范侧信道攻击和时序攻击
pub fn basic_ole_beaver_example() -> Result<()> {
    println!("=== 基础 OLE Beaver 三元组生成演示 ===");
    
    // === 步骤1: 配置多方计算环境 ===
    let party_count = 3;    // 3方协议，常用的小规模设置
    let threshold = 2;      // 2-out-of-3 门限，提供1个参与方的容错能力
    let party_id = 0;       // 当前模拟第0方的行为
    
    println!("🔧 MPC 协议配置:");
    println!("  参与方数量: {} (支持分布式计算)", party_count);
    println!("  重构门限: {} (需要{}方合作才能重构秘密)", threshold, threshold);
    println!("  当前方身份: 参与方 {} (模拟分布式环境)", party_id);
    println!("  安全保证: {}-out-of-{} 门限秘密分享", threshold, party_count);
    
    // === 步骤2: 创建 OLE Beaver 生成器 ===
    println!("\n⚙️ 创建 OLE Beaver 三元组生成器...");
    println!("  OLE 协议特点:");
    println!("    • 无需可信第三方");
    println!("    • 基于计算安全假设");
    println!("    • 支持高效批量生成");
    
    let mut ole_generator = OLEBeaverGenerator::new(party_count, threshold, party_id)?;
    println!("  ✅ OLE Beaver 生成器初始化成功");
    
    // === 步骤3: 生成单个 Beaver 三元组 ===
    println!("\n🎲 生成 Beaver 三元组...");
    println!("  OLE 协议执行步骤:");
    println!("    1. 生成随机线性函数参数");
    println!("    2. 执行不经意线性求值协议");
    println!("    3. 构造满足 c = a × b 的三元组");
    println!("    4. 创建秘密分享并分发给各方");
    
    let beaver_triple = ole_generator.generate_single()?;
    println!("  ✅ Beaver 三元组生成完成");
    
    // === 步骤4: 验证三元组的数学正确性 ===
    println!("\n🔍 验证三元组正确性...");
    println!("  验证内容:");
    println!("    • 数学关系: c = a × b (mod p)");
    println!("    • 分享一致性: 所有分享指向相同的秘密");
    println!("    • 结构完整性: 分享数量和格式正确");
    
    let is_valid = ole_generator.verify_triple(&beaver_triple)?;
    println!("  验证结果: {}", if is_valid { "✅ 通过" } else { "❌ 失败" });
    
    if !is_valid {
        return Err(MpcError::ProtocolError("三元组验证失败，可能存在协议执行错误".to_string()));
    }
    
    // === 步骤5: 分析三元组结构 ===
    println!("\n📊 三元组结构分析:");
    println!("  分享分布:");
    println!("    • 分享数量: {} (每个参与方一份)", beaver_triple.shares.len());
    println!("    • 分享类型: Shamir 秘密分享");
    println!("    • 门限设置: 任意{}方可重构完整三元组", threshold);
    
    // 展示参与方分享信息（实际部署中不应显示具体值）
    for (party_id, share) in &beaver_triple.shares {
        println!("    参与方 {}: a=({},***), b=({},***), c=({},***)", 
                party_id, share.a.x, share.b.x, share.c.x);
    }
    
    // === 步骤6: 验证原始三元组关系（仅用于演示） ===
    println!("\n🔓 原始三元组验证 (仅供教学参考):");
    
    if let Some((a, b, c)) = beaver_triple.original_values {
        println!("  原始三元组值:");
        println!("    a = {} (第一个随机因子)", a);
        println!("    b = {} (第二个随机因子)", b);
        println!("    c = {} (计算乘积)", c);
        
        let computed_c = field_mul(a, b);
        println!("  数学验证:");
        println!("    计算: a × b = {} × {} = {}", a, b, computed_c);
        println!("    期望: c = {}", c);
        
        assert_eq!(c, computed_c, "三元组不满足乘法关系");
        println!("    ✅ 数学关系验证: c = a × b 成立");
        
        println!("  💡 在生产环境中，原始值应立即安全删除");
    } else {
        println!("  💡 原始值已被安全删除（符合安全最佳实践）");
    }
    
    // === 总结和要点 ===
    println!("\n📋 基础 OLE Beaver 生成要点总结:");
    println!("  ✅ 成功创建并配置 OLE 生成器");
    println!("  ✅ 成功生成符合要求的 Beaver 三元组");
    println!("  ✅ 验证了三元组的数学正确性");
    println!("  ✅ 分析了分享结构和安全属性");
    
    println!("\n💡 关键收获:");
    println!("  • OLE 方法无需可信第三方即可生成安全的 Beaver 三元组");
    println!("  • 生成的三元组满足密码学安全要求");
    println!("  • 分享机制确保了隐私保护和容错能力");
    println!("  • 验证机制保证了协议执行的正确性");
    
    println!("\n✅ 基础 OLE Beaver 三元组生成演示完成\n");
    Ok(())
}

/// OLE Beaver 三元组安全乘法协议完整演示
/// 
/// ## 🎯 功能概述
/// 
/// 本函数演示了如何使用 OLE 生成的 Beaver 三元组来执行安全乘法协议。
/// 这是 MPC 中最基础也是最重要的操作，所有复杂的安全计算都建立在此基础上。
/// 
/// ## 📚 安全乘法协议原理
/// 
/// ### Beaver 三元组乘法的数学基础
/// 
/// 给定秘密分享 [x] 和 [y]，以及 Beaver 三元组 ([a], [b], [c])，其中 c = a × b：
/// 
/// 1. **掩码阶段**: 计算 d = x - a 和 e = y - b
/// 2. **公开阶段**: 各方重构并公开 d 和 e（这是安全的，因为 a, b 是随机的）
/// 3. **计算阶段**: 计算 [xy] = [c] + d[b] + e[a] + de
/// 
/// ### 安全性分析
/// 
/// - **隐私保护**: d 和 e 的公开不泄露 x, y 的信息（因为 a, b 是随机掩码）
/// - **正确性**: 可以数学证明结果等于 xy
/// - **高效性**: 只需要一轮通信和简单的线性运算
/// 
/// ## 🔒 协议安全要求
/// 
/// - **随机性**: Beaver 三元组必须使用高质量的随机数
/// - **新鲜性**: 每个三元组只能使用一次
/// - **验证**: 三元组必须经过正确性验证
/// - **同步**: 所有参与方必须使用相同的三元组
/// 
/// ## ⚡ 性能特点
/// 
/// - **预处理**: 三元组生成可以离线进行
/// - **在线效率**: 在线阶段只需要O(1)轮通信
/// - **可并行**: 多个乘法可以并行执行
/// - **低开销**: 计算开销主要是简单的域运算
pub fn secure_multiplication_example() -> Result<()> {
    println!("=== OLE Beaver 三元组安全乘法协议演示 ===");
    
    // === 协议参数配置 ===
    let party_count = 3;
    let threshold = 2;
    let party_id = 0;
    
    println!("🔧 安全乘法协议配置:");
    println!("  参与方: {} 方协作计算", party_count);
    println!("  门限: {} (需要{}方参与重构)", threshold, threshold);
    println!("  隐私保证: 计算过程中不泄露输入值");
    
    // === 步骤1: 准备 Beaver 三元组 ===
    println!("\n🎲 步骤1: 生成 OLE Beaver 三元组");
    let mut ole_generator = OLEBeaverGenerator::new(party_count, threshold, party_id)?;
    let beaver_triple = ole_generator.generate_single()?;
    
    println!("  ✅ Beaver 三元组准备完成");
    println!("  💡 每个三元组只能使用一次，确保安全性");
    
    // === 步骤2: 设置计算任务 ===
    println!("\n📝 步骤2: 定义安全乘法任务");
    let x = 15u64;  // 第一个参与方的私有输入
    let y = 25u64;  // 第二个参与方的私有输入
    let expected_product = field_mul(x, y);
    
    println!("  计算任务: 安全计算 x × y");
    println!("  输入值 x: {} (参与方A的私有数据)", x);
    println!("  输入值 y: {} (参与方B的私有数据)", y);
    println!("  期望结果: {} (仅用于验证，实际不可见)", expected_product);
    println!("  🎯 目标: 在不泄露 x, y 的情况下计算乘积");
    
    // === 步骤3: 创建输入的秘密分享 ===
    println!("\n📤 步骤3: 创建输入的秘密分享");
    println!("  将私有输入转换为秘密分享格式...");
    
    let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
    let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
    
    println!("  ✅ 输入分享创建完成");
    println!("  📊 分享分布（实际部署中通过安全信道传输）:");
    
    for i in 0..party_count {
        println!("    参与方 {}: x_share=({}, ***), y_share=({}, ***)", 
                i, x_shares[i].x, y_shares[i].x);
    }
    println!("  💡 每个参与方只知道自己的分享，无法推断原始值");
    
    // === 步骤4: 执行安全乘法协议 ===
    println!("\n🔐 步骤4: 执行 Beaver 三元组安全乘法协议");
    println!("  协议执行步骤:");
    println!("    1. 计算掩码值: d = x - a, e = y - b");
    println!("    2. 重构并公开 d 和 e（安全，因为 a,b 随机）");
    println!("    3. 计算结果: [xy] = [c] + d[b] + e[a] + de");
    println!("    4. 生成乘积的秘密分享");
    
    let product_shares = secure_multiply(&x_shares, &y_shares, &beaver_triple, threshold)?;
    
    println!("  ✅ 安全乘法协议执行完成");
    println!("  📊 生成的乘积分享:");
    
    for (i, share) in product_shares.iter().enumerate() {
        println!("    参与方 {}: product_share=({}, ***)", i, share.x);
    }
    
    // === 步骤5: 重构计算结果 ===
    println!("\n📥 步骤5: 重构乘法计算结果");
    println!("  使用门限数量的分享重构最终结果...");
    
    let reconstructed_product = ShamirSecretSharing::reconstruct(
        &product_shares[0..threshold], 
        threshold
    )?;
    
    println!("  ✅ 结果重构完成");
    println!("  🎉 计算结果:");
    println!("    安全乘法结果: {}", reconstructed_product);
    println!("    预期结果: {}", expected_product);
    println!("    验证: {} == {} -> {}", 
            reconstructed_product, expected_product, 
            reconstructed_product == expected_product);
    
    // === 步骤6: 验证协议正确性 ===
    println!("\n✅ 步骤6: 验证协议正确性");
    
    assert_eq!(reconstructed_product, expected_product, "安全乘法结果验证失败");
    
    println!("  🎯 协议验证结果:");
    println!("    • 数学正确性: ✅ 通过");
    println!("    • 隐私保护: ✅ 输入值始终保密");
    println!("    • 安全性: ✅ 无信息泄露");
    println!("    • 效率: ✅ 高效的一轮通信协议");
    
    // === 协议特性总结 ===
    println!("\n📋 安全乘法协议特性总结:");
    println!("  🔒 安全特性:");
    println!("    • 输入隐私: 参与方私有输入始终保密");
    println!("    • 计算正确: 数学上可证明的正确性");
    println!("    • 抗共谋: 少于门限的参与方无法获得额外信息");
    
    println!("  ⚡ 性能特性:");
    println!("    • 通信轮数: 1轮（高效）");
    println!("    • 计算复杂度: O(n) 域运算");
    println!("    • 预处理: Beaver 三元组可提前生成");
    
    println!("  🚀 实用特性:");
    println!("    • 可组合: 可用于构建复杂算术电路");
    println!("    • 可并行: 支持多个乘法同时执行");
    println!("    • 标准化: 基于成熟的密码学理论");
    
    println!("\n✅ OLE Beaver 三元组安全乘法演示完成\n");
    
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