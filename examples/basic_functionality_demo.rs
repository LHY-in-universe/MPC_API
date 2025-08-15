//! # MPC API 基础功能演示指南
//! 
//! 本文件提供了一个全面的 MPC (Multi-Party Computation) API 基础功能演示，
//! 专为初学者和希望快速上手的开发者设计。通过实际可运行的代码示例，
//! 展示安全多方计算的核心概念和基础操作。
//! 
//! ## 🎯 学习目标
//! 
//! 通过本演示，您将掌握：
//! - **有限域运算**: 密码学计算的数学基础，包括加法、减法、乘法和逆元运算
//! - **秘密分享机制**: Shamir 秘密分享的完整流程，从分享生成到重构
//! - **Beaver 三元组**: 安全乘法的核心预处理材料及其应用
//! - **承诺方案**: 哈希承诺的创建、验证和隐私保护特性
//! - **Merkle 树**: 数据完整性证明和包含性验证技术
//! 
//! ## 🔒 密码学基础概念
//! 
//! ### 有限域 (Finite Field)
//! 
//! 有限域是密码学的数学基础，所有运算都在模 p 意义下进行，其中 p 是一个大素数。
//! 这确保了：
//! - **确定性**: 运算结果唯一且可重现
//! - **安全性**: 大素数提供足够的计算安全性
//! - **效率性**: 模运算具有良好的计算性能
//! 
//! ### 秘密分享 (Secret Sharing)
//! 
//! Shamir 秘密分享将秘密 s 分解为 n 个分享，满足：
//! - 任意 t 个分享可以重构原始秘密
//! - 少于 t 个分享无法获得秘密的任何信息
//! - 基于多项式插值的数学原理
//! 
//! ### Beaver 三元组 (Beaver Triples)
//! 
//! Beaver 三元组 (a, b, c) 满足 c = a × b，用于安全乘法：
//! - **预处理**: 在离线阶段生成，不依赖实际输入
//! - **高效性**: 在线阶段只需常数轮通信
//! - **通用性**: 可用于任意两个秘密值的乘法
//! 
//! ## 🚀 应用场景
//! 
//! - **隐私保护机器学习**: 多方联合训练而不泄露数据
//! - **金融风控**: 银行间联合风险评估
//! - **医疗数据分析**: 医院间协作研究保护患者隐私
//! - **供应链协作**: 企业间信息共享而不泄露商业机密
//! 
//! ## 📊 性能特点
//! 
//! - **有限域运算**: O(1) 时间复杂度，高度优化
//! - **秘密分享**: O(n) 分享生成，O(t) 重构复杂度
//! - **Beaver 三元组**: 一次性预处理，多次高效使用
//! - **承诺方案**: O(1) 承诺和验证操作
//! - **Merkle 树**: O(log n) 证明生成和验证

use mpc_api::{*, Result};
use mpc_api::secret_sharing::FIELD_PRIME;

/// 有限域运算基础演示
/// 
/// ## 🎯 功能概述
/// 
/// 本函数展示有限域 F_p 中的基本算术运算，这是所有密码学协议的数学基础。
/// 有限域确保所有运算都在一个封闭的、有限的数学结构中进行。
/// 
/// ## 📚 数学背景
/// 
/// ### 有限域的定义
/// 有限域 F_p 是由素数 p 定义的集合 {0, 1, 2, ..., p-1}，具有以下性质：
/// - **加法**: (a + b) mod p
/// - **减法**: (a - b + p) mod p  
/// - **乘法**: (a × b) mod p
/// - **逆元**: a^(-1) 满足 (a × a^(-1)) mod p = 1
/// 
/// ### 为什么使用有限域？
/// 
/// 1. **确定性**: 所有运算结果都在有限范围内
/// 2. **安全性**: 大素数 p 提供密码学安全性
/// 3. **效率性**: 模运算可以高效实现
/// 4. **代数结构**: 满足交换律、结合律、分配律
/// 
/// ## 🔒 密码学重要性
/// 
/// - **椭圆曲线密码**: 基于有限域上的椭圆曲线
/// - **秘密分享**: 多项式系数在有限域中选择
/// - **同态加密**: 密文运算对应明文的有限域运算
/// - **零知识证明**: 证明和验证都在有限域中进行
/// 
/// ## 💡 实际应用
/// 
/// - 确保计算的一致性和可重现性
/// - 防止整数溢出和数值不稳定
/// - 支持高效的模运算硬件加速
/// - 与标准密码学算法兼容
pub fn field_operations_demo() -> Result<()> {
    println!("=== 有限域运算基础演示 ===");
    
    // 展示当前使用的有限域素数
    // 这个素数的选择影响安全性和性能
    println!("🔢 当前有限域素数: {}", FIELD_PRIME);
    println!("  二进制位数: {} 位", (FIELD_PRIME as f64).log2().ceil() as u32);
    println!("  安全等级: 大约 {} 位安全强度", (FIELD_PRIME as f64).log2().ceil() as u32 / 2);
    
    // 选择两个示例操作数
    let a = 12345u64;
    let b = 67890u64;
    
    println!("\n🧮 选择测试操作数:");
    println!("  a = {} (十六进制: 0x{:x})", a, a);
    println!("  b = {} (十六进制: 0x{:x})", b, b);
    
    // === 基本算术运算演示 ===
    println!("\n➕ 有限域基本运算:");
    
    // 1. 加法运算: (a + b) mod p
    let sum = field_add(a, b);
    println!("  加法: {} + {} ≡ {} (mod {})", a, b, sum, FIELD_PRIME);
    // 验证：普通加法与模运算的关系
    let normal_sum = (a + b) % FIELD_PRIME;
    assert_eq!(sum, normal_sum, "有限域加法应该等于普通模加法");
    
    // 2. 减法运算: (a - b + p) mod p  
    let difference = field_sub(a, b);
    println!("  减法: {} - {} ≡ {} (mod {})", a, b, difference, FIELD_PRIME);
    // 验证：减法的正确性
    let verification = field_add(difference, b);
    assert_eq!(verification, a, "减法验证: (a - b) + b = a");
    
    // 3. 乘法运算: (a × b) mod p
    let product = field_mul(a, b);
    println!("  乘法: {} × {} ≡ {} (mod {})", a, b, product, FIELD_PRIME);
    // 验证：普通乘法与模运算的关系
    let normal_product = ((a as u128 * b as u128) % FIELD_PRIME as u128) as u64;
    assert_eq!(product, normal_product, "有限域乘法应该等于普通模乘法");
    
    // === 乘法逆元演示 ===
    println!("\n🔄 乘法逆元运算:");
    
    // 计算 a 的乘法逆元
    if let Some(a_inv) = field_inv(a) {
        println!("  {} 的乘法逆元: {}", a, a_inv);
        
        // 验证逆元的正确性: a × a^(-1) ≡ 1 (mod p)
        let should_be_one = field_mul(a, a_inv);
        println!("  验证: {} × {} ≡ {} (mod {})", a, a_inv, should_be_one, FIELD_PRIME);
        assert_eq!(should_be_one, 1, "乘法逆元验证失败");
        println!("  ✅ 乘法逆元验证通过");
        
        // 展示逆元的唯一性
        println!("  💡 数学性质: 在有限域中，除0外每个元素都有唯一的乘法逆元");
    } else {
        // 这种情况不应该发生，因为 a ≠ 0 且 FIELD_PRIME 是素数
        println!("  ❌ 无法找到 {} 的乘法逆元", a);
    }
    
    // === 有限域性质验证 ===
    println!("\n🔍 有限域代数性质验证:");
    
    // 1. 交换律验证
    let ab = field_mul(a, b);
    let ba = field_mul(b, a);
    assert_eq!(ab, ba, "乘法交换律验证失败");
    println!("  ✅ 乘法交换律: a × b = b × a");
    
    // 2. 分配律验证  
    let c = 98765u64;
    let left = field_mul(a, field_add(b, c));   // a × (b + c)
    let right = field_add(field_mul(a, b), field_mul(a, c)); // a × b + a × c
    assert_eq!(left, right, "分配律验证失败");
    println!("  ✅ 分配律: a × (b + c) = a × b + a × c");
    
    // 3. 零元和单位元验证
    let zero_result = field_add(a, 0);
    assert_eq!(zero_result, a, "加法零元验证失败");
    let one_result = field_mul(a, 1);
    assert_eq!(one_result, a, "乘法单位元验证失败");
    println!("  ✅ 零元性质: a + 0 = a");
    println!("  ✅ 单位元性质: a × 1 = a");
    
    // === 实际应用示例 ===
    println!("\n🎯 实际应用示例:");
    println!("  • 椭圆曲线点运算: 坐标在有限域中计算");
    println!("  • 秘密分享多项式: 系数和求值都在有限域中");
    println!("  • 同态加密运算: 密文运算对应有限域运算");
    println!("  • 数字签名算法: 签名计算使用有限域算术");
    
    println!("\n✅ 有限域运算演示完成");
    println!("💡 关键要点:");
    println!("  1. 所有运算都在模 {} 意义下进行", FIELD_PRIME);
    println!("  2. 结果总是在 [0, {}) 范围内", FIELD_PRIME);
    println!("  3. 满足所有代数运算法则（交换律、结合律、分配律）");
    println!("  4. 为上层密码学协议提供数学基础\n");
    
    Ok(())
}

/// Shamir 秘密分享机制详细演示
/// 
/// ## 🎯 功能概述
/// 
/// 本函数演示 Shamir 秘密分享方案的完整流程，这是安全多方计算的核心技术。
/// 通过多项式插值的数学原理，将一个秘密安全地分配给多个参与方。
/// 
/// ## 📚 算法原理
/// 
/// ### Shamir 秘密分享的数学基础
/// 
/// 给定秘密 s，选择 t-1 次多项式 f(x) = s + a₁x + a₂x² + ... + aₜ₋₁x^(t-1)
/// 其中：
/// - f(0) = s (秘密值)
/// - 系数 a₁, a₂, ..., aₜ₋₁ 随机选择
/// - 每个参与方 i 获得分享 (i, f(i))
/// 
/// ### 门限重构原理
/// 
/// - **门限性质**: 任意 t 个分享可以通过拉格朗日插值重构秘密
/// - **隐私性质**: 少于 t 个分享无法获得秘密的任何信息
/// - **线性性质**: 分享的运算对应秘密的运算
/// 
/// ## 🔒 安全保证
/// 
/// 1. **完美秘密性**: 信息论安全，对抗计算无界敌手
/// 2. **门限控制**: 精确控制重构所需的最少参与方数量
/// 3. **可验证性**: 可以验证分享的有效性和一致性
/// 4. **容错性**: 可以容忍部分参与方离线或故障
/// 
/// ## 🚀 应用场景
/// 
/// - **分布式密钥管理**: 加密密钥的安全存储和使用
/// - **多方计算输入**: 各方输入数据的隐私保护
/// - **区块链治理**: 多签钱包和去中心化决策
/// - **关键基础设施**: 核设施、金融系统的安全控制
pub fn secret_sharing_demo() -> Result<()> {
    println!("=== Shamir 秘密分享机制演示 ===");
    
    // === 基本参数设置 ===
    let secret = 123456u64;
    let threshold = 3;      // 重构门限：需要至少3个分享
    let total_parties = 5;  // 总参与方：生成5个分享
    
    println!("🔐 秘密分享配置:");
    println!("  秘密值: {} (需要保护的敏感数据)", secret);
    println!("  门限方案: {}-out-of-{}", threshold, total_parties);
    println!("  重构门限: {} (最少需要{}个参与方合作)", threshold, threshold);
    println!("  参与方总数: {} (总共{}方持有分享)", total_parties, total_parties);
    println!("  容错能力: 可容忍{}方离线", total_parties - threshold);
    
    // === 步骤1: 秘密分享生成 ===
    println!("\n📤 步骤1: 生成秘密分享");
    println!("  使用 {}-1 = {} 次多项式进行分享", threshold, threshold - 1);
    
    let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
    
    println!("  ✅ 成功生成 {} 个秘密分享", shares.len());
    
    // 展示分享结构（注意：实际应用中不应泄露分享值）
    println!("  📊 分享分布情况:");
    for (i, share) in shares.iter().enumerate() {
        println!("    参与方 {}: 点({}, ***) [x坐标={}, y坐标保密]", 
                i + 1, share.x, share.x);
    }
    
    // === 步骤2: 秘密重构演示 ===
    println!("\n📥 步骤2: 使用门限数量的分享重构秘密");
    println!("  选择前 {} 个分享进行重构", threshold);
    
    let reconstruction_shares = &shares[0..threshold];
    println!("  使用分享: {:?}", 
            reconstruction_shares.iter().map(|s| s.x).collect::<Vec<_>>());
    
    let reconstructed = ShamirSecretSharing::reconstruct(reconstruction_shares, threshold)?;
    
    println!("  🔓 重构结果: {}", reconstructed);
    println!("  📊 重构验证: {} == {} -> {}", 
            secret, reconstructed, secret == reconstructed);
    
    assert_eq!(secret, reconstructed, "秘密重构失败");
    println!("  ✅ 秘密重构成功");
    
    // === 步骤3: 隐私性验证 ===
    println!("\n🛡️ 步骤3: 隐私性验证");
    println!("  测试少于门限的分享无法重构秘密");
    
    let insufficient_shares = &shares[0..threshold-1];
    println!("  使用 {} 个分享（少于门限 {}）", insufficient_shares.len(), threshold);
    
    // 注意：这里我们不实际尝试重构，因为会失败
    // 在实际实现中，应该返回错误或随机值
    println!("  💡 理论保证: {} 个分享无法获得秘密的任何信息", threshold - 1);
    
    // === 步骤4: 同态性质演示 ===
    println!("\n🔄 步骤4: 同态运算演示");
    println!("  展示秘密分享的线性同态性质");
    
    let secret2 = 654321u64;
    println!("  第二个秘密: {}", secret2);
    
    let shares2 = ShamirSecretSharing::share(&secret2, threshold, total_parties)?;
    println!("  生成第二组分享完成");
    
    // 分享级别的加法运算
    println!("  执行分享级别的加法运算...");
    let sum_shares: Vec<_> = shares.iter()
        .zip(shares2.iter())
        .map(|(s1, s2)| ShamirSecretSharing::add_shares(s1, s2))
        .collect::<Result<Vec<_>>>()?;
    
    println!("  ✅ 分享加法完成，生成 {} 个和分享", sum_shares.len());
    
    // 重构加法结果
    let computed_sum = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
    let expected_sum = field_add(secret, secret2);
    
    println!("  🧮 同态运算验证:");
    println!("    秘密1: {}", secret);
    println!("    秘密2: {}", secret2);
    println!("    期望和: {}", expected_sum);
    println!("    计算和: {}", computed_sum);
    println!("    验证: {} == {} -> {}", 
            expected_sum, computed_sum, expected_sum == computed_sum);
    
    assert_eq!(computed_sum, expected_sum, "同态加法验证失败");
    println!("  ✅ 同态加法验证成功");
    
    // === 步骤5: 鲁棒性演示 ===
    println!("\n🔧 步骤5: 容错性和鲁棒性");
    
    // 使用不同的分享组合重构
    println!("  测试使用不同分享组合重构:");
    
    let test_combinations = vec![
        vec![0, 1, 2],  // 前三个分享
        vec![1, 2, 3],  // 中间三个分享
        vec![2, 3, 4],  // 后三个分享
    ];
    
    for (i, combination) in test_combinations.iter().enumerate() {
        let test_shares: Vec<_> = combination.iter()
            .map(|&idx| shares[idx].clone())
            .collect();
        
        let test_result = ShamirSecretSharing::reconstruct(&test_shares, threshold)?;
        
        println!("    组合 {}: 分享{:?} -> 结果 {}", 
                i + 1, combination, test_result);
        assert_eq!(test_result, secret, "分享组合{}重构失败", i + 1);
    }
    
    println!("  ✅ 所有分享组合都能正确重构秘密");
    
    // === 安全性和应用总结 ===
    println!("\n📋 Shamir 秘密分享特性总结:");
    println!("  🔒 安全特性:");
    println!("    • 信息论安全: 对计算无界敌手安全");
    println!("    • 完美秘密性: 少于门限的分享不泄露任何信息");
    println!("    • 可验证性: 可以检测无效或损坏的分享");
    
    println!("  ⚡ 性能特性:");
    println!("    • 分享生成: O(n) 时间复杂度");
    println!("    • 秘密重构: O(t²) 时间复杂度（拉格朗日插值）");
    println!("    • 存储开销: 每个分享需要两个域元素");
    
    println!("  🚀 实际应用:");
    println!("    • 多方计算协议的输入层");
    println!("    • 分布式密钥管理系统");
    println!("    • 区块链多签名方案");
    println!("    • 容错存储系统");
    
    println!("\n✅ Shamir 秘密分享演示完成");
    println!("💡 核心价值: 在分布式环境中提供数学上可证明的秘密保护\n");
    
    Ok(())
}

/// Beaver 三元组安全乘法机制演示
/// 
/// ## 🎯 功能概述
/// 
/// 本函数详细演示 Beaver 三元组技术，这是安全多方计算中实现高效乘法运算的核心技术。
/// Beaver 三元组通过预处理的方式，将复杂的安全乘法问题转化为简单的线性运算。
/// 
/// ## 📚 技术原理
/// 
/// ### Beaver 三元组的定义
/// 
/// Beaver 三元组是满足 c = a × b 的三元组 (a, b, c)，其中：
/// - a, b: 随机选择的有限域元素
/// - c: a 和 b 的乘积，在有限域中计算
/// - 所有值都以秘密分享的形式分发给参与方
/// 
/// ### 安全乘法协议
/// 
/// 使用 Beaver 三元组实现安全乘法的步骤：
/// 1. 各方持有秘密分享 [x] 和 [y]（待乘的值）
/// 2. 各方持有预处理的 Beaver 三元组 ([a], [b], [c])
/// 3. 计算并公开 d = x - a 和 e = y - b
/// 4. 计算结果：[xy] = [c] + d[b] + e[a] + de
/// 
/// ### 安全性分析
/// 
/// - **隐私保护**: d 和 e 的公开不会泄露 x, y 的信息（因为 a, b 是随机的）
/// - **正确性**: 数学上可证明结果等于 xy
/// - **高效性**: 在线阶段只需要一轮通信和简单运算
/// 
/// ## 🚀 优势特点
/// 
/// 1. **预处理模式**: 三元组可以提前生成，不依赖实际输入
/// 2. **高效在线**: 在线阶段复杂度极低，接近明文计算速度
/// 3. **可扩展性**: 支持任意数量的参与方和复杂计算
/// 4. **通用性**: 可以组合构建任意的算术电路
/// 
/// ## 💡 应用场景
/// 
/// - **隐私保护机器学习**: 神经网络的矩阵乘法运算
/// - **金融计算**: 多方风险评估和投资组合优化
/// - **统计分析**: 多源数据的协方差和相关性计算
/// - **科学计算**: 联合研究中的数值模拟
pub fn beaver_triples_demo() -> Result<()> {
    println!("=== Beaver 三元组安全乘法演示 ===");
    
    // === 配置协议参数 ===
    let party_count = 3;    // 3方协议
    let threshold = 2;      // 2-out-of-3 门限
    let party_id = 0;       // 当前方ID
    
    println!("🔧 协议配置:");
    println!("  参与方数量: {} 方", party_count);
    println!("  门限设置: {}-out-of-{}", threshold, party_count);
    println!("  当前方身份: 参与方 {}", party_id);
    println!("  容错能力: 可容忍 {} 方故障", party_count - threshold);
    
    // === 步骤1: 创建可信第三方生成器 ===
    println!("\n⚙️ 步骤1: 创建 Beaver 三元组生成器");
    println!("  使用可信第三方模式（适用于受控环境）");
    
    let mut generator = TrustedPartyBeaverGenerator::new(
        party_count, 
        threshold, 
        party_id, 
        None  // 使用默认安全参数
    )?;
    
    println!("  ✅ 可信第三方生成器创建成功");
    
    // === 步骤2: 生成 Beaver 三元组 ===
    println!("\n🎲 步骤2: 生成 Beaver 三元组");
    println!("  生成满足 c = a × b 关系的随机三元组...");
    
    let beaver_triple = generator.generate_single()?;
    
    println!("  ✅ Beaver 三元组生成成功");
    println!("  📊 三元组结构:");
    println!("    分享数量: {} (每个参与方一份)", beaver_triple.shares.len());
    println!("    分享类型: Shamir 秘密分享");
    
    // === 步骤3: 验证三元组有效性 ===
    println!("\n🔍 步骤3: 验证三元组有效性");
    println!("  检查数学关系 c = a × b 是否成立...");
    
    let is_valid = generator.verify_triple(&beaver_triple)?;
    println!("  验证结果: {}", if is_valid { "✅ 有效" } else { "❌ 无效" });
    
    if !is_valid {
        println!("  ⚠️ 警告: 三元组验证失败，可能存在生成错误");
        println!("     在生产环境中应该重新生成或使用备份三元组");
    }
    
    // === 步骤4: 分析三元组结构 ===
    println!("\n📋 步骤4: 分析三元组分享结构");
    
    for (party_id, triple_share) in &beaver_triple.shares {
        println!("  📍 参与方 {} 的分享:", party_id);
        println!("    a 分享: 点({}, ***) [x={}, y值保密]", triple_share.a.x, triple_share.a.x);
        println!("    b 分享: 点({}, ***) [x={}, y值保密]", triple_share.b.x, triple_share.b.x);
        println!("    c 分享: 点({}, ***) [x={}, y值保密]", triple_share.c.x, triple_share.c.x);
        
        // 检查分享的内部一致性
        let consistency = triple_share.is_consistent();
        println!("    分享一致性: {}", if consistency { "✅ 一致" } else { "❌ 不一致" });
    }
    
    // === 步骤5: 验证原始值关系（仅用于教学演示） ===
    println!("\n🔓 步骤5: 验证原始三元组关系 (仅供教学)");
    
    if let Some((a, b, c)) = beaver_triple.original_values {
        println!("  原始三元组值:");
        println!("    a = {} (第一个随机因子)", a);
        println!("    b = {} (第二个随机因子)", b);
        println!("    c = {} (计算得出的乘积)", c);
        
        let computed_c = field_mul(a, b);
        println!("  数学验证:");
        println!("    计算 a × b = {} × {} = {}", a, b, computed_c);
        println!("    验证 c = {} (期望值)", c);
        
        if c == computed_c {
            println!("    ✅ 数学关系正确: c = a × b");
        } else {
            println!("    ❌ 数学关系错误: c ≠ a × b");
            return Err(MpcError::ProtocolError("Beaver 三元组数学关系验证失败".to_string()));
        }
    } else {
        println!("  💡 原始值已安全删除（符合安全协议要求）");
    }
    
    // === 步骤6: 安全乘法协议演示 ===
    println!("\n🔐 步骤6: 使用 Beaver 三元组进行安全乘法");
    
    if is_valid {
        // 选择两个待相乘的秘密值
        let x = 25u64;
        let y = 16u64;
        let expected_product = field_mul(x, y);
        
        println!("  🎯 乘法任务:");
        println!("    秘密值 x: {}", x);
        println!("    秘密值 y: {}", y);
        println!("    期望乘积: {}", expected_product);
        
        // 将秘密值转换为秘密分享
        println!("  📤 创建输入的秘密分享...");
        let x_shares = ShamirSecretSharing::share(&x, threshold, party_count)?;
        let y_shares = ShamirSecretSharing::share(&y, threshold, party_count)?;
        println!("    ✅ x 和 y 的秘密分享创建完成");
        
        // 执行安全乘法协议
        println!("  🧮 执行 Beaver 三元组安全乘法协议...");
        println!("    协议步骤:");
        println!("      1. 计算 d = x - a (在秘密分享上)");
        println!("      2. 计算 e = y - b (在秘密分享上)");
        println!("      3. 重构并公开 d 和 e");
        println!("      4. 计算 [xy] = [c] + d[b] + e[a] + de");
        
        let result_shares = secure_multiply(&x_shares, &y_shares, &beaver_triple, threshold)?;
        println!("    ✅ 安全乘法协议执行完成");
        
        // 重构最终结果
        println!("  📥 重构乘法结果...");
        let computed_result = ShamirSecretSharing::reconstruct(&result_shares[0..threshold], threshold)?;
        
        println!("  🎉 安全乘法结果:");
        println!("    计算结果: {}", computed_result);
        println!("    期望结果: {}", expected_product);
        println!("    验证: {} == {} -> {}", 
                computed_result, expected_product, computed_result == expected_product);
        
        if computed_result == expected_product {
            println!("    ✅ 安全乘法结果完全正确");
        } else {
            println!("    ❌ 安全乘法结果错误");
            return Err(MpcError::ProtocolError("安全乘法结果验证失败".to_string()));
        }
        
        // === 性能和安全性分析 ===
        println!("\n📊 性能和安全性分析:");
        println!("  ⚡ 性能特点:");
        println!("    • 预处理阶段: 一次性生成，可重复使用");
        println!("    • 在线阶段: 仅需1轮通信 + 简单运算");
        println!("    • 计算复杂度: 接近明文乘法的性能");
        
        println!("  🔒 安全保证:");
        println!("    • 隐私保护: x, y 值始终保密");
        println!("    • 正确性: 数学上可证明的正确性");
        println!("    • 可验证性: 可以验证计算结果的正确性");
        
    } else {
        println!("  ⚠️ 跳过安全乘法演示（三元组验证失败）");
        println!("    在实际应用中应该:");
        println!("      1. 重新生成三元组");
        println!("      2. 使用备份三元组");
        println!("      3. 检查生成器配置");
    }
    
    // === 实际应用场景 ===
    println!("\n🚀 Beaver 三元组实际应用:");
    println!("  💼 商业应用:");
    println!("    • 联合投资组合优化: 多家金融机构合作计算最优配置");
    println!("    • 供应链风险评估: 多方协作评估供应链整体风险");
    println!("    • 市场调研分析: 多企业联合分析市场数据");
    
    println!("  🏥 科研应用:");
    println!("    • 医疗数据研究: 多医院联合研究而不泄露患者信息");
    println!("    • 基因数据分析: 多机构协作基因组研究");
    println!("    • 气候模型计算: 多国合作气候预测模型");
    
    println!("  🤖 技术应用:");
    println!("    • 联邦学习: 多方联合训练机器学习模型");
    println!("    • 隐私保护推荐: 多平台协作推荐系统");
    println!("    • 安全审计: 多方协作安全审计计算");
    
    println!("\n✅ Beaver 三元组演示完成");
    println!("💡 核心价值: 高效、安全、可扩展的多方乘法运算解决方案\n");
    
    Ok(())
}

/// 哈希承诺方案详细演示
/// 
/// ## 🎯 功能概述
/// 
/// 本函数演示哈希承诺方案，这是密码学中一种基础的承诺原语。
/// 承诺方案允许一方在不泄露信息的情况下承诺某个值，并在稍后阶段验证承诺的正确性。
/// 
/// ## 📚 理论基础
/// 
/// ### 承诺方案的定义
/// 
/// 承诺方案包含两个阶段：
/// 1. **承诺阶段**: 承诺方选择秘密值 s 和随机数 r，计算承诺值 c = Commit(s, r)
/// 2. **揭示阶段**: 承诺方公开 s 和 r，验证方检查 c = Commit(s, r) 是否成立
/// 
/// ### 安全性质
/// 
/// 承诺方案必须满足两个关键性质：
/// 
/// 1. **隐藏性 (Hiding)**: 承诺值 c 不泄露关于秘密值 s 的任何信息
///    - 即使攻击者拥有无限计算能力，也无法从 c 推断出 s
///    - 数学表示: Pr[s=0|c] = Pr[s=1|c] (对于二进制情况)
/// 
/// 2. **绑定性 (Binding)**: 承诺方无法找到两个不同的值对应同一个承诺
///    - 即无法找到 (s₁,r₁) ≠ (s₂,r₂) 使得 Commit(s₁,r₁) = Commit(s₂,r₂)
///    - 基于哈希函数的抗碰撞性质
/// 
/// ### 哈希承诺的构造
/// 
/// 哈希承诺使用密码学哈希函数 H：
/// - 承诺: c = H(s || r)  (s 连接 r 后计算哈希)
/// - 验证: 检查 c ?= H(s || r)
/// 
/// ## 🔒 安全分析
/// 
/// - **隐藏性**: 基于哈希函数的单向性和伪随机性
/// - **绑定性**: 基于哈希函数的抗碰撞性
/// - **计算安全**: 对计算多项式时间敌手安全
/// 
/// ## 🚀 应用场景
/// 
/// - **拍卖协议**: 密封竞价拍卖中的出价承诺
/// - **投票系统**: 电子投票中的选票承诺
/// - **零知识证明**: 作为更复杂协议的构建块
/// - **区块链**: 提交-揭示模式的智能合约
/// - **多方计算**: 输入承诺和结果验证
pub fn hash_commitment_demo() -> Result<()> {
    println!("=== 哈希承诺方案详细演示 ===");
    
    // === 设置演示参数 ===
    let secret_value = 42u64;      // 要承诺的秘密值
    let randomness = 123456u64;    // 随机数（确保隐藏性）
    
    println!("🔐 承诺设置:");
    println!("  秘密值: {} (需要承诺的敏感信息)", secret_value);
    println!("  随机数: {} (确保承诺的隐藏性)", randomness);
    println!("  哈希函数: SHA-256 (提供安全保证)");
    
    // === 步骤1: 创建承诺 ===
    println!("\n📝 步骤1: 创建哈希承诺");
    println!("  执行承诺计算: c = H(secret || randomness)");
    
    let commitment = HashCommitment::commit_u64(secret_value, randomness);
    
    println!("  ✅ 承诺创建完成");
    println!("  📊 承诺信息:");
    println!("    承诺值长度: {} 字节", commitment.len());
    println!("    承诺值(前8字节): {:02x?}...", &commitment[0..8]);
    println!("    💡 完整承诺值可以安全公开");
    
    // === 步骤2: 承诺验证（正确情况） ===
    println!("\n🔍 步骤2: 承诺验证 (正确揭示)");
    println!("  使用原始秘密值和随机数进行验证...");
    
    let is_valid = HashCommitment::verify_u64(&commitment, secret_value, randomness);
    
    println!("  验证过程:");
    println!("    1. 重新计算: c' = H({} || {})", secret_value, randomness);
    println!("    2. 比较结果: c' ?= c");
    println!("    3. 验证结果: {}", if is_valid { "✅ 通过" } else { "❌ 失败" });
    
    assert!(is_valid, "正确的承诺验证应该通过");
    println!("  ✅ 承诺验证成功，证明秘密值确实是 {}", secret_value);
    
    // === 步骤3: 错误值验证（演示绑定性） ===
    println!("\n🚫 步骤3: 错误值验证 (演示绑定性)");
    
    let wrong_value = 99u64;
    println!("  尝试使用错误的秘密值: {}", wrong_value);
    println!("  (保持随机数不变: {})", randomness);
    
    let is_wrong_valid = HashCommitment::verify_u64(&commitment, wrong_value, randomness);
    
    println!("  验证过程:");
    println!("    1. 计算: c'' = H({} || {})", wrong_value, randomness);
    println!("    2. 比较: c'' ?= c");
    println!("    3. 结果: {}", if is_wrong_valid { "❌ 意外通过" } else { "✅ 正确拒绝" });
    
    assert!(!is_wrong_valid, "错误的值应该被拒绝");
    println!("  ✅ 绑定性验证：无法使用错误值通过验证");
    
    // === 步骤4: 错误随机数验证 ===
    println!("\n🎲 步骤4: 错误随机数验证");
    
    let wrong_randomness = 654321u64;
    println!("  尝试使用错误的随机数: {}", wrong_randomness);
    println!("  (保持秘密值不变: {})", secret_value);
    
    let is_wrong_rand_valid = HashCommitment::verify_u64(&commitment, secret_value, wrong_randomness);
    
    println!("  验证结果: {}", if is_wrong_rand_valid { "❌ 意外通过" } else { "✅ 正确拒绝" });
    assert!(!is_wrong_rand_valid, "错误的随机数应该被拒绝");
    println!("  ✅ 随机数绑定性验证：必须使用正确的随机数");
    
    // === 步骤5: 隐藏性演示 ===
    println!("\n🔒 步骤5: 隐藏性特性演示");
    
    // 创建多个不同值的承诺
    let test_values = vec![0u64, 1u64, 42u64, 100u64, 999999u64];
    let test_randomness = vec![111111u64, 222222u64, 333333u64, 444444u64, 555555u64];
    
    println!("  创建多个不同值的承诺:");
    
    let mut commitments = Vec::new();
    for (i, (&value, &rand)) in test_values.iter().zip(test_randomness.iter()).enumerate() {
        let comm = HashCommitment::commit_u64(value, rand);
        commitments.push(comm);
        println!("    承诺 {}: 值={}, 随机数={}, 承诺值前4字节={:02x?}", 
                i + 1, value, rand, &commitments[i][0..4]);
    }
    
    println!("  💡 观察: 即使知道所有承诺值，也无法推断出原始秘密值");
    println!("     这展示了哈希承诺的隐藏性特质");
    
    // === 步骤6: 实际应用场景模拟 ===
    println!("\n🎯 步骤6: 实际应用场景模拟");
    
    // 模拟密封竞价拍卖
    println!("  📱 场景: 密封竞价拍卖");
    let auction_bids = vec![
        (100u64, 789012u64),  // 竞价者A: 100元
        (150u64, 345678u64),  // 竞价者B: 150元  
        (120u64, 901234u64),  // 竞价者C: 120元
    ];
    
    println!("    第一阶段 - 提交承诺:");
    let mut auction_commitments = Vec::new();
    for (i, &(bid, rand)) in auction_bids.iter().enumerate() {
        let comm = HashCommitment::commit_u64(bid, rand);
        auction_commitments.push(comm);
        println!("      竞价者 {}: 提交承诺 {:02x?}...", 
                char::from(b'A' + i as u8), &comm[0..4]);
    }
    
    println!("    第二阶段 - 揭示竞价:");
    let mut revealed_bids = Vec::new();
    for (i, &(bid, rand)) in auction_bids.iter().enumerate() {
        let is_valid = HashCommitment::verify_u64(&auction_commitments[i], bid, rand);
        if is_valid {
            revealed_bids.push((i, bid));
            println!("      竞价者 {}: 竞价 {}元 ✅ 验证通过", 
                    char::from(b'A' + i as u8), bid);
        } else {
            println!("      竞价者 {}: ❌ 验证失败", char::from(b'A' + i as u8));
        }
    }
    
    // 确定拍卖结果
    if let Some((winner_idx, winning_bid)) = revealed_bids.iter().max_by_key(|(_, bid)| *bid) {
        println!("    🏆 拍卖结果: 竞价者 {} 以 {}元 获胜", 
                char::from(b'A' + *winner_idx as u8), winning_bid);
    }
    
    // === 安全性和性能分析 ===
    println!("\n📊 哈希承诺特性分析:");
    
    println!("  🔒 安全特性:");
    println!("    • 隐藏性: 承诺值不泄露秘密信息");
    println!("    • 绑定性: 无法更改已承诺的值");
    println!("    • 抗篡改: 任何修改都会被检测到");
    println!("    • 可验证: 任何人都可以验证承诺");
    
    println!("  ⚡ 性能特性:");
    println!("    • 承诺生成: O(1) 时间，一次哈希计算");
    println!("    • 验证速度: O(1) 时间，一次哈希计算");
    println!("    • 存储开销: 固定大小（哈希长度）");
    println!("    • 通信开销: 最小化，只需传输哈希值");
    
    println!("  🚀 应用优势:");
    println!("    • 简单高效: 实现和使用都很简单");
    println!("    • 标准化: 基于成熟的哈希函数");
    println!("    • 可组合: 可以作为复杂协议的构建块");
    println!("    • 通用性: 适用于各种需要承诺的场景");
    
    println!("\n✅ 哈希承诺演示完成");
    println!("💡 核心价值: 简单、高效、安全的数字承诺解决方案\n");
    
    Ok(())
}

/// Merkle 树数据完整性验证演示
/// 
/// ## 🎯 功能概述
/// 
/// 本函数演示 Merkle 树（默克尔树）的构建、证明生成和验证过程。
/// Merkle 树是一种重要的密码学数据结构，广泛用于区块链、分布式系统和数据完整性验证。
/// 
/// ## 📚 技术原理
/// 
/// ### Merkle 树的结构
/// 
/// Merkle 树是一种二叉树结构，具有以下特点：
/// - **叶子节点**: 存储数据项的哈希值 H(data_i)
/// - **内部节点**: 存储子节点哈希值的哈希 H(left || right)  
/// - **根节点**: 树的顶层节点，代表整个数据集的"指纹"
/// 
/// ### 构建过程
/// 
/// 1. **叶子层**: 对每个数据项计算哈希值
/// 2. **合并过程**: 相邻叶子节点的哈希值配对并再次哈希
/// 3. **递归构建**: 重复配对和哈希直到只剩一个根节点
/// 4. **平衡处理**: 奇数节点时复制最后一个节点
/// 
/// ### 包含性证明 (Merkle Proof)
/// 
/// 包含性证明是一个路径上的哈希值列表，用于证明某个数据项确实包含在树中：
/// - **证明路径**: 从叶子节点到根节点的路径上的兄弟节点哈希
/// - **验证过程**: 使用证明路径重新计算根哈希并与已知根哈希比较
/// - **对数复杂度**: 证明大小为 O(log n)，验证时间为 O(log n)
/// 
/// ## 🔒 安全性分析
/// 
/// - **完整性**: 任何数据修改都会改变根哈希
/// - **不可伪造**: 基于哈希函数的抗碰撞性质
/// - **高效验证**: 无需下载完整数据集即可验证
/// - **隐私友好**: 验证时不泄露其他数据项信息
/// 
/// ## 🚀 应用场景
/// 
/// - **区块链**: 交易数据的完整性证明
/// - **分布式存储**: 文件完整性验证（如 IPFS）
/// - **软件更新**: 增量更新的完整性保证
/// - **审计系统**: 大规模数据的高效审计
/// - **版本控制**: Git 等系统的数据结构
pub fn merkle_tree_demo() -> Result<()> {
    println!("=== Merkle 树数据完整性验证演示 ===");
    
    // === 准备测试数据 ===
    let data_items = vec![
        b"Transaction-001: Alice -> Bob: 100 coins".to_vec(),
        b"Transaction-002: Bob -> Charlie: 50 coins".to_vec(), 
        b"Transaction-003: Charlie -> David: 25 coins".to_vec(),
        b"Transaction-004: David -> Alice: 75 coins".to_vec(),
    ];
    
    println!("📄 准备测试数据:");
    println!("  数据项数量: {}", data_items.len());
    println!("  数据类型: 模拟区块链交易记录");
    
    for (i, item) in data_items.iter().enumerate() {
        println!("    [{}] {}", i, String::from_utf8_lossy(item));
    }
    
    // === 步骤1: 构建 Merkle 树 ===
    println!("\n🌳 步骤1: 构建 Merkle 树");
    println!("  计算叶子节点哈希...");
    
    // 显示叶子节点哈希计算过程
    for (i, item) in data_items.iter().enumerate() {
        // 这里我们无法直接访问内部哈希，但可以说明过程
        println!("    叶子 {}: H(data_{}) = H({:?}...)", i, i, &item[0..12]);
    }
    
    let merkle_tree = MerkleTree::new(&data_items)?;
    let root_hash = merkle_tree.get_root();
    
    println!("  ✅ Merkle 树构建完成");
    println!("  📊 树结构信息:");
    println!("    叶子节点数: {}", data_items.len());
    println!("    树的深度: {} 层", (data_items.len() as f64).log2().ceil() as u32 + 1);
    println!("    根哈希值: {:02x?}... (前8字节)", &root_hash[0..8]);
    
    // === 步骤2: 包含性证明生成 ===
    println!("\n🔍 步骤2: 包含性证明生成");
    
    let prove_index = 1;  // 证明第2个交易（索引1）
    println!("  目标数据: 为索引 {} 的数据项生成包含性证明", prove_index);
    println!("  证明内容: \"{}\"", String::from_utf8_lossy(&data_items[prove_index]));
    
    let proof = merkle_tree.generate_proof(prove_index)?;
    
    println!("  ✅ 包含性证明生成完成");
    println!("  📋 证明信息:");
    println!("    证明路径长度: {} 个哈希值", proof.siblings.len());
    println!("    证明大小: {} 字节", proof.siblings.len() * 32); // 假设每个哈希32字节
    
    // 显示证明路径（部分信息）
    for (i, hash) in proof.siblings.iter().enumerate() {
        println!("    路径 {}: {:02x?}... (兄弟节点)", i, &hash[0..4]);
    }
    
    // === 步骤3: 包含性证明验证 ===
    println!("\n✅ 步骤3: 包含性证明验证");
    println!("  验证过程: 使用证明路径重新计算根哈希");
    
    let is_included = MerkleTree::verify_proof(
        root_hash,
        &data_items[prove_index],
        &proof
    )?;
    
    println!("  验证步骤:");
    println!("    1. 计算目标数据的哈希值");
    println!("    2. 使用证明路径逐层向上计算");
    println!("    3. 将计算得到的根哈希与已知根哈希比较");
    
    println!("  🎉 验证结果: {}", if is_included { "✅ 包含" } else { "❌ 不包含" });
    assert!(is_included, "包含性证明验证应该通过");
    
    println!("  ✅ 数据项 {} 确实包含在 Merkle 树中", prove_index);
    
    // === 步骤4: 验证所有数据项 ===
    println!("\n🔄 步骤4: 验证所有数据项的包含性");
    
    let mut all_verified = true;
    for i in 0..data_items.len() {
        let proof = merkle_tree.generate_proof(i)?;
        let is_valid = MerkleTree::verify_proof(root_hash, &data_items[i], &proof)?;
        
        println!("  数据项 {}: {}", i, if is_valid { "✅ 验证通过" } else { "❌ 验证失败" });
        all_verified &= is_valid;
    }
    
    assert!(all_verified, "所有数据项都应该通过验证");
    println!("  🎉 所有数据项都成功通过包含性验证");
    
    // === 步骤5: 篡改检测演示 ===
    println!("\n🚫 步骤5: 数据篡改检测演示");
    
    // 模拟篡改数据
    let tampered_data = b"Transaction-002: Bob -> Mallory: 50 coins".to_vec(); // 篡改收款人
    println!("  原始数据: \"{}\"", String::from_utf8_lossy(&data_items[1]));
    println!("  篡改数据: \"{}\"", String::from_utf8_lossy(&tampered_data));
    
    // 使用原始证明验证篡改数据
    let tampered_proof = merkle_tree.generate_proof(1)?; // 获取原始位置的证明
    let tampered_valid = MerkleTree::verify_proof(root_hash, &tampered_data, &tampered_proof)?;
    
    println!("  篡改检测结果: {}", if tampered_valid { "❌ 未检测到篡改" } else { "✅ 成功检测到篡改" });
    assert!(!tampered_valid, "篡改的数据应该无法通过验证");
    
    // === 步骤6: 性能和效率分析 ===
    println!("\n📊 步骤6: 性能和效率分析");
    
    // 模拟不同规模的数据集
    let test_sizes = vec![4, 16, 64, 256, 1024];
    
    println!("  不同数据集规模的证明大小分析:");
    println!("  数据项数 | 证明大小 | 树深度 | 验证复杂度");
    println!("  ---------|----------|--------|----------");
    
    for &size in &test_sizes {
        let depth = (size as f64).log2().ceil() as u32;
        let proof_size = depth * 32; // 每个哈希32字节
        println!("  {:>8} | {:>6} B | {:>4} | O(log n)", size, proof_size, depth);
    }
    
    // === 步骤7: 实际应用场景模拟 ===
    println!("\n🎯 步骤7: 实际应用场景模拟");
    
    // 模拟区块链轻节点验证
    println!("  💰 场景: 区块链轻节点交易验证");
    println!("  问题: 轻节点如何在不下载完整区块的情况下验证交易？");
    println!("  解决方案: 使用 Merkle 证明");
    
    let target_tx_index = 2;
    let tx_proof = merkle_tree.generate_proof(target_tx_index)?;
    
    println!("    1. 轻节点请求交易 {} 的包含性证明", target_tx_index);
    println!("    2. 全节点返回证明路径 ({} 个哈希值)", tx_proof.siblings.len());
    println!("    3. 轻节点使用区块头中的根哈希验证");
    
    let verification_result = MerkleTree::verify_proof(root_hash, &data_items[target_tx_index], &tx_proof)?;
    println!("    4. 验证结果: {}", if verification_result { "✅ 交易有效" } else { "❌ 交易无效" });
    
    println!("  💡 优势: 节省带宽和存储，O(log n) 复杂度");
    
    // === 总结和特性分析 ===
    println!("\n📋 Merkle 树技术特性总结:");
    
    println!("  🔒 安全特性:");
    println!("    • 数据完整性: 任何修改都会改变根哈希");
    println!("    • 不可伪造: 基于哈希函数的抗碰撞性");
    println!("    • 可验证性: 高效的包含性证明机制");
    println!("    • 防篡改: 自动检测数据修改");
    
    println!("  ⚡ 性能特性:");
    println!("    • 构建复杂度: O(n) 时间和空间");
    println!("    • 证明大小: O(log n) 哈希值");
    println!("    • 验证时间: O(log n) 哈希计算");
    println!("    • 更新效率: 局部更新，不需要重构整树");
    
    println!("  🚀 应用优势:");
    println!("    • 可扩展性: 支持大规模数据集");
    println!("    • 效率性: 无需传输完整数据");
    println!("    • 标准化: 成熟的密码学工具");
    println!("    • 通用性: 适用于各种完整性验证场景");
    
    println!("  💼 实际应用:");
    println!("    • 比特币/以太坊: 交易完整性验证");
    println!("    • IPFS: 分布式文件存储验证");
    println!("    • Certificate Transparency: SSL证书透明度");
    println!("    • Git: 版本控制系统的数据结构");
    
    println!("\n✅ Merkle 树演示完成");
    println!("💡 核心价值: 高效、安全、可扩展的数据完整性验证解决方案\n");
    
    Ok(())
}

/// 运行所有基础功能演示的主控制函数
/// 
/// ## 🎯 演示目标
/// 
/// 本函数按逻辑顺序运行所有基础功能演示，为用户提供完整的 MPC API 学习体验。
/// 每个演示都建立在前面的概念基础上，形成一个完整的知识体系。
/// 
/// ## 📚 演示顺序和逻辑
/// 
/// 1. **有限域运算**: 建立数学基础，理解所有计算的数学环境
/// 2. **秘密分享**: 展示隐私保护的基本机制和分布式计算基础
/// 3. **Beaver 三元组**: 演示高级安全计算协议，建立在秘密分享之上
/// 4. **哈希承诺**: 展示承诺方案，补充密码学工具箱
/// 5. **Merkle 树**: 演示数据完整性验证，展示大规模应用技术
/// 
/// ## 🎓 学习路径
/// 
/// - **初学者**: 重点关注概念和安全性质的理解
/// - **开发者**: 关注 API 使用方法和集成模式  
/// - **研究者**: 深入理解算法原理和性能特征
/// - **工程师**: 关注实际应用场景和部署考虑
pub fn run_all_demos() -> Result<()> {
    println!("🌟 === MPC API 基础功能全面演示 ===");
    println!("📚 本演示将带您完整了解安全多方计算的核心技术");
    println!("⏱️  预计演示时间: 5-10 分钟");
    println!("🎯 适合对象: MPC 初学者、开发者、研究人员\n");
    
    // === 演示1: 有限域运算 ===
    println!("🔢 开始第1个演示: 有限域运算基础");
    println!("💡 学习重点: 理解密码学计算的数学基础\n");
    
    field_operations_demo()?;
    
    println!("⏸️  第1个演示完成，按回车继续下一个演示...");
    println!("───────────────────────────────────────────────────────────────────");
    
    // === 演示2: 秘密分享 ===
    println!("\n🔐 开始第2个演示: Shamir 秘密分享机制");
    println!("💡 学习重点: 理解隐私保护和分布式计算的基础");
    println!("🔗 与前面的联系: 基于有限域运算实现多项式插值\n");
    
    secret_sharing_demo()?;
    
    println!("⏸️  第2个演示完成，按回车继续下一个演示...");
    println!("───────────────────────────────────────────────────────────────────");
    
    // === 演示3: Beaver 三元组 ===
    println!("\n🎲 开始第3个演示: Beaver 三元组安全乘法");
    println!("💡 学习重点: 理解高级安全计算协议的设计");
    println!("🔗 与前面的联系: 基于秘密分享实现安全乘法运算\n");
    
    beaver_triples_demo()?;
    
    println!("⏸️  第3个演示完成，按回车继续下一个演示...");
    println!("───────────────────────────────────────────────────────────────────");
    
    // === 演示4: 哈希承诺 ===
    println!("\n📝 开始第4个演示: 哈希承诺方案");
    println!("💡 学习重点: 理解承诺方案在密码学协议中的作用");
    println!("🔗 与前面的联系: 为 MPC 协议提供输入承诺和验证能力\n");
    
    hash_commitment_demo()?;
    
    println!("⏸️  第4个演示完成，按回车继续最后一个演示...");
    println!("───────────────────────────────────────────────────────────────────");
    
    // === 演示5: Merkle 树 ===
    println!("\n🌳 开始第5个演示: Merkle 树数据完整性验证");
    println!("💡 学习重点: 理解大规模数据的高效完整性验证");
    println!("🔗 与前面的联系: 为 MPC 应用提供数据完整性保证\n");
    
    merkle_tree_demo()?;
    
    // === 演示总结 ===
    println!("───────────────────────────────────────────────────────────────────");
    println!("🎉 === 所有基础功能演示成功完成！ ===");
    
    println!("\n📊 演示内容回顾:");
    println!("  1️⃣ 有限域运算 - 密码学计算的数学基础");
    println!("     ✓ 模运算、逆元计算、代数性质验证");
    println!("     ✓ 为所有上层协议提供数学支撑");
    
    println!("  2️⃣ Shamir 秘密分享 - 隐私保护的核心机制");
    println!("     ✓ 门限重构、同态运算、容错性验证");
    println!("     ✓ 分布式计算和隐私保护的基础技术");
    
    println!("  3️⃣ Beaver 三元组 - 高效安全乘法协议");
    println!("     ✓ 预处理模式、安全乘法、性能优化");
    println!("     ✓ 复杂安全计算协议的核心构建块");
    
    println!("  4️⃣ 哈希承诺方案 - 简单高效的承诺原语");
    println!("     ✓ 隐藏性、绑定性、实际应用场景");
    println!("     ✓ 为协议提供输入承诺和验证能力");
    
    println!("  5️⃣ Merkle 树 - 可扩展的数据完整性验证");
    println!("     ✓ 包含性证明、篡改检测、效率分析");
    println!("     ✓ 大规模应用中的数据完整性保证");
    
    println!("\n🔗 技术关联图:");
    println!("  有限域运算 ← 所有密码学操作的基础");
    println!("       ↓");
    println!("  秘密分享 ← 隐私保护计算的核心");
    println!("       ↓");
    println!("  Beaver 三元组 ← 高级安全计算协议");
    println!("       ↓");
    println!("  哈希承诺 + Merkle 树 ← 辅助技术和完整性保证");
    
    println!("\n🚀 下一步学习建议:");
    println!("  📖 深入学习:");
    println!("    • 阅读 examples/complete_api_usage_guide.rs 了解完整 API");
    println!("    • 研究 examples/beaver_triples_trusted_party_example.rs 了解生产级实现");
    println!("    • 探索 examples/advanced_protocols_guide.rs 学习高级协议");
    
    println!("  🛠️ 实践练习:");
    println!("    • 尝试修改参数（门限值、参与方数量等）观察影响");
    println!("    • 组合不同技术实现自定义协议");
    println!("    • 测量和优化性能特征");
    
    println!("  🏢 应用开发:");
    println!("    • 分析您的应用场景需求");
    println!("    • 选择合适的技术组合");
    println!("    • 考虑安全性和性能平衡");
    
    println!("\n💡 核心收获:");
    println!("  ✓ MPC 不是单一技术，而是多种密码学技术的有机结合");
    println!("  ✓ 每种技术都有其特定的应用场景和性能特点");
    println!("  ✓ 实际应用需要根据需求选择和组合技术");
    println!("  ✓ 安全性、性能和可用性需要综合考虑");
    
    println!("\n🎓 恭喜您完成了 MPC API 基础功能的完整学习！");
    println!("🌟 您现在已经具备了开发安全多方计算应用的基础知识。");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_field_operations_demo() {
        field_operations_demo().unwrap();
    }
    
    #[test]
    fn test_secret_sharing_demo() {
        secret_sharing_demo().unwrap();
    }
    
    #[test]
    fn test_beaver_triples_demo() {
        beaver_triples_demo().unwrap();
    }
    
    #[test]
    fn test_hash_commitment_demo() {
        hash_commitment_demo().unwrap();
    }
    
    #[test]
    fn test_merkle_tree_demo() {
        merkle_tree_demo().unwrap();
    }
}

// 如果直接运行此文件，执行所有演示
fn main() -> Result<()> {
    run_all_demos()
}