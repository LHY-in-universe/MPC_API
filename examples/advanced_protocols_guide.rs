//! # 高级协议使用指南
//! 
//! 详细展示MPC API中高级协议的使用方法，所有示例都可以编译和运行。
//! 这些示例专注于实际可用的高级协议功能：
//! 
//! ## Bash 测试代码
//! 
//! ```bash
//! # 编译检查
//! cargo check --example advanced_protocols_guide
//! 
//! # 运行示例
//! cargo run --example advanced_protocols_guide
//! 
//! # 运行所有相关测试
//! cargo test --example advanced_protocols_guide
//! 
//! # 运行特定测试
//! cargo test test_hash_commitment_examples
//! cargo test test_pedersen_commitment_examples
//! cargo test test_merkle_tree_examples
//! cargo test test_application_scenarios
//! 
//! # 性能基准测试
//! cargo bench --bench mpc_benchmarks -- commitment
//! 
//! # 文档生成
//! cargo doc --example advanced_protocols_guide --open
//! ```
//! 
//! ## 运行方式
//! 
//! 1. 作为可执行文件运行所有示例：
//!    ```bash
//!    cargo run --example advanced_protocols_guide
//!    ```
//! 
//! 2. 运行特定的测试用例：
//!    ```bash
//!    cargo test test_hash_commitment_examples
//!    cargo test test_pedersen_commitment_examples
//!    cargo test test_merkle_tree_examples
//!    cargo test test_application_scenarios
//!    ```
//! 
//! 3. 在代码中使用：
//!    ```rust
//!    use mpc_api::examples::advanced_protocols_guide::*;
//!    
//!    // 运行哈希承诺示例
//!    hash_commitment_examples::run_all()?;
//!    
//!    // 或运行单个示例
//!    hash_commitment_examples::basic_hash_commitment()?;
//!    ```
//! 
//! ## 协议功能覆盖
//! 
//! ### 1. 哈希承诺方案 (Hash Commitment Schemes)
//! - **基本承诺**: 单值承诺和验证
//! - **批量承诺**: 多个值的并行承诺处理
//! - **向量承诺**: 整个数组的承诺
//! - **安全特性**: 隐藏性（Hiding）和绑定性（Binding）
//! 
//! ### 2. Pedersen 承诺方案 (Pedersen Commitment Schemes)
//! - **基本承诺**: 基于椭圆曲线的承诺
//! - **同态性质**: 承诺的加法同态
//! - **批量处理**: 多个承诺的高效生成和验证
//! - **完美隐藏**: 信息论级别的隐藏性
//! 
//! ### 3. Merkle 树 (Merkle Trees)
//! - **树构建**: 高效的二进制哈希树构建
//! - **包含证明**: 数据项的存在性证明
//! - **批量验证**: 多个数据项的并行验证
//! - **空间效率**: O(log n) 大小的证明
//! 
//! ### 4. 实际应用场景组合使用
//! - **密封竞价拍卖**: 承诺-揭示模式的实际应用
//! - **数据完整性验证**: Merkle树在区块链中的应用
//! - **秘密投票**: 承诺方案在电子投票中的应用
//! 
//! ## 性能特点
//! 
//! - **哈希承诺**: 计算开销小，验证快速 (~1μs)
//! - **Pedersen承诺**: 支持同态操作，适合代数运算 (~100μs)
//! - **Merkle树**: 对数级证明大小，适合大数据集 (~10μs 验证)
//! 
//! ## 安全注意事项
//! 
//! - 承诺方案的随机数必须保密且唯一
//! - Pedersen承诺依赖离散对数假设
//! - Merkle树的安全性依赖底层哈希函数的抗碰撞性

use mpc_api::{*, Result};

/// 1. 哈希承诺方案演示
/// 
/// 哈希承诺是最基础的承诺方案，基于哈希函数的单向性和抗碰撞性。
/// 
/// ## 工作原理
/// 1. **承诺阶段**: Com(m, r) = H(m || r) 其中 m 是消息，r 是随机数
/// 2. **验证阶段**: 验证者检查 H(m' || r') 是否等于承诺值
/// 
/// ## 安全特性
/// - **隐藏性**: 由哈希函数的单向性保证，无法从承诺推导出原始消息
/// - **绑定性**: 由哈希函数的抗碰撞性保证，无法找到不同的 (m, r) 产生相同承诺
/// 
/// ## 适用场景
/// - 密封拍卖、投票系统、数字签名、零知识证明
/// - 对计算效率要求高的场景
/// - 不需要同态性质的应用
pub mod hash_commitment_examples {
    use super::*;
    
    /// 哈希承诺基本使用
    /// 
    /// 演示最基本的承诺-验证流程，包括：
    /// - 如何生成一个安全的承诺
    /// - 如何验证承诺的正确性
    /// - 如何检测无效的承诺
    /// 
    /// ## 参数说明
    /// - `secret_value`: 需要承诺的秘密值 (u64)
    /// - `randomness`: 随机数，必须保密且唯一
    /// 
    /// ## 安全要求
    /// - 随机数必须真正随机且足够长
    /// - 同一个值不能使用相同的随机数多次承诺
    /// - 随机数在揭示前必须保密
    pub fn basic_hash_commitment() -> Result<()> {
        println!("=== 1.1 哈希承诺基本使用 ===");
        
        let secret_value = 42u64;
        let randomness = 123456u64;
        
        println!("秘密值: {}", secret_value);
        println!("随机数: {}", randomness);
        
        // 创建承诺
        let commitment = HashCommitment::commit_u64(secret_value, randomness);
        println!("承诺创建完成");
        
        // 验证承诺
        let is_valid = HashCommitment::verify_u64(&commitment, secret_value, randomness);
        println!("承诺验证: {}", if is_valid { "有效" } else { "无效" });
        assert!(is_valid);
        
        // 测试错误值
        let wrong_value = 99u64;
        let is_wrong = HashCommitment::verify_u64(&commitment, wrong_value, randomness);
        println!("错误值验证: {}", if is_wrong { "有效" } else { "无效" });
        assert!(!is_wrong);
        
        println!("✓ 哈希承诺基本使用完成\n");
        Ok(())
    }
    
    /// 批量哈希承诺演示
    /// 
    /// 演示如何高效地处理多个值的承诺，这在以下场景中非常有用：
    /// - 多轮拍卖中的批量出价
    /// - 投票系统中的批量投票
    /// - 游戏中的批量策略承诺
    /// 
    /// ## 优势
    /// - **并行处理**: 可以并行生成多个承诺
    /// - **批量验证**: 一次性验证多个承诺的有效性
    /// - **原子性**: 要么全部成功，要么全部失败
    /// 
    /// ## 实现细节
    /// - 使用相同的哈希函数但不同的随机数
    /// - 每个承诺独立，一个失败不影响其他
    /// - 可以选择性地揭示部分承诺
    pub fn batch_commitment() -> Result<()> {
        println!("=== 1.2 批量哈希承诺 ===");
        
        let values = vec![10u64, 20u64, 30u64];
        let randomness = vec![111u64, 222u64, 333u64];
        
        println!("批量承诺 {} 个值", values.len());
        
        // 批量生成承诺
        let commitments = HashCommitment::batch_commit_u64(&values, &randomness)?;
        
        println!("批量承诺生成完成");
        
        // 验证每个承诺
        for (i, (&value, &rand)) in values.iter().zip(randomness.iter()).enumerate() {
            let is_valid = HashCommitment::verify_u64(&commitments[i], value, rand);
            println!("承诺 {}: 值={}, 验证={}", i, value, if is_valid { "✓" } else { "✗" });
            assert!(is_valid);
        }
        
        println!("✓ 批量哈希承诺完成\n");
        Ok(())
    }
    
    /// 向量承诺演示
    /// 
    /// 演示对整个数组/向量的承诺，这是一种特殊的承诺方式：
    /// - 将整个向量作为单一实体进行承诺
    /// - 检测向量中任何元素的修改
    /// - 适用于数据完整性验证
    /// 
    /// ## 与批量承诺的区别
    /// - **向量承诺**: 对整个向量生成一个承诺
    /// - **批量承诺**: 对每个元素分别生成承诺
    /// 
    /// ## 使用场景
    /// - 文件完整性检查
    /// - 数据库记录验证
    /// - 配置文件防篡改
    /// 
    /// ## 安全特性
    /// - 任何位置的修改都会导致承诺验证失败
    /// - 无法部分揭示，必须提供完整向量
    pub fn vector_commitment() -> Result<()> {
        println!("=== 1.3 向量承诺 ===");
        
        let vector = vec![100u64, 200u64, 300u64, 400u64];
        let randomness = 555u64;
        
        println!("向量长度: {}", vector.len());
        println!("向量内容: {:?}", vector);
        
        // 生成向量承诺
        let commitment = HashCommitment::vector_commit_u64(&vector, randomness);
        println!("向量承诺生成完成");
        
        // 验证向量承诺
        let is_valid = HashCommitment::verify_vector_u64(&commitment, &vector, randomness);
        println!("向量承诺验证: {}", if is_valid { "有效" } else { "无效" });
        assert!(is_valid);
        
        // 测试篡改检测
        let mut tampered_vector = vector.clone();
        tampered_vector[1] = 999u64;
        
        let is_tampered = HashCommitment::verify_vector_u64(&commitment, &tampered_vector, randomness);
        println!("篡改检测: {}", if is_tampered { "未检测到" } else { "检测到篡改" });
        assert!(!is_tampered);
        
        println!("✓ 向量承诺完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_hash_commitment()?;
        batch_commitment()?;
        vector_commitment()?;
        Ok(())
    }
}

/// 2. Pedersen 承诺方案演示
/// 
/// Pedersen承诺是基于椭圆曲线离散对数问题的承诺方案，具有独特的数学性质。
/// 
/// ## 工作原理
/// 1. **设置阶段**: 选择椭圆曲线和两个生成元 G, H
/// 2. **承诺阶段**: Com(m, r) = mG + rH 其中 m 是消息，r 是随机数
/// 3. **验证阶段**: 验证者检查提供的 (m', r') 是否满足 m'G + r'H = Com
/// 
/// ## 独特优势
/// - **完美隐藏**: 信息论级别的隐藏性，即使攻击者有无限计算能力
/// - **同态性质**: 承诺支持加法运算 Com(m1) + Com(m2) = Com(m1 + m2)
/// - **可扩展性**: 可以扩展到更复杂的承诺方案
/// 
/// ## 计算开销
/// - 比哈希承诺慢约100倍，但仍然实用
/// - 椭圆曲线运算的复杂度为 O(log n)
/// - 参数生成需要一次性开销
/// 
/// ## 安全假设
/// - 依赖椭圆曲线离散对数问题的困难性
/// - 需要可信的参数生成过程
pub mod pedersen_commitment_examples {
    use super::*;
    
    /// Pedersen 承诺基本使用
    /// 
    /// 演示 Pedersen 承诺的基本工作流程：
    /// 1. 生成系统参数（椭圆曲线参数）
    /// 2. 创建承诺
    /// 3. 验证承诺
    /// 
    /// ## 参数安全性
    /// - 参数生成必须使用可信的随机性
    /// - 生成元G和H之间的离散对数关系必须未知
    /// - 在实际应用中，参数通常通过"可信设置"仪式生成
    /// 
    /// ## 与哈希承诺的比较
    /// - **优点**: 支持同态运算，完美隐藏
    /// - **缺点**: 计算开销较大，需要参数设置
    pub fn basic_pedersen_commitment() -> Result<()> {
        println!("=== 2.1 Pedersen 承诺基本使用 ===");
        
        // 生成参数
        let params = PedersenParams::new()?;
        println!("Pedersen 参数生成完成");
        
        // 创建承诺
        let message = 42u64;
        let randomness = 123456u64;
        
        let commitment = PedersenCommitment::commit_with_params(&params, message, randomness)?;
        println!("消息: {}, 随机数: {}", message, randomness);
        println!("承诺生成完成");
        
        // 验证承诺
        let is_valid = PedersenCommitment::verify_with_params(&params, &commitment, message, randomness)?;
        println!("承诺验证: {}", if is_valid { "有效" } else { "无效" });
        assert!(is_valid);
        
        println!("✓ Pedersen 承诺基本使用完成\n");
        Ok(())
    }
    
    /// Pedersen 承诺同态性质演示
    /// 
    /// 这是 Pedersen 承诺最重要的特性：承诺的加法同态性。
    /// 该性质允许在不揭示原始值的情况下对承诺进行运算。
    /// 
    /// ## 数学原理
    /// ```
    /// Com(m1, r1) = m1*G + r1*H
    /// Com(m2, r2) = m2*G + r2*H
    /// Com(m1, r1) + Com(m2, r2) = (m1+m2)*G + (r1+r2)*H = Com(m1+m2, r1+r2)
    /// ```
    /// 
    /// ## 实际应用
    /// - **隐私保护的投票**: 可以计算总票数而不泄露个人投票
    /// - **多方求和**: 各方提交承诺，可以计算和的承诺
    /// - **零知识证明**: 作为更复杂证明系统的构建块
    /// 
    /// ## 注意事项
    /// - 只支持加法，不支持乘法同态
    /// - 随机数也必须相应地相加
    /// - 结果承诺的验证需要对应的和值
    pub fn homomorphic_properties() -> Result<()> {
        println!("=== 2.2 Pedersen 承诺同态性质 ===");
        
        let params = PedersenParams::new()?;
        
        // 两个消息
        let msg1 = 10u64;
        let msg2 = 20u64;
        let rand1 = 100u64;
        let rand2 = 200u64;
        
        println!("消息1: {}, 消息2: {}", msg1, msg2);
        
        // 生成各自的承诺
        let commit1 = PedersenCommitment::commit_with_params(&params, msg1, rand1)?;
        let commit2 = PedersenCommitment::commit_with_params(&params, msg2, rand2)?;
        
        // 承诺相加（同态加法）
        let sum_commit = PedersenCommitment::add_commitments(&commit1, &commit2)?;
        
        // 验证同态性质
        let sum_msg = field_add(msg1, msg2);
        let sum_rand = field_add(rand1, rand2);
        
        let is_homomorphic = PedersenCommitment::verify_with_params(&params, &sum_commit, sum_msg, sum_rand)?;
        
        println!("同态加法: {} + {} = {}", msg1, msg2, sum_msg);
        println!("同态性质验证: {}", if is_homomorphic { "有效" } else { "无效" });
        assert!(is_homomorphic);
        
        println!("✓ Pedersen 承诺同态性质完成\n");
        Ok(())
    }
    
    /// 批量承诺演示
    pub fn batch_commitment() -> Result<()> {
        println!("=== 2.3 Pedersen 批量承诺 ===");
        
        let params = PedersenParams::new()?;
        
        let messages = vec![11u64, 22u64, 33u64];
        let randomness = vec![111u64, 222u64, 333u64];
        
        println!("批量承诺 {} 个消息", messages.len());
        
        // 批量生成承诺
        let commitments = PedersenCommitment::batch_commit(&params, &messages, &randomness)?;
        
        // 验证每个承诺
        for (i, (&msg, &rand)) in messages.iter().zip(randomness.iter()).enumerate() {
            let is_valid = PedersenCommitment::verify_with_params(&params, &commitments[i], msg, rand)?;
            println!("批量承诺 {}: 消息={}, 验证={}", i, msg, if is_valid { "✓" } else { "✗" });
            assert!(is_valid);
        }
        
        println!("✓ Pedersen 批量承诺完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_pedersen_commitment()?;
        homomorphic_properties()?;
        batch_commitment()?;
        Ok(())
    }
}

/// 3. Merkle 树演示
/// 
/// Merkle树是一种二进制哈希树，用于高效且安全地验证大数据集的完整性。
/// 
/// ## 数据结构
/// ```
///        Root Hash
///       /          \
///   Hash01       Hash23
///   /    \       /    \
/// Hash0 Hash1 Hash2 Hash3
///   |     |     |     |
/// Data0 Data1 Data2 Data3
/// ```
/// 
/// ## 核心优势
/// - **效率**: O(log n) 的证明大小和验证时间
/// - **完整性**: 任何数据修改都会改变根哈希
/// - **可验证性**: 可以验证特定数据项的存在而无需下载整个数据集
/// - **并行化**: 可以并行计算哈希
/// 
/// ## 应用场景
/// - **区块链**: 比特币、以太坊用于交易验证
/// - **分布式系统**: IPFS、BitTorrent 等 P2P 系统
/// - **数据完整性**: 备份系统、云存储验证
/// - **数字签名**: 对大量文档的批量签名
/// 
/// ## 安全特性
/// - 依赖底层哈希函数的抗碰撞性
/// - 树的结构公开，但叶子节点数据可以保密
/// - 支持部分披露：只暴露证明路径上的哈希值
pub mod merkle_tree_examples {
    use super::*;
    
    /// 基本 Merkle 树操作
    /// 
    /// 演示 Merkle 树的基本构建过程：
    /// 1. 从叶子节点（原始数据）开始
    /// 2. 两两配对计算父节点哈希
    /// 3. 递归向上直到根节点
    /// 
    /// ## 构建细节
    /// - 如果叶子节点数量为奇数，最后一个节点会被复制
    /// - 每个内部节点的哈希是其两个子节点哈希的连接后再哈希
    /// - 根哈希唯一标识整个数据集
    /// 
    /// ## 性能考虑
    /// - 构建时间: O(n) 其中 n 是数据项数量
    /// - 空间复杂度: O(n) 存储所有节点
    /// - 实际中可以选择只存储必要的节点
    pub fn basic_merkle_tree() -> Result<()> {
        println!("=== 3.1 基本 Merkle 树操作 ===");
        
        let data_items = vec![
            "数据项 1".as_bytes().to_vec(),
            "数据项 2".as_bytes().to_vec(), 
            "数据项 3".as_bytes().to_vec(),
            "数据项 4".as_bytes().to_vec(),
        ];
        
        println!("构建包含 {} 个数据项的 Merkle 树", data_items.len());
        for (i, item) in data_items.iter().enumerate() {
            println!("  项目 {}: {}", i, String::from_utf8_lossy(item));
        }
        
        // 构建 Merkle 树
        let merkle_tree = MerkleTree::new(&data_items)?;
        let root_hash = merkle_tree.get_root();
        
        println!("Merkle 树构建完成");
        println!("树深度: {}", merkle_tree.get_depth());
        println!("根哈希: {:02x?}", &root_hash[0..8]); // 显示前8字节
        
        println!("✓ 基本 Merkle 树操作完成\n");
        Ok(())
    }
    
    /// 包含证明演示
    pub fn inclusion_proof() -> Result<()> {
        println!("=== 3.2 Merkle 树包含证明 ===");
        
        let data_items = vec![
            "交易记录 A".as_bytes().to_vec(),
            "交易记录 B".as_bytes().to_vec(),
            "交易记录 C".as_bytes().to_vec(),
            "交易记录 D".as_bytes().to_vec(),
        ];
        
        let merkle_tree = MerkleTree::new(&data_items)?;
        let root_hash = merkle_tree.get_root();
        
        // 为第2个数据项生成包含证明
        let prove_index = 1;
        let proof = merkle_tree.generate_proof(prove_index)?;
        
        println!("为索引 {} 生成包含证明", prove_index);
        println!("数据项: {}", String::from_utf8_lossy(&data_items[prove_index]));
        println!("证明路径长度: {}", proof.path.len());
        
        // 验证包含证明
        let is_included = MerkleTree::verify_proof(
            root_hash,
            &data_items[prove_index],
            &proof
        )?;
        
        println!("包含证明验证: {}", if is_included { "有效" } else { "无效" });
        assert!(is_included);
        
        // 测试错误数据的证明
        let fake_data = "伪造数据".as_bytes();
        let is_fake = MerkleTree::verify_proof(root_hash, fake_data, &proof)?;
        println!("伪造数据验证: {}", if is_fake { "有效" } else { "无效" });
        assert!(!is_fake);
        
        println!("✓ Merkle 树包含证明完成\n");
        Ok(())
    }
    
    /// 批量验证演示
    pub fn batch_verification() -> Result<()> {
        println!("=== 3.3 Merkle 树批量验证 ===");
        
        let data_items = vec![
            "批量数据 1".as_bytes().to_vec(),
            "批量数据 2".as_bytes().to_vec(),
            "批量数据 3".as_bytes().to_vec(),
            "批量数据 4".as_bytes().to_vec(),
            "批量数据 5".as_bytes().to_vec(),
            "批量数据 6".as_bytes().to_vec(),
        ];
        
        let merkle_tree = MerkleTree::new(&data_items)?;
        let root_hash = merkle_tree.get_root();
        
        println!("批量验证 {} 个数据项的包含证明", data_items.len());
        
        // 为所有数据项生成和验证证明
        for i in 0..data_items.len() {
            let proof = merkle_tree.generate_proof(i)?;
            let is_valid = MerkleTree::verify_proof(root_hash, &data_items[i], &proof)?;
            
            println!("  项目 {}: {} {}", i, 
                     String::from_utf8_lossy(&data_items[i]), 
                     if is_valid { "✓" } else { "✗" });
            assert!(is_valid);
        }
        
        println!("✓ Merkle 树批量验证完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_merkle_tree()?;
        inclusion_proof()?;
        batch_verification()?;
        Ok(())
    }
}

/// 4. 应用场景演示
pub mod application_scenarios {
    use super::*;
    
    /// 密封竞价拍卖
    pub fn sealed_bid_auction() -> Result<()> {
        println!("=== 4.1 密封竞价拍卖 ===");
        
        let bidders = vec!["Alice", "Bob", "Charlie"];
        let bids = vec![1000u64, 1500u64, 1200u64];
        
        println!("拍卖参与者:");
        for (bidder, &bid) in bidders.iter().zip(bids.iter()) {
            println!("  {}: ${} (保密)", bidder, bid);
        }
        
        // 承诺阶段 - 每个投标者创建承诺
        let mut commitments = Vec::new();
        let mut nonces = Vec::new();
        
        println!("\n承诺阶段:");
        for (bidder, &bid) in bidders.iter().zip(bids.iter()) {
            let (nonce, commitment) = HashCommitment::auto_commit_u64(bid);
            commitments.push(commitment);
            nonces.push(nonce);
            println!("  {} 提交承诺", bidder);
        }
        
        // 揭示阶段 - 验证所有承诺
        println!("\n揭示阶段:");
        for (i, (bidder, &bid)) in bidders.iter().zip(bids.iter()).enumerate() {
            let is_valid = HashCommitment::verify_u64(&commitments[i], bid, nonces[i]);
            println!("  {} 出价 ${}: {}", bidder, bid, if is_valid { "有效" } else { "无效" });
            assert!(is_valid);
        }
        
        // 确定获胜者
        let max_bid = *bids.iter().max().unwrap();
        let winner_index = bids.iter().position(|&x| x == max_bid).unwrap();
        
        println!("\n拍卖结果:");
        println!("  获胜者: {}", bidders[winner_index]);
        println!("  获胜出价: ${}", max_bid);
        
        println!("✓ 密封竞价拍卖完成\n");
        Ok(())
    }
    
    /// 数据完整性验证
    pub fn data_integrity_verification() -> Result<()> {
        println!("=== 4.2 数据完整性验证 ===");
        
        // 模拟区块链交易数据
        let transactions = vec![
            "Alice -> Bob: $100".as_bytes().to_vec(),
            "Bob -> Charlie: $50".as_bytes().to_vec(),
            "Charlie -> Dave: $25".as_bytes().to_vec(),
            "Dave -> Alice: $75".as_bytes().to_vec(),
            "Alice -> Eve: $200".as_bytes().to_vec(),
        ];
        
        println!("构建交易 Merkle 树:");
        for (i, tx) in transactions.iter().enumerate() {
            println!("  交易 {}: {}", i, String::from_utf8_lossy(tx));
        }
        
        // 构建 Merkle 树
        let merkle_tree = MerkleTree::new(&transactions)?;
        let root_hash = merkle_tree.get_root();
        
        println!("Merkle 根哈希: {:02x?}", &root_hash[0..8]);
        
        // 模拟轻节点验证特定交易
        let verify_tx_index = 2;
        let proof = merkle_tree.generate_proof(verify_tx_index)?;
        
        println!("\n轻节点验证交易 {}:", verify_tx_index);
        println!("  交易内容: {}", String::from_utf8_lossy(&transactions[verify_tx_index]));
        
        // 验证包含性
        let is_included = MerkleTree::verify_proof(
            root_hash,
            &transactions[verify_tx_index],
            &proof
        )?;
        
        println!("  验证结果: {}", if is_included { "交易存在于区块中" } else { "交易不存在" });
        assert!(is_included);
        
        println!("✓ 数据完整性验证完成\n");
        Ok(())
    }
    
    /// 秘密投票
    pub fn secret_voting() -> Result<()> {
        println!("=== 4.3 秘密投票 ===");
        
        let voters = vec!["选民A", "选民B", "选民C", "选民D"];
        let votes = vec![1u64, 0u64, 1u64, 1u64]; // 1=赞成, 0=反对
        
        println!("秘密投票系统:");
        println!("  选民数量: {}", voters.len());
        
        // 承诺阶段 - 每个选民对投票创建承诺
        let mut vote_commitments = Vec::new();
        let mut vote_nonces = Vec::new();
        
        println!("\n投票承诺阶段:");
        for (voter, &vote) in voters.iter().zip(votes.iter()) {
            let (nonce, commitment) = HashCommitment::auto_commit_u64(vote);
            vote_commitments.push(commitment);
            vote_nonces.push(nonce);
            println!("  {} 提交投票承诺", voter);
        }
        
        // 计票阶段 - 揭示并统计
        println!("\n计票阶段:");
        let mut yes_count = 0u64;
        let mut no_count = 0u64;
        
        for (i, (voter, &vote)) in voters.iter().zip(votes.iter()).enumerate() {
            let is_valid = HashCommitment::verify_u64(&vote_commitments[i], vote, vote_nonces[i]);
            
            if is_valid {
                if vote == 1 {
                    yes_count += 1;
                    println!("  {} 投票: 赞成", voter);
                } else {
                    no_count += 1;
                    println!("  {} 投票: 反对", voter);
                }
            } else {
                println!("  {} 投票无效", voter);
            }
        }
        
        // 公布结果
        println!("\n投票结果:");
        println!("  赞成: {} 票", yes_count);
        println!("  反对: {} 票", no_count);
        println!("  结果: {}", if yes_count > no_count { "提案通过" } else { "提案未通过" });
        
        println!("✓ 秘密投票完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        sealed_bid_auction()?;
        data_integrity_verification()?;
        secret_voting()?;
        Ok(())
    }
}

/// 运行所有高级协议指南
pub fn run_advanced_protocols_guide() -> Result<()> {
    println!("🚀 === 高级协议使用指南 ===\n");
    
    hash_commitment_examples::run_all()?;
    pedersen_commitment_examples::run_all()?;
    merkle_tree_examples::run_all()?;
    application_scenarios::run_all()?;
    
    println!("🎉 === 高级协议指南演示完成 ===");
    println!("📝 指南总结:");
    println!("  ✓ 哈希承诺 - 基本、批量、向量承诺");
    println!("  ✓ Pedersen承诺 - 基本、同态性质、批量承诺");  
    println!("  ✓ Merkle树 - 构建、包含证明、批量验证");
    println!("  ✓ 应用场景 - 密封拍卖、数据完整性、秘密投票");
    println!("\n你现在已经掌握了MPC中所有高级协议的使用方法。");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_commitment_examples() {
        hash_commitment_examples::run_all().unwrap();
    }
    
    #[test]
    fn test_pedersen_commitment_examples() {
        pedersen_commitment_examples::run_all().unwrap();
    }
    
    #[test]
    fn test_merkle_tree_examples() {
        merkle_tree_examples::run_all().unwrap();
    }
    
    #[test]
    fn test_application_scenarios() {
        application_scenarios::run_all().unwrap();
    }
}

/// # 使用指南和最佳实践
/// 
/// ## 快速开始
/// 
/// ### 1. 选择合适的承诺方案
/// 
/// | 需求 | 推荐方案 | 理由 |
/// |------|----------|------|
/// | 高性能，简单验证 | 哈希承诺 | 计算快速，实现简单 |
/// | 需要同态运算 | Pedersen承诺 | 支持加法同态 |
/// | 大数据集验证 | Merkle树 | 对数级证明大小 |
/// | 批量处理 | 哈希承诺批量 | 并行性能好 |
/// 
/// ### 2. 安全参数选择
/// 
/// ```rust
/// // 哈希承诺：使用足够长的随机数
/// let randomness = rand::thread_rng().gen::<u64>();  // 最少64位
/// 
/// // Pedersen承诺：使用安全的椭圆曲线
/// let params = PedersenParams::new()?;  // 内部使用256位曲线
/// 
/// // Merkle树：选择抗碰撞的哈希函数
/// let tree = MerkleTree::new(&data)?;  // 内部使用SHA-256
/// ```
/// 
/// ### 3. 性能优化建议
/// 
/// ```rust
/// // 批量操作比单个操作更高效
/// let commitments = HashCommitment::batch_commit_u64(&values, &randomness)?;
/// 
/// // 预生成随机数以提高实时性能
/// let random_pool: Vec<u64> = (0..1000).map(|_| rand::random()).collect();
/// 
/// // 对于Merkle树，考虑缓存中间节点
/// let tree = MerkleTree::new(&data)?;
/// let cached_root = tree.get_root();  // 缓存根哈希
/// ```
/// 
/// ### 4. 常见错误和解决方案
/// 
/// #### 错误1：重复使用随机数
/// ```rust
/// // ❌ 错误：相同随机数的重复使用
/// let rand = 12345u64;
/// let com1 = HashCommitment::commit_u64(value1, rand);
/// let com2 = HashCommitment::commit_u64(value2, rand);  // 不安全！
/// 
/// // ✅ 正确：每次使用不同的随机数
/// let rand1 = rand::random::<u64>();
/// let rand2 = rand::random::<u64>();
/// let com1 = HashCommitment::commit_u64(value1, rand1);
/// let com2 = HashCommitment::commit_u64(value2, rand2);
/// ```
/// 
/// #### 错误2：忽略参数验证
/// ```rust
/// // ❌ 错误：未验证Pedersen参数
/// let params = PedersenParams::new()?;
/// // 直接使用params，没有验证其正确性
/// 
/// // ✅ 正确：验证参数
/// let params = PedersenParams::new()?;
/// assert!(params.validate()?);  // 验证参数有效性
/// ```
/// 
/// #### 错误3：不安全的随机数生成
/// ```rust
/// // ❌ 错误：使用固定或可预测的随机数
/// let rand = 12345u64;  // 固定值
/// 
/// // ✅ 正确：使用密码学安全的随机数生成器
/// use rand::{thread_rng, Rng};
/// let rand = thread_rng().gen::<u64>();
/// ```
/// 
/// ### 5. 实际部署考虑
/// 
/// #### 网络通信
/// ```rust
/// // 序列化承诺进行网络传输
/// let commitment = HashCommitment::commit_u64(value, randomness);
/// let serialized = serde_json::to_string(&commitment)?;
/// 
/// // 接收方反序列化
/// let received_commitment: HashCommitment = serde_json::from_str(&serialized)?;
/// ```
/// 
/// #### 持久化存储
/// ```rust
/// // 安全存储承诺和随机数
/// struct StoredCommitment {
///     commitment: HashCommitment,
///     randomness: u64,  // 注意：随机数必须安全存储
///     timestamp: u64,
/// }
/// ```
/// 
/// #### 并发安全
/// ```rust
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// 
/// // 在多线程环境中安全使用
/// let params = Arc::new(PedersenParams::new()?);
/// let shared_params = params.clone();  // 参数可以安全共享
/// ```
/// 
/// ### 6. 错误处理模式
/// 
/// ```rust
/// use mpc_api::Result;
/// 
/// fn robust_commitment_verification(
///     commitment: &HashCommitment,
///     value: u64,
///     randomness: u64
/// ) -> Result<bool> {
///     // 添加输入验证
///     if randomness == 0 {
///         return Err("随机数不能为零".into());
///     }
///     
///     // 验证承诺
///     let is_valid = HashCommitment::verify_u64(commitment, value, randomness);
///     
///     // 记录验证结果（用于调试）
///     if !is_valid {
///         eprintln!("承诺验证失败: value={}, randomness={}", value, randomness);
///     }
///     
///     Ok(is_valid)
/// }
/// ```
/// 
/// ### 7. 测试策略
/// 
/// ```rust
/// #[cfg(test)]
/// mod comprehensive_tests {
///     use super::*;
///     
///     #[test]
///     fn test_commitment_security_properties() {
///         // 测试隐藏性：相同值不同随机数应产生不同承诺
///         let value = 42u64;
///         let rand1 = rand::random::<u64>();
///         let rand2 = rand::random::<u64>();
///         
///         let com1 = HashCommitment::commit_u64(value, rand1);
///         let com2 = HashCommitment::commit_u64(value, rand2);
///         
///         assert_ne!(com1, com2);  // 承诺应该不同
///     }
///     
///     #[test]
///     fn test_batch_consistency() {
///         // 测试批量操作与单个操作的一致性
///         let values = vec![1u64, 2u64, 3u64];
///         let randomness = vec![10u64, 20u64, 30u64];
///         
///         let batch_commits = HashCommitment::batch_commit_u64(&values, &randomness).unwrap();
///         
///         for i in 0..values.len() {
///             let single_commit = HashCommitment::commit_u64(values[i], randomness[i]);
///             assert_eq!(batch_commits[i], single_commit);
///         }
///     }
/// }
/// ```

// 如果直接运行此文件，执行所有高级协议指南
fn main() -> Result<()> {
    run_advanced_protocols_guide()
}