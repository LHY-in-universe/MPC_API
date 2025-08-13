//! # 高级协议使用指南
//! 
//! 详细展示MPC API中高级协议的使用方法，所有示例都可以编译和运行。
//! 这些示例专注于实际可用的高级协议功能：
//! 1. 哈希承诺方案 (Hash Commitment Schemes)
//! 2. Pedersen 承诺方案 (Pedersen Commitment Schemes)  
//! 3. Merkle 树 (Merkle Trees)
//! 4. 实际应用场景组合使用

use mpc_api::{*, Result};

/// 1. 哈希承诺方案演示
pub mod hash_commitment_examples {
    use super::*;
    
    /// 哈希承诺基本使用
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
    
    /// 批量承诺演示
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
pub mod pedersen_commitment_examples {
    use super::*;
    
    /// Pedersen 承诺基本使用
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
    
    /// 同态性质演示
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
pub mod merkle_tree_examples {
    use super::*;
    
    /// 基本 Merkle 树操作
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

// 如果直接运行此文件，执行所有高级协议指南
fn main() -> Result<()> {
    run_advanced_protocols_guide()
}