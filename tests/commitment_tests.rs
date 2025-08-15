//! 承诺方案测试
//! 
//! 本文件包含对MPC API承诺模块的全面测试，覆盖以下承诺方案：
//! - Hash承诺 (Hash Commitment) - 基于密码学哈希函数的承诺
//! - Pedersen承诺 (Pedersen Commitment) - 基于椭圆曲线的同态承诺
//! - Merkle树承诺 (Merkle Tree Commitment) - 基于Merkle树的批量承诺
//! 
//! 承诺方案是密码学的基础原语，提供隐藏性和绑定性保证：
//! - 隐藏性：承诺不会泄露承诺值的信息
//! - 绑定性：承诺者无法改变已承诺的值

use mpc_api::commitment::*;
use mpc_api::secret_sharing::field_add;

// ===== Hash Commitment Tests =====
// Hash承诺使用密码学哈希函数实现，简单高效，适用于大多数承诺场景

/// 测试Hash承诺的基本提交和验证流程
/// 
/// 目的：验证Hash承诺的核心功能：提交 -> 验证
/// 预期：使用相同消息和随机数的承诺应该能够通过验证
#[test]
fn test_hash_commitment_basic() {
    let message = b"Hello, World!";
    let randomness = HashCommitment::generate_randomness(32);
    
    // 使用消息和随机数创建承诺
    let commitment = HashCommitment::commit(message.to_vec(), randomness.clone());
    // 验证承诺的正确性
    let verification = HashCommitment::verify(commitment, message.to_vec(), randomness);
    
    // 验证应该成功
    assert!(verification);
}

/// 测试Hash承诺对64位整数的专用提交功能
/// 
/// 目的：验证Hash承诺能够直接处理u64类型数据
/// 预期：64位整数的承诺和验证应该成功
#[test]
fn test_hash_commitment_u64() {
    let value = 12345u64;
    let randomness = 67890u64;
    
    // 对u64值创建承诺
    let commitment = HashCommitment::commit_u64(value, randomness);
    // 验证u64承诺
    let verification = HashCommitment::verify_u64(&commitment, value, randomness);
    
    // 验证应该成功
    assert!(verification);
}

/// 测试Hash承诺的绑定性（使用错误值验证）
/// 
/// 目的：验证Hash承诺能够检测到值被篡改，确保绑定性
/// 预期：使用错误值验证相同承诺时应该失败
#[test]
fn test_hash_commitment_wrong_value() {
    let value = 12345u64;
    let wrong_value = 12346u64;
    let randomness = 67890u64;
    
    // 使用原始值创建承诺
    let commitment = HashCommitment::commit_u64(value, randomness);
    // 尝试用错误值验证 - 应该失败
    let verification = HashCommitment::verify_u64(&commitment, wrong_value, randomness);
    
    // 验证应该失败，确保绑定性
    assert!(!verification);
}

/// 测试Hash承诺对随机数的敏感性
/// 
/// 目的：验证Hash承诺能够检测到随机数被篡改
/// 预期：使用错误随机数验证时应该失败
#[test]
fn test_hash_commitment_wrong_randomness() {
    let value = 12345u64;
    let randomness = 67890u64;
    let wrong_randomness = 67891u64;
    
    // 使用原始随机数创建承诺
    let commitment = HashCommitment::commit_u64(value, randomness);
    // 尝试用错误随机数验证 - 应该失败
    let verification = HashCommitment::verify_u64(&commitment, value, wrong_randomness);
    
    // 验证应该失败，确保随机数完整性
    assert!(!verification);
}

#[test]
fn test_hash_commitment_string() {
    let message = "Secret message";
    let randomness = HashCommitment::generate_randomness(16);
    
    let commitment = HashCommitment::commit_string(message, &randomness);
    let verification = HashCommitment::verify_string(&commitment, message, &randomness);
    
    assert!(verification);
}

/// 测试Hash承诺的批量操作功能
/// 
/// 目的：验证Hash承诺能够高效地批量处理多个值的承诺
/// 预期：批量承诺应该生成正确数量的承诺，每个都能通过验证
#[test]
fn test_hash_commitment_batch() {
    let values = vec![10u64, 20u64, 30u64];
    let randomness = vec![100u64, 200u64, 300u64];
    
    // 批量创建承诺
    let commitments = HashCommitment::batch_commit_u64(&values, &randomness).unwrap();
    
    assert_eq!(commitments.len(), 3); // 确保生成了正确数量的承诺
    
    // 验证每个承诺
    for (i, (value, rand)) in values.iter().zip(randomness.iter()).enumerate() {
        let verification = HashCommitment::verify_u64(&commitments[i], *value, *rand);
        assert!(verification); // 每个承诺都应该通过验证
    }
}

#[test]
fn test_hash_commitment_vector() {
    let values = vec![10u64, 20u64, 30u64];
    let randomness = 500u64;
    
    let commitment = HashCommitment::vector_commit_u64(&values, randomness);
    let verification = HashCommitment::verify_vector_u64(&commitment, &values, randomness);
    
    assert!(verification);
}

#[test]
fn test_hash_commitment_merkle() {
    let data = vec![
        b"data1".to_vec(),
        b"data2".to_vec(),
        b"data3".to_vec(),
        b"data4".to_vec(),
    ];
    
    let commitment = HashCommitment::merkle_commit(&data).unwrap();
    assert_eq!(commitment.len(), 32);
}

#[test]
fn test_hash_commitment_auto() {
    let value = 42u64;
    let (randomness, commitment) = HashCommitment::auto_commit_u64(value);
    
    let verification = HashCommitment::verify_u64(&commitment, value, randomness);
    assert!(verification);
}

#[test]
fn test_hash_commitment_secret_share() {
    let share_value = 123u64;
    let share_index = 1usize;
    let randomness = 456u64;
    
    let commitment = HashCommitment::commit_secret_share(share_value, share_index, randomness);
    let verification = HashCommitment::verify_secret_share(&commitment, share_value, share_index, randomness);
    
    assert!(verification);
}

#[test]
fn test_hash_commitment_different_messages() {
    let randomness = 12345u64;
    
    let commit1 = HashCommitment::commit_u64(100, randomness);
    let commit2 = HashCommitment::commit_u64(101, randomness);
    
    // Different messages should produce different commitments
    assert_ne!(commit1, commit2);
}

#[test]
fn test_hash_commitment_same_message_different_randomness() {
    let value = 100u64;
    
    let commit1 = HashCommitment::commit_u64(value, 123);
    let commit2 = HashCommitment::commit_u64(value, 124);
    
    // Same message with different randomness should produce different commitments
    assert_ne!(commit1, commit2);
}

// ===== Pedersen Commitment Tests =====
// Pedersen承诺基于椭圆曲线离散对数问题，提供完美的隐藏性和计算绑定性，并支持同态运算

/// 测试Pedersen承诺的基本提交和验证流程
/// 
/// 目的：验证Pedersen承诺的核心功能：提交 -> 验证
/// 预期：使用相同消息和随机数的承诺应该能够通过验证
#[test]
fn test_pedersen_commitment_basic() {
    let message = 42u64;
    let randomness = 123u64;
    
    // 使用默认参数创建承诺
    let commitment = PedersenCommitment::commit(message, randomness);
    // 验证承诺的正确性
    let verification = PedersenCommitment::verify(commitment, message, randomness);
    
    // 验证应该成功
    assert!(verification);
}

/// 测试Pedersen承诺使用自定义参数的功能
/// 
/// 目的：验证Pedersen承诺能够使用用户提供的椭圆曲线参数
/// 预期：使用自定义参数的承诺和验证应该成功
#[test]
fn test_pedersen_commitment_with_params() {
    let params = PedersenParams::new().unwrap(); // 生成椭圆曲线参数
    let message = 42u64;
    let randomness = 123u64;
    
    // 使用指定参数创建承诺
    let commitment = PedersenCommitment::commit_with_params(&params, message, randomness).unwrap();
    // 使用相同参数验证承诺
    let verification = PedersenCommitment::verify_with_params(&params, &commitment, message, randomness).unwrap();
    
    // 验证应该成功
    assert!(verification);
}

#[test]
fn test_pedersen_commitment_wrong_message() {
    let params = PedersenParams::new().unwrap();
    let message = 42u64;
    let wrong_message = 43u64;
    let randomness = 123u64;
    
    let commitment = PedersenCommitment::commit_with_params(&params, message, randomness).unwrap();
    let verification = PedersenCommitment::verify_with_params(&params, &commitment, wrong_message, randomness).unwrap();
    
    assert!(!verification);
}

#[test]
fn test_pedersen_commitment_wrong_randomness() {
    let params = PedersenParams::new().unwrap();
    let message = 42u64;
    let randomness = 123u64;
    let wrong_randomness = 124u64;
    
    let commitment = PedersenCommitment::commit_with_params(&params, message, randomness).unwrap();
    let verification = PedersenCommitment::verify_with_params(&params, &commitment, message, wrong_randomness).unwrap();
    
    assert!(!verification);
}

/// 测试Pedersen承诺的同态加法特性
/// 
/// 目的：验证Pedersen承诺支持同态运算，C(m1)+C(m2)=C(m1+m2)
/// 预期：两个承诺的加法结果应等于消息和的承诺
#[test]
fn test_pedersen_commitment_homomorphic_addition() {
    let params = PedersenParams::new().unwrap();
    
    let message1 = 10u64;
    let randomness1 = 20u64;
    let commit1 = PedersenCommitment::commit_with_params(&params, message1, randomness1).unwrap();
    
    let message2 = 15u64;
    let randomness2 = 25u64;
    let commit2 = PedersenCommitment::commit_with_params(&params, message2, randomness2).unwrap();
    
    // 执行承诺的同态加法
    let combined_commit = PedersenCommitment::add_commitments(&commit1, &commit2).unwrap();
    
    // 验证同态性：计算消息和的承诺
    let combined_message = field_add(message1, message2);
    let combined_randomness = field_add(randomness1, randomness2);
    let expected_commit = PedersenCommitment::commit_with_params(&params, combined_message, combined_randomness).unwrap();
    
    // 两种方式应该产生相同的承诺
    assert_eq!(combined_commit, expected_commit);
}

#[test]
fn test_pedersen_commitment_batch() {
    let params = PedersenParams::new().unwrap();
    let messages = vec![10u64, 20u64, 30u64];
    let randomness = vec![100u64, 200u64, 300u64];
    
    let commitments = PedersenCommitment::batch_commit(&params, &messages, &randomness).unwrap();
    
    assert_eq!(commitments.len(), 3);
    
    // Verify each commitment
    for (i, (msg, rand)) in messages.iter().zip(randomness.iter()).enumerate() {
        let verification = PedersenCommitment::verify_with_params(&params, &commitments[i], *msg, *rand).unwrap();
        assert!(verification);
    }
}

#[test]
fn test_pedersen_commitment_vector() {
    let params = PedersenParams::new().unwrap();
    let messages = vec![10u64, 20u64, 30u64];
    let randomness = 500u64;
    
    let vector_commit = PedersenCommitment::vector_commit(&params, &messages, randomness).unwrap();
    
    // Verify vector commitment
    let total_message = messages.iter().fold(0u64, |acc, &msg| field_add(acc, msg));
    let expected_commit = PedersenCommitment::commit_with_params(&params, total_message, randomness).unwrap();
    
    assert_eq!(vector_commit, expected_commit);
}

#[test]
fn test_pedersen_generate_random_commitment() {
    let (message, randomness, commitment) = PedersenCommitment::generate_random_commitment().unwrap();
    
    let verification = PedersenCommitment::verify(commitment, message, randomness);
    assert!(verification);
}

#[test]
fn test_pedersen_add_message_to_commitment() {
    let params = PedersenParams::new().unwrap();
    
    let initial_message = 100u64;
    let initial_randomness = 200u64;
    let initial_commit = PedersenCommitment::commit_with_params(&params, initial_message, initial_randomness).unwrap();
    
    let additional_message = 50u64;
    let additional_randomness = 75u64;
    
    let updated_commit = PedersenCommitment::add_message_to_commitment(
        &params,
        &initial_commit,
        additional_message,
        additional_randomness,
    ).unwrap();
    
    // Verify updated commitment
    let total_message = field_add(initial_message, additional_message);
    let total_randomness = field_add(initial_randomness, additional_randomness);
    let verification = PedersenCommitment::verify_with_params(&params, &updated_commit, total_message, total_randomness).unwrap();
    
    assert!(verification);
}

// ===== Merkle Tree Tests =====
// Merkle树是一种二叉树结构，用于高效验证大量数据的完整性，广泛应用于区块链和分布式系统

/// 测试Merkle树的创建和基本属性
/// 
/// 目的：验证Merkle树能够正确创建并返回正确的叶子节点数和根哈希
/// 预期：树应该包含正确数量的叶子节点，根哈希长度为32字节
#[test]
fn test_merkle_tree_creation() {
    let data = vec![
        b"data1".to_vec(),
        b"data2".to_vec(),
        b"data3".to_vec(),
        b"data4".to_vec(),
    ];
    
    // 创建Merkle树
    let tree = MerkleTree::new(&data).unwrap();
    assert_eq!(tree.get_leaf_count(), 4); // 验证叶子节点数量
    assert_eq!(tree.get_root().len(), 32); // 验证根哈希长度(SHA-256)
}

/// 测试Merkle证明的生成和验证功能
/// 
/// 目的：验证Merkle树能够为任意叶子节点生成有效的包含性证明
/// 预期：每个叶子节点的证明都应该能够通过验证
#[test]
fn test_merkle_proof_generation_and_verification() {
    let data = vec![
        b"data1".to_vec(),
        b"data2".to_vec(),
        b"data3".to_vec(),
        b"data4".to_vec(),
    ];
    
    let tree = MerkleTree::new(&data).unwrap();
    let root = *tree.get_root();
    
    // 为每个叶子节点测试证明生成和验证
    for i in 0..data.len() {
        let proof = tree.generate_proof(i).unwrap(); // 生成包含性证明
        let verification = MerkleTree::verify_proof(&root, &data[i], &proof).unwrap(); // 验证证明
        assert!(verification); // 每个证明都应该有效
    }
}

#[test]
fn test_merkle_proof_invalid_data() {
    let data = vec![
        b"data1".to_vec(),
        b"data2".to_vec(),
        b"data3".to_vec(),
    ];
    
    let tree = MerkleTree::new(&data).unwrap();
    let root = *tree.get_root();
    let proof = tree.generate_proof(0).unwrap();
    
    // Try to verify with wrong data
    let verification = MerkleTree::verify_proof(&root, b"wrong_data", &proof).unwrap();
    assert!(!verification);
}

#[test]
fn test_merkle_tree_update() {
    let data = vec![
        b"data1".to_vec(),
        b"data2".to_vec(),
        b"data3".to_vec(),
    ];
    
    let mut tree = MerkleTree::new(&data).unwrap();
    let original_root = *tree.get_root();
    
    // Update a leaf
    tree.update_leaf(1, b"new_data2").unwrap();
    let new_root = *tree.get_root();
    
    assert_ne!(original_root, new_root);
    
    // Verify new proof
    let proof = tree.generate_proof(1).unwrap();
    let verification = MerkleTree::verify_proof(&new_root, b"new_data2", &proof).unwrap();
    assert!(verification);
}

#[test]
fn test_merkle_commitment_scheme() {
    let data = vec![
        b"message1".to_vec(),
        b"message2".to_vec(),
        b"message3".to_vec(),
    ];
    
    let commitment = MerkleCommitment::commit(data.clone(), ());
    let verification = MerkleCommitment::verify(commitment, data, ());
    
    assert!(verification);
}

#[test]
fn test_batch_merkle_commitment() {
    let data = vec![
        b"item1".to_vec(),
        b"item2".to_vec(),
        b"item3".to_vec(),
        b"item4".to_vec(),
    ];
    
    let batch = BatchMerkleCommitment::new(data.clone()).unwrap();
    let commitment = *batch.get_commitment();
    
    // Test inclusion proof
    let (proven_data, proof) = batch.prove_inclusion(1).unwrap();
    assert_eq!(proven_data, b"item2".to_vec());
    
    let verification = BatchMerkleCommitment::verify_inclusion(&commitment, &proven_data, &proof).unwrap();
    assert!(verification);
}

#[test]
fn test_batch_merkle_commitment_update() {
    let data = vec![
        b"item1".to_vec(),
        b"item2".to_vec(),
        b"item3".to_vec(),
    ];
    
    let mut batch = BatchMerkleCommitment::new(data).unwrap();
    let original_commitment = *batch.get_commitment();
    
    // Update data
    batch.update_data(1, b"new_item2".to_vec()).unwrap();
    let new_commitment = *batch.get_commitment();
    
    assert_ne!(original_commitment, new_commitment);
    
    // Verify updated data
    let (proven_data, proof) = batch.prove_inclusion(1).unwrap();
    assert_eq!(proven_data, b"new_item2".to_vec());
    
    let verification = BatchMerkleCommitment::verify_inclusion(&new_commitment, &proven_data, &proof).unwrap();
    assert!(verification);
}

#[test]
fn test_merkle_tree_odd_number_of_leaves() {
    let data = vec![
        b"data1".to_vec(),
        b"data2".to_vec(),
        b"data3".to_vec(),
    ];
    
    let tree = MerkleTree::new(&data).unwrap();
    assert_eq!(tree.get_leaf_count(), 3);
    
    // Test proofs for all leaves
    for i in 0..data.len() {
        let proof = tree.generate_proof(i).unwrap();
        let verification = MerkleTree::verify_proof(tree.get_root(), &data[i], &proof).unwrap();
        assert!(verification);
    }
}

#[test]
fn test_merkle_tree_single_leaf() {
    let data = vec![b"single_data".to_vec()];
    
    let tree = MerkleTree::new(&data).unwrap();
    assert_eq!(tree.get_leaf_count(), 1);
    
    let proof = tree.generate_proof(0).unwrap();
    let verification = MerkleTree::verify_proof(tree.get_root(), &data[0], &proof).unwrap();
    assert!(verification);
}