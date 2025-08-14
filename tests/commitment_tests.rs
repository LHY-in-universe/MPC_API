//! 承诺方案测试
//! 
//! 包含 Hash 承诺, Pedersen 承诺, Merkle 树等承诺方案的测试

use mpc_api::commitment::*;
use mpc_api::secret_sharing::field_add;
use mpc_api::Result;

// ===== Hash Commitment Tests =====

#[test]
fn test_hash_commitment_basic() {
    let message = b"Hello, World!";
    let randomness = HashCommitment::generate_randomness(32);
    
    let commitment = HashCommitment::commit(message.to_vec(), randomness.clone());
    let verification = HashCommitment::verify(commitment, message.to_vec(), randomness);
    
    assert!(verification);
}

#[test]
fn test_hash_commitment_u64() {
    let value = 12345u64;
    let randomness = 67890u64;
    
    let commitment = HashCommitment::commit_u64(value, randomness);
    let verification = HashCommitment::verify_u64(&commitment, value, randomness);
    
    assert!(verification);
}

#[test]
fn test_hash_commitment_wrong_value() {
    let value = 12345u64;
    let wrong_value = 12346u64;
    let randomness = 67890u64;
    
    let commitment = HashCommitment::commit_u64(value, randomness);
    let verification = HashCommitment::verify_u64(&commitment, wrong_value, randomness);
    
    assert!(!verification);
}

#[test]
fn test_hash_commitment_wrong_randomness() {
    let value = 12345u64;
    let randomness = 67890u64;
    let wrong_randomness = 67891u64;
    
    let commitment = HashCommitment::commit_u64(value, randomness);
    let verification = HashCommitment::verify_u64(&commitment, value, wrong_randomness);
    
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

#[test]
fn test_hash_commitment_batch() {
    let values = vec![10u64, 20u64, 30u64];
    let randomness = vec![100u64, 200u64, 300u64];
    
    let commitments = HashCommitment::batch_commit_u64(&values, &randomness).unwrap();
    
    assert_eq!(commitments.len(), 3);
    
    // Verify each commitment
    for (i, (value, rand)) in values.iter().zip(randomness.iter()).enumerate() {
        let verification = HashCommitment::verify_u64(&commitments[i], *value, *rand);
        assert!(verification);
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

#[test]
fn test_pedersen_commitment_basic() {
    let message = 42u64;
    let randomness = 123u64;
    
    let commitment = PedersenCommitment::commit(message, randomness);
    let verification = PedersenCommitment::verify(commitment, message, randomness);
    
    assert!(verification);
}

#[test]
fn test_pedersen_commitment_with_params() {
    let params = PedersenParams::new().unwrap();
    let message = 42u64;
    let randomness = 123u64;
    
    let commitment = PedersenCommitment::commit_with_params(&params, message, randomness).unwrap();
    let verification = PedersenCommitment::verify_with_params(&params, &commitment, message, randomness).unwrap();
    
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

#[test]
fn test_pedersen_commitment_homomorphic_addition() {
    let params = PedersenParams::new().unwrap();
    
    let message1 = 10u64;
    let randomness1 = 20u64;
    let commit1 = PedersenCommitment::commit_with_params(&params, message1, randomness1).unwrap();
    
    let message2 = 15u64;
    let randomness2 = 25u64;
    let commit2 = PedersenCommitment::commit_with_params(&params, message2, randomness2).unwrap();
    
    // Add commitments
    let combined_commit = PedersenCommitment::add_commitments(&commit1, &commit2).unwrap();
    
    // Verify combined commitment
    let combined_message = field_add(message1, message2);
    let combined_randomness = field_add(randomness1, randomness2);
    let expected_commit = PedersenCommitment::commit_with_params(&params, combined_message, combined_randomness).unwrap();
    
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

#[test]
fn test_merkle_tree_creation() {
    let data = vec![
        b"data1".to_vec(),
        b"data2".to_vec(),
        b"data3".to_vec(),
        b"data4".to_vec(),
    ];
    
    let tree = MerkleTree::new(&data).unwrap();
    assert_eq!(tree.get_leaf_count(), 4);
    assert_eq!(tree.get_root().len(), 32);
}

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
    
    // Test proof for each leaf
    for i in 0..data.len() {
        let proof = tree.generate_proof(i).unwrap();
        let verification = MerkleTree::verify_proof(&root, &data[i], &proof).unwrap();
        assert!(verification);
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