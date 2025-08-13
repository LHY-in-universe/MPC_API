//! Merkle Tree Commitment Scheme
//! 
//! Implements Merkle tree based commitments for efficient vector commitments

use crate::{MpcError, Result};
use super::CommitmentScheme;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleTree {
    pub root: [u8; 32],
    pub leaves: Vec<[u8; 32]>,
    pub nodes: Vec<Vec<[u8; 32]>>, // Each level of the tree
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub siblings: Vec<[u8; 32]>,
    pub path: Vec<bool>, // true for right, false for left
}

impl MerkleTree {
    pub fn new(data: &[Vec<u8>]) -> Result<Self> {
        if data.is_empty() {
            return Err(MpcError::ProtocolError("Cannot create Merkle tree from empty data".to_string()));
        }
        
        // Hash all leaves
        let leaves: Vec<[u8; 32]> = data.iter().map(|item| {
            let mut hasher = Sha256::new();
            hasher.update(item);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        }).collect();
        
        let mut nodes = Vec::new();
        nodes.push(leaves.clone());
        
        let mut current_level = leaves.clone();
        
        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    // Duplicate the last node for odd number of nodes
                    hasher.update(&chunk[0]);
                }
                
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                next_level.push(hash);
            }
            
            nodes.push(next_level.clone());
            current_level = next_level;
        }
        
        let root = current_level[0];
        
        Ok(MerkleTree {
            root,
            leaves,
            nodes,
        })
    }
    
    pub fn get_root(&self) -> &[u8; 32] {
        &self.root
    }
    
    pub fn generate_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(MpcError::ProtocolError("Leaf index out of bounds".to_string()));
        }
        
        let mut siblings = Vec::new();
        let mut path = Vec::new();
        let mut current_index = leaf_index;
        
        // Traverse from leaf to root
        for level in 0..(self.nodes.len() - 1) {
            let level_nodes = &self.nodes[level];
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            if sibling_index < level_nodes.len() {
                siblings.push(level_nodes[sibling_index]);
                path.push(current_index % 2 == 0);
            } else {
                // No sibling (odd number of nodes)
                siblings.push(level_nodes[current_index]);
                path.push(false);
            }
            
            current_index /= 2;
        }
        
        Ok(MerkleProof {
            leaf_index,
            siblings,
            path,
        })
    }
    
    pub fn verify_proof(
        root: &[u8; 32],
        leaf_data: &[u8],
        proof: &MerkleProof,
    ) -> Result<bool> {
        // Hash the leaf data
        let mut hasher = Sha256::new();
        hasher.update(leaf_data);
        let result = hasher.finalize();
        let mut current_hash = [0u8; 32];
        current_hash.copy_from_slice(&result);
        
        // Traverse up the tree using the proof
        for (sibling, is_left) in proof.siblings.iter().zip(proof.path.iter()) {
            let mut hasher = Sha256::new();
            
            if *is_left {
                hasher.update(&current_hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current_hash);
            }
            
            let result = hasher.finalize();
            current_hash.copy_from_slice(&result);
        }
        
        Ok(current_hash == *root)
    }
    
    pub fn update_leaf(&mut self, leaf_index: usize, new_data: &[u8]) -> Result<()> {
        if leaf_index >= self.leaves.len() {
            return Err(MpcError::ProtocolError("Leaf index out of bounds".to_string()));
        }
        
        // Hash new data
        let mut hasher = Sha256::new();
        hasher.update(new_data);
        let result = hasher.finalize();
        let mut new_hash = [0u8; 32];
        new_hash.copy_from_slice(&result);
        
        // Update leaf
        self.leaves[leaf_index] = new_hash;
        self.nodes[0][leaf_index] = new_hash;
        
        // Update path to root
        let mut current_index = leaf_index;
        
        for level in 0..(self.nodes.len() - 1) {
            let parent_index = current_index / 2;
            let left_child = current_index & !1;  // Even index
            let right_child = left_child + 1;
            
            let mut hasher = Sha256::new();
            hasher.update(&self.nodes[level][left_child]);
            
            if right_child < self.nodes[level].len() {
                hasher.update(&self.nodes[level][right_child]);
            } else {
                hasher.update(&self.nodes[level][left_child]);
            }
            
            let result = hasher.finalize();
            let mut parent_hash = [0u8; 32];
            parent_hash.copy_from_slice(&result);
            
            self.nodes[level + 1][parent_index] = parent_hash;
            current_index = parent_index;
        }
        
        // Update root
        self.root = self.nodes[self.nodes.len() - 1][0];
        
        Ok(())
    }
    
    pub fn get_leaf_count(&self) -> usize {
        self.leaves.len()
    }
    
    pub fn get_depth(&self) -> usize {
        self.nodes.len() - 1
    }
}

// Merkle tree commitment scheme
pub struct MerkleCommitment;

impl CommitmentScheme for MerkleCommitment {
    type Commitment = [u8; 32];
    type Message = Vec<Vec<u8>>;
    type Randomness = ();
    
    fn commit(message: Self::Message, _randomness: Self::Randomness) -> Self::Commitment {
        let tree = MerkleTree::new(&message).unwrap();
        *tree.get_root()
    }
    
    fn verify(commitment: Self::Commitment, message: Self::Message, _randomness: Self::Randomness) -> bool {
        let tree = MerkleTree::new(&message).unwrap();
        *tree.get_root() == commitment
    }
}

// Batch commitment using Merkle trees
pub struct BatchMerkleCommitment {
    pub tree: MerkleTree,
    pub data: Vec<Vec<u8>>,
}

impl BatchMerkleCommitment {
    pub fn new(data: Vec<Vec<u8>>) -> Result<Self> {
        let tree = MerkleTree::new(&data)?;
        Ok(BatchMerkleCommitment { tree, data })
    }
    
    pub fn get_commitment(&self) -> &[u8; 32] {
        self.tree.get_root()
    }
    
    pub fn prove_inclusion(&self, index: usize) -> Result<(Vec<u8>, MerkleProof)> {
        if index >= self.data.len() {
            return Err(MpcError::ProtocolError("Index out of bounds".to_string()));
        }
        
        let data = self.data[index].clone();
        let proof = self.tree.generate_proof(index)?;
        Ok((data, proof))
    }
    
    pub fn verify_inclusion(
        commitment: &[u8; 32],
        data: &[u8],
        proof: &MerkleProof,
    ) -> Result<bool> {
        MerkleTree::verify_proof(commitment, data, proof)
    }
    
    pub fn update_data(&mut self, index: usize, new_data: Vec<u8>) -> Result<()> {
        if index >= self.data.len() {
            return Err(MpcError::ProtocolError("Index out of bounds".to_string()));
        }
        
        self.data[index] = new_data.clone();
        self.tree.update_leaf(index, &new_data)
    }
}

// Merkle tree is binding
impl super::BindingCommitment for MerkleCommitment {}

#[cfg(test)]
mod tests {
    use super::*;
    
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
}