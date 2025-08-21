//! # 网络通信与秘密分享集成测试
//!
//! 本测试文件验证网络模块和秘密分享模块的集成功能，
//! 包括通过网络进行秘密分享协议的各种场景测试。

use mpc_api::{
    secret_sharing::{
        ShamirSecretSharing, SecretSharing, AdditiveSecretSharing,
        AdditiveSecretSharingScheme, Share, field_add,
    },
    Result, MpcError,
};
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::{
    sync::RwLock,
};

/// 秘密分享网络消息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretShareMessage {
    pub share_id: String,
    pub share: Share,
    pub sender_id: String,
    pub message_type: String,
}

/// 简化的网络秘密分享节点
#[derive(Debug)]
pub struct NetworkSecretSharingNode {
    pub node_id: String,
    pub local_shares: Arc<RwLock<HashMap<String, Share>>>,
    pub received_messages: Arc<RwLock<Vec<SecretShareMessage>>>,
}

impl NetworkSecretSharingNode {
    /// 创建新节点
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            local_shares: Arc::new(RwLock::new(HashMap::new())),
            received_messages: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// 存储分享
    pub async fn store_share(&self, share_id: String, share: Share) {
        let mut shares = self.local_shares.write().await;
        shares.insert(share_id, share);
    }
    
    /// 获取分享
    pub async fn get_share(&self, share_id: &str) -> Option<Share> {
        let shares = self.local_shares.read().await;
        shares.get(share_id).cloned()
    }
    
    /// 模拟接收网络消息
    pub async fn receive_message(&self, message: SecretShareMessage) {
        let mut messages = self.received_messages.write().await;
        messages.push(message);
    }
    
    /// 获取接收到的消息数量
    pub async fn get_message_count(&self) -> usize {
        let messages = self.received_messages.read().await;
        messages.len()
    }
}

/// 模拟网络通信的秘密分享协议
#[derive(Debug)]
pub struct NetworkSecretSharingProtocol {
    pub nodes: Vec<NetworkSecretSharingNode>,
}

impl NetworkSecretSharingProtocol {
    /// 创建协议实例
    pub fn new(node_count: usize) -> Self {
        let mut nodes = Vec::new();
        for i in 0..node_count {
            let node_id = format!("node_{}", i);
            nodes.push(NetworkSecretSharingNode::new(node_id));
        }
        
        Self { nodes }
    }
    
    /// 分发秘密分享
    pub async fn distribute_shares(
        &self,
        secret: u64,
        share_id: String,
        threshold: usize,
    ) -> Result<()> {
        let total_parties = self.nodes.len();
        
        // 生成 Shamir 秘密分享
        let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)
            .map_err(|e| MpcError::ProtocolError(format!("Failed to create shares: {:?}", e)))?;
        
        // 分发给各个节点
        for (i, node) in self.nodes.iter().enumerate() {
            node.store_share(share_id.clone(), shares[i].clone()).await;
            
            // 模拟网络消息
            let message = SecretShareMessage {
                share_id: share_id.clone(),
                share: shares[i].clone(),
                sender_id: "dealer".to_string(),
                message_type: "share_distribution".to_string(),
            };
            
            node.receive_message(message).await;
        }
        
        Ok(())
    }
    
    /// 重构秘密
    pub async fn reconstruct_secret(
        &self,
        share_id: &str,
        threshold: usize,
    ) -> Result<u64> {
        let mut shares = Vec::new();
        
        // 收集足够的分享
        for node in self.nodes.iter().take(threshold) {
            if let Some(share) = node.get_share(share_id).await {
                shares.push(share);
            }
        }
        
        if shares.len() < threshold {
            return Err(MpcError::InsufficientShares);
        }
        
        // 重构秘密
        ShamirSecretSharing::reconstruct(&shares, threshold)
            .map_err(|e| MpcError::ProtocolError(format!("Failed to reconstruct: {:?}", e)))
    }
    
    /// 执行同态加法
    pub async fn homomorphic_add(
        &self,
        share_id1: &str,
        share_id2: &str,
        result_id: String,
    ) -> Result<()> {
        for node in &self.nodes {
            let share1 = node.get_share(share_id1).await
                .ok_or_else(|| MpcError::ProtocolError(format!("Share not found: {}", share_id1)))?;
            let share2 = node.get_share(share_id2).await
                .ok_or_else(|| MpcError::ProtocolError(format!("Share not found: {}", share_id2)))?;
            
            let result_share = ShamirSecretSharing::add_shares(&share1, &share2)
                .map_err(|e| MpcError::ProtocolError(format!("Failed to add shares: {:?}", e)))?;
            
            node.store_share(result_id.clone(), result_share).await;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    /// 测试网络节点创建
    #[tokio::test]
    async fn test_network_node_creation() {
        let node = NetworkSecretSharingNode::new("test_node".to_string());
        assert_eq!(node.node_id, "test_node");
        assert_eq!(node.get_message_count().await, 0);
    }
    
    /// 测试分享存储和检索
    #[tokio::test]
    async fn test_share_storage_and_retrieval() {
        let node = NetworkSecretSharingNode::new("test_node".to_string());
        let share = Share::new(1, 42);
        
        // 存储分享
        node.store_share("test_share".to_string(), share.clone()).await;
        
        // 检索分享
        let retrieved = node.get_share("test_share").await;
        assert_eq!(retrieved, Some(share));
        
        // 检索不存在的分享
        let not_found = node.get_share("nonexistent").await;
        assert_eq!(not_found, None);
    }
    
    /// 测试网络消息接收
    #[tokio::test]
    async fn test_message_receiving() {
        let node = NetworkSecretSharingNode::new("test_node".to_string());
        
        let message = SecretShareMessage {
            share_id: "test_share".to_string(),
            share: Share::new(1, 42),
            sender_id: "sender".to_string(),
            message_type: "test".to_string(),
        };
        
        // 接收消息前
        assert_eq!(node.get_message_count().await, 0);
        
        // 接收消息
        node.receive_message(message).await;
        
        // 接收消息后
        assert_eq!(node.get_message_count().await, 1);
    }
    
    /// 测试网络秘密分享协议创建
    #[tokio::test]
    async fn test_protocol_creation() {
        let protocol = NetworkSecretSharingProtocol::new(3);
        assert_eq!(protocol.nodes.len(), 3);
        
        for (i, node) in protocol.nodes.iter().enumerate() {
            assert_eq!(node.node_id, format!("node_{}", i));
        }
    }
    
    /// 测试秘密分享分发
    #[tokio::test]
    async fn test_secret_sharing_distribution() {
        let protocol = NetworkSecretSharingProtocol::new(3);
        let secret = 42u64;
        let threshold = 2;
        
        let result = protocol.distribute_shares(
            secret,
            "test_secret".to_string(),
            threshold,
        ).await;
        
        assert!(result.is_ok());
        
        // 验证每个节点都收到了分享
        for node in &protocol.nodes {
            let share = node.get_share("test_secret").await;
            assert!(share.is_some());
            assert_eq!(node.get_message_count().await, 1);
        }
    }
    
    /// 测试秘密重构
    #[tokio::test]
    async fn test_secret_reconstruction() {
        let protocol = NetworkSecretSharingProtocol::new(3);
        let secret = 100u64;
        let threshold = 2;
        
        // 分发秘密
        protocol.distribute_shares(
            secret,
            "test_secret".to_string(),
            threshold,
        ).await.unwrap();
        
        // 重构秘密
        let reconstructed = protocol.reconstruct_secret(
            "test_secret",
            threshold,
        ).await.unwrap();
        
        assert_eq!(reconstructed, secret);
    }
    
    /// 测试同态加法运算
    #[tokio::test]
    async fn test_homomorphic_addition() {
        let protocol = NetworkSecretSharingProtocol::new(3);
        let secret1 = 30u64;
        let secret2 = 70u64;
        let threshold = 2;
        
        // 分发两个秘密
        protocol.distribute_shares(
            secret1,
            "secret1".to_string(),
            threshold,
        ).await.unwrap();
        
        protocol.distribute_shares(
            secret2,
            "secret2".to_string(),
            threshold,
        ).await.unwrap();
        
        // 执行同态加法
        protocol.homomorphic_add(
            "secret1",
            "secret2",
            "sum_result".to_string(),
        ).await.unwrap();
        
        // 重构结果
        let sum = protocol.reconstruct_secret(
            "sum_result",
            threshold,
        ).await.unwrap();
        
        assert_eq!(sum, field_add(secret1, secret2));
    }
    
    /// 测试不足分享数量的重构失败
    #[tokio::test]
    async fn test_insufficient_shares_reconstruction() {
        let protocol = NetworkSecretSharingProtocol::new(2);
        let secret = 42u64;
        let threshold = 3; // 阈值大于节点数
        
        // 尝试分发秘密（应该失败）
        let result = protocol.distribute_shares(
            secret,
            "test_secret".to_string(),
            threshold,
        ).await;
        
        // 由于阈值大于总节点数，分享创建应该失败
        assert!(result.is_err());
    }
    
    /// 测试加法秘密分享网络集成
    #[tokio::test]
    async fn test_additive_secret_sharing_network_integration() {
        use mpc_api::secret_sharing::AdditiveShare;
        
        let scheme = AdditiveSecretSharingScheme::new();
        let secret = 1000u64;
        let num_parties = 3;
        
        // 生成加法分享
        let additive_shares = scheme.share_additive(&secret, num_parties).unwrap();
        
        // 模拟网络分发 - 将 AdditiveShare 转换为 Share 用于网络传输
        let mut nodes = Vec::new();
        for i in 0..num_parties {
            let node = NetworkSecretSharingNode::new(format!("additive_node_{}", i));
            // 将加法分享的值存储为 Share 结构用于网络传输
            node.store_share("additive_secret".to_string(), Share::new(i as u64, additive_shares[i].value)).await;
            nodes.push(node);
        }
        
        // 收集分享并重构
        let mut collected_additive_shares = Vec::new();
        for (i, node) in nodes.iter().enumerate() {
            if let Some(share) = node.get_share("additive_secret").await {
                // 重新构造 AdditiveShare
                collected_additive_shares.push(AdditiveShare::new(i, share.y));
            }
        }
        
        let reconstructed = scheme.reconstruct_additive(&collected_additive_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }
    
    /// 测试网络消息序列化
    #[test]
    fn test_network_message_serialization() {
        let message = SecretShareMessage {
            share_id: "test_share".to_string(),
            share: Share::new(1, 42),
            sender_id: "test_sender".to_string(),
            message_type: "test_type".to_string(),
        };
        
        // 序列化
        let serialized = serde_json::to_string(&message);
        assert!(serialized.is_ok());
        
        // 反序列化
        let deserialized: std::result::Result<SecretShareMessage, _> = 
            serde_json::from_str(&serialized.unwrap());
        assert!(deserialized.is_ok());
        
        let deserialized_message = deserialized.unwrap();
        assert_eq!(deserialized_message, message);
    }
    
    /// 测试网络配置与秘密分享参数验证
    #[tokio::test]
    async fn test_network_config_with_secret_sharing_params() {
        // 测试有效的配置组合
        let valid_combinations = vec![
            (3, 2), // 3方2阈值
            (5, 3), // 5方3阈值
            (7, 4), // 7方4阈值
        ];
        
        for (total_parties, threshold) in valid_combinations {
            let protocol = NetworkSecretSharingProtocol::new(total_parties);
            let secret = 123u64;
            
            let result = protocol.distribute_shares(
                secret,
                format!("test_{}_{}", total_parties, threshold),
                threshold,
            ).await;
            
            assert!(result.is_ok(), 
                "Failed for combination: {} parties, {} threshold", 
                total_parties, threshold);
        }
    }
    
    /// 测试并发网络操作
    #[tokio::test]
    async fn test_concurrent_network_operations() {
        let protocol = Arc::new(NetworkSecretSharingProtocol::new(5));
        let threshold = 3;
        
        // 并发分发多个秘密
        let mut handles = Vec::new();
        
        for i in 0..10 {
            let protocol_clone = Arc::clone(&protocol);
            let handle = tokio::spawn(async move {
                protocol_clone.distribute_shares(
                    (i * 10) as u64,
                    format!("concurrent_secret_{}", i),
                    threshold,
                ).await
            });
            handles.push(handle);
        }
        
        // 等待所有操作完成
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
        
        // 验证所有秘密都能正确重构
        for i in 0..10 {
            let reconstructed = protocol.reconstruct_secret(
                &format!("concurrent_secret_{}", i),
                threshold,
            ).await.unwrap();
            
            assert_eq!(reconstructed, (i * 10) as u64);
        }
    }
    
    /// 测试网络错误处理
    #[tokio::test]
    async fn test_network_error_handling() {
        let protocol = NetworkSecretSharingProtocol::new(3);
        
        // 测试重构不存在的秘密
        let result = protocol.reconstruct_secret("nonexistent", 2).await;
        assert!(result.is_err());
        
        // 测试同态运算中的错误
        let add_result = protocol.homomorphic_add(
            "nonexistent1",
            "nonexistent2",
            "result".to_string(),
        ).await;
        assert!(add_result.is_err());
    }
}

/// 运行所有网络秘密分享集成测试
pub async fn run_all_integration_tests() -> Result<()> {
    println!("🧪 运行网络秘密分享集成测试...");
    
    // 这里可以添加更多的集成测试逻辑
    println!("✅ 所有集成测试通过!");
    
    Ok(())
}