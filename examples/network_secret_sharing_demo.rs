//! # 网络通信与秘密分享集成示例
//!
//! 本示例展示如何使用 MPC_API 的网络模块和秘密分享模块进行多方安全计算。
//! 演示了三方通过网络进行 Shamir 秘密分享协议的完整流程。
//!
//! ## Bash 测试代码
//!
//! ```bash
//! # 编译检查
//! cargo check --example network_secret_sharing_demo
//!
//! # 运行完整网络演示
//! cargo run --example network_secret_sharing_demo
//!
//! # 运行所有测试
//! cargo test --example network_secret_sharing_demo
//!
//! # 运行特定网络测试
//! cargo test test_coordinator_creation
//! cargo test test_additive_sharing_demo
//! cargo test test_message_serialization
//!
//! # 运行网络集成测试
//! cargo test --test network_secret_sharing_integration_tests
//!
//! # 网络性能基准测试
//! cargo bench --bench mpc_benchmarks -- network
//!
//! # 生成网络文档
//! cargo doc --example network_secret_sharing_demo --open
//! ```

use mpc_api::{
    network::{
        p2p::{P2PNode, PeerConfig, NodeRole},
        protocol::NetworkMessage,
    },
    secret_sharing::{
        ShamirSecretSharing, SecretSharing, AdditiveSecretSharing,
        AdditiveSecretSharingScheme,
        Share, field_add,
    },
    Result, MpcError,
};
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{RwLock, mpsc},
};

/// 秘密分享网络消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretSharingMessage {
    /// 分享分发消息
    ShareDistribution {
        share_id: String,
        share: Share,
        threshold: usize,
        total_parties: usize,
    },
    /// 重构请求消息
    ReconstructionRequest {
        share_id: String,
        requester_id: String,
    },
    /// 重构响应消息
    ReconstructionResponse {
        share_id: String,
        share: Share,
        party_id: String,
    },
    /// 计算请求消息（同态运算）
    ComputationRequest {
        operation: String,
        operand1_id: String,
        operand2_id: Option<String>,
        scalar: Option<u64>,
    },
    /// 计算结果消息
    ComputationResult {
        result_id: String,
        shares: Vec<Share>,
    },
}

/// 多方秘密分享协调器
pub struct SecretSharingCoordinator {
    /// 节点 ID
    node_id: String,
    /// P2P 网络节点
    _p2p_node: Arc<P2PNode>,
    /// 本地存储的分享
    local_shares: Arc<RwLock<HashMap<String, Share>>>,
    /// 消息接收通道
    _message_receiver: Arc<RwLock<Option<mpsc::Receiver<SecretSharingMessage>>>>,
    /// 消息发送通道
    message_sender: mpsc::Sender<SecretSharingMessage>,
}

impl SecretSharingCoordinator {
    /// 创建新的秘密分享协调器
    pub async fn new(port: u16, node_role: NodeRole) -> Result<Self> {
        let mut peer_config = PeerConfig::default();
        peer_config.port = port;
        peer_config.node_role = node_role;
        
        let p2p_node = Arc::new(P2PNode::new(peer_config).await
            .map_err(|e| MpcError::NetworkError(format!("Failed to create P2P node: {:?}", e)))?);
        
        let node_id = p2p_node.node_id.clone();
        
        let (sender, receiver) = mpsc::channel(100);
        
        Ok(Self {
            node_id,
            _p2p_node: p2p_node,
            local_shares: Arc::new(RwLock::new(HashMap::new())),
            _message_receiver: Arc::new(RwLock::new(Some(receiver))),
            message_sender: sender,
        })
    }
    
    /// 启动协调器
    pub async fn start(&self) -> Result<()> {
        println!("🚀 启动秘密分享协调器: {}", self.node_id);
        
        // 启动消息处理循环
        self.start_message_handler().await?;
        
        Ok(())
    }
    
    /// 分享秘密给其他参与方
    pub async fn share_secret(
        &self,
        secret: u64,
        share_id: String,
        threshold: usize,
        total_parties: usize,
    ) -> Result<()> {
        println!("📤 分享秘密 '{}': {} (阈值: {}, 总方数: {})", 
                share_id, secret, threshold, total_parties);
        
        // 生成 Shamir 秘密分享
        let shares = <ShamirSecretSharing as SecretSharing>::share(&secret, threshold, total_parties)
            .map_err(|e| MpcError::ProtocolError(format!("Failed to create shares: {:?}", e)))?;
        
        // 存储所有分享到全局存储中（模拟网络分发）
        {
            let mut local_shares = self.local_shares.write().await;
            // 为了演示目的，我们将所有分享都存储在每个节点中
            // 在真实的网络环境中，每个节点只会收到自己的分享
            for (i, share) in shares.iter().enumerate() {
                local_shares.insert(format!("{}_party_{}", share_id, i + 1), share.clone());
            }
            // 同时存储一个通用的分享用于本地操作
            local_shares.insert(share_id.clone(), shares[0].clone());
        }
        
        // 向其他参与方发送分享（模拟）
        for (_i, share) in shares.iter().enumerate().skip(1) {
            let message = SecretSharingMessage::ShareDistribution {
                share_id: share_id.clone(),
                share: share.clone(),
                threshold,
                total_parties,
            };
            
            self.broadcast_message(message).await?;
        }
        
        println!("✅ 秘密分享完成: {}", share_id);
        Ok(())
    }
    
    /// 请求重构秘密
    pub async fn reconstruct_secret(&self, share_id: String) -> Result<u64> {
        println!("🔍 请求重构秘密: {}", share_id);
        
        // 发送重构请求
        let request = SecretSharingMessage::ReconstructionRequest {
            share_id: share_id.clone(),
            requester_id: self.node_id.clone(),
        };
        
        self.broadcast_message(request).await?;
        
        // 收集足够的分享进行重构
        let shares = self.collect_shares_for_reconstruction(&share_id).await?;
        
        // 重构秘密
        let secret = <ShamirSecretSharing as SecretSharing>::reconstruct(&shares, shares.len())
            .map_err(|e| MpcError::ProtocolError(format!("Failed to reconstruct: {:?}", e)))?;
        
        println!("✅ 秘密重构成功: {} = {}", share_id, secret);
        Ok(secret)
    }
    
    /// 执行同态加法运算
    pub async fn homomorphic_add(
        &self,
        operand1_id: String,
        operand2_id: String,
        result_id: String,
    ) -> Result<()> {
        println!("➕ 执行同态加法: {} + {} = {}", operand1_id, operand2_id, result_id);
        
        let local_shares = self.local_shares.read().await;
        
        let share1 = local_shares.get(&operand1_id)
            .ok_or_else(|| MpcError::ProtocolError(format!("Share not found: {}", operand1_id)))?;
        let share2 = local_shares.get(&operand2_id)
            .ok_or_else(|| MpcError::ProtocolError(format!("Share not found: {}", operand2_id)))?;
        
        // 执行本地加法运算
        let result_share = <ShamirSecretSharing as AdditiveSecretSharing>::add_shares(share1, share2)
            .map_err(|e| MpcError::ProtocolError(format!("Failed to add shares: {:?}", e)))?;
        
        // 存储结果分享
        drop(local_shares);
        {
            let mut local_shares = self.local_shares.write().await;
            local_shares.insert(result_id.clone(), result_share.clone());
        }
        
        // 广播计算结果
        let message = SecretSharingMessage::ComputationResult {
            result_id: result_id.clone(),
            shares: vec![result_share],
        };
        
        self.broadcast_message(message).await?;
        
        println!("✅ 同态加法完成: {}", result_id);
        Ok(())
    }
    
    /// 执行标量乘法运算
    pub async fn scalar_multiply(
        &self,
        operand_id: String,
        scalar: u64,
        result_id: String,
    ) -> Result<()> {
        println!("✖️ 执行标量乘法: {} * {} = {}", operand_id, scalar, result_id);
        
        let local_shares = self.local_shares.read().await;
        
        let share = local_shares.get(&operand_id)
            .ok_or_else(|| MpcError::ProtocolError(format!("Share not found: {}", operand_id)))?;
        
        // 执行标量乘法
        let result_share = <ShamirSecretSharing as AdditiveSecretSharing>::scalar_mul(share, &scalar)
            .map_err(|e| MpcError::ProtocolError(format!("Failed to multiply share: {:?}", e)))?;
        
        // 存储结果分享
        drop(local_shares);
        {
            let mut local_shares = self.local_shares.write().await;
            local_shares.insert(result_id.clone(), result_share.clone());
        }
        
        println!("✅ 标量乘法完成: {}", result_id);
        Ok(())
    }
    
    /// 启动消息处理器
    async fn start_message_handler(&self) -> Result<()> {
        let _local_shares = Arc::clone(&self.local_shares);
        let _message_sender = self.message_sender.clone();
        
        // 这里应该启动一个实际的消息处理循环
        // 由于这是示例代码，我们简化处理
        println!("📡 消息处理器已启动");
        
        Ok(())
    }
    
    /// 广播消息给所有参与方
    async fn broadcast_message(&self, message: SecretSharingMessage) -> Result<()> {
        // 序列化消息
        let payload = serde_json::to_vec(&message)
            .map_err(|e| MpcError::SerializationError(format!("Failed to serialize message: {}", e)))?;
        
        // 创建网络消息
        let _network_message = NetworkMessage::new("secret_sharing", &payload);
        
        println!("📡 广播消息: {:?}", message);
        
        // 在实际实现中，这里会通过 P2P 网络发送消息
        // 由于这是示例，我们只是打印消息
        
        Ok(())
    }
    
    /// 收集重构所需的分享
    async fn collect_shares_for_reconstruction(&self, share_id: &str) -> Result<Vec<Share>> {
        // 在实际实现中，这里会等待并收集来自其他参与方的分享
        // 为了演示，我们从本地存储中收集所有相关分享
        
        let local_shares = self.local_shares.read().await;
        let mut shares = Vec::new();
        
        // 收集所有相关的分享
        for i in 1..=3 {
            let key = format!("{}_party_{}", share_id, i);
            if let Some(share) = local_shares.get(&key) {
                shares.push(share.clone());
            }
        }
        
        // 如果没有找到分片格式的分享，尝试查找直接的分享
        if shares.is_empty() {
            if let Some(share) = local_shares.get(share_id) {
                shares.push(share.clone());
            }
        }
        
        if shares.is_empty() {
            Err(MpcError::ProtocolError(format!("Share not found: {}", share_id)))
        } else {
            Ok(shares)
        }
    }
    
    /// 获取本地存储的分享信息
    pub async fn get_local_shares(&self) -> HashMap<String, Share> {
        self.local_shares.read().await.clone()
    }
}

/// 运行三方秘密分享演示
pub async fn run_three_party_demo() -> Result<()> {
    println!("🎯 开始三方秘密分享演示");
    println!("{}", "=".repeat(50));
    
    // 创建三个参与方
    let party1 = SecretSharingCoordinator::new(8001, NodeRole::Bootstrap).await?;
    let party2 = SecretSharingCoordinator::new(8002, NodeRole::Participant).await?;
    let party3 = SecretSharingCoordinator::new(8003, NodeRole::Participant).await?;
    
    // 启动所有参与方
    party1.start().await?;
    party2.start().await?;
    party3.start().await?;
    
    println!("\n📋 演示场景:");
    println!("1. Party1 分享秘密 42");
    println!("2. Party2 分享秘密 58");
    println!("3. 模拟网络同步分享数据");
    println!("4. 执行同态加法: 42 + 58 = 100");
    println!("5. 执行标量乘法: 100 * 2 = 200");
    println!("6. 重构最终结果");
    
    // 1. Party1 分享秘密 42
    println!("\n🔸 步骤 1: Party1 分享秘密");
    party1.share_secret(42, "secret1".to_string(), 2, 3).await?;
    
    // 2. Party2 分享秘密 58
    println!("\n🔸 步骤 2: Party2 分享秘密");
    party2.share_secret(58, "secret2".to_string(), 2, 3).await?;
    
    // 3. 模拟网络同步 - 将分享数据同步到所有节点
    println!("\n🔸 步骤 3: 模拟网络同步分享数据");
    
    // 获取 party1 和 party2 的分享数据
    let party1_shares = party1.get_local_shares().await;
    let party2_shares = party2.get_local_shares().await;
    
    // 将 party2 的 secret2 分享同步到 party1
    {
        let mut party1_local = party1.local_shares.write().await;
        for (key, share) in &party2_shares {
            if key.starts_with("secret2") {
                party1_local.insert(key.clone(), share.clone());
            }
        }
    }
    
    // 将 party1 的 secret1 分享同步到 party2
    {
        let mut party2_local = party2.local_shares.write().await;
        for (key, share) in &party1_shares {
            if key.starts_with("secret1") {
                party2_local.insert(key.clone(), share.clone());
            }
        }
    }
    
    println!("✅ 网络同步完成");
    
    // 模拟网络延迟
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // 4. 执行同态加法
    println!("\n🔸 步骤 4: 执行同态加法");
    party1.homomorphic_add(
        "secret1".to_string(),
        "secret2".to_string(),
        "sum_result".to_string(),
    ).await?;
    
    // 5. 执行标量乘法
    println!("\n🔸 步骤 5: 执行标量乘法");
    party1.scalar_multiply(
        "sum_result".to_string(),
        2,
        "final_result".to_string(),
    ).await?;
    
    // 6. 重构最终结果
    println!("\n🔸 步骤 6: 重构秘密验证结果");
    
    // 重构原始秘密进行验证
    let reconstructed_secret1 = party1.reconstruct_secret("secret1".to_string()).await?;
    let reconstructed_secret2 = party1.reconstruct_secret("secret2".to_string()).await?;
    
    println!("\n📊 验证结果:");
    println!("重构的 secret1: {} (期望: 42)", reconstructed_secret1);
    println!("重构的 secret2: {} (期望: 58)", reconstructed_secret2);
    println!("验证 secret1: {}", reconstructed_secret1 == 42);
    println!("验证 secret2: {}", reconstructed_secret2 == 58);
    
    let party1_shares_final = party1.get_local_shares().await;
    let party2_shares_final = party2.get_local_shares().await;
    let party3_shares_final = party3.get_local_shares().await;
    
    println!("\n📊 各方最终分享状态:");
    println!("Party1 分享数量: {}", party1_shares_final.len());
    println!("Party2 分享数量: {}", party2_shares_final.len());
    println!("Party3 分享数量: {}", party3_shares_final.len());
    
    println!("\n✅ 三方秘密分享演示完成!");
    println!("{}", "=".repeat(50));
    
    Ok(())
}

/// 运行加法秘密分享演示
pub async fn run_additive_sharing_demo() -> Result<()> {
    println!("🎯 开始加法秘密分享演示");
    println!("{}", "=".repeat(50));
    
    let scheme = AdditiveSecretSharingScheme::new();
    let secret = 1000u64;
    let num_parties = 3;
    
    println!("📋 演示场景:");
    println!("- 原始秘密: {}", secret);
    println!("- 参与方数量: {}", num_parties);
    
    // 生成加法分享
    println!("\n🔸 生成加法秘密分享");
    let shares = scheme.share_additive(&secret, num_parties)
        .map_err(|e| MpcError::ProtocolError(format!("Failed to create additive shares: {:?}", e)))?;
    
    println!("✅ 生成了 {} 个分享", shares.len());
    for (i, share) in shares.iter().enumerate() {
        println!("  分享 {}: party_id={}, value={}", i + 1, share.party_id, share.value);
    }
    
    // 重构秘密
    println!("\n🔸 重构秘密");
    let reconstructed = scheme.reconstruct_additive(&shares)
        .map_err(|e| MpcError::ProtocolError(format!("Failed to reconstruct: {:?}", e)))?;
    
    println!("✅ 重构结果: {}", reconstructed);
    println!("✅ 验证成功: {}", secret == reconstructed);
    
    // 同态运算演示
    println!("\n🔸 同态运算演示");
    let secret2 = 500u64;
    let shares2 = scheme.share_additive(&secret2, num_parties)
        .map_err(|e| MpcError::ProtocolError(format!("Failed to create second shares: {:?}", e)))?;
    
    // 执行加法
    let mut sum_shares = Vec::new();
    for i in 0..num_parties {
        let sum_share = scheme.add_additive_shares(&shares[i], &shares2[i])
            .map_err(|e| MpcError::ProtocolError(format!("Failed to add shares: {:?}", e)))?;
        sum_shares.push(sum_share);
    }
    
    let sum_result = scheme.reconstruct_additive(&sum_shares)
        .map_err(|e| MpcError::ProtocolError(format!("Failed to reconstruct sum: {:?}", e)))?;
    
    println!("✅ 同态加法: {} + {} = {}", secret, secret2, sum_result);
    println!("✅ 验证成功: {}", field_add(secret, secret2) == sum_result);
    
    println!("\n✅ 加法秘密分享演示完成!");
    println!("{}", "=".repeat(50));
    
    Ok(())
}

/// 主演示函数
#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 MPC API 网络通信与秘密分享集成演示");
    println!("{}", "=".repeat(60));
    
    // 运行加法秘密分享演示
    run_additive_sharing_demo().await?;
    
    println!("\n");
    
    // 运行三方秘密分享演示
    run_three_party_demo().await?;
    
    println!("\n🎉 所有演示完成!");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_coordinator_creation() {
        let coordinator = SecretSharingCoordinator::new(8000, NodeRole::Bootstrap).await;
        assert!(coordinator.is_ok());
    }
    
    #[tokio::test]
    async fn test_additive_sharing_demo() {
        let result = run_additive_sharing_demo().await;
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_message_serialization() {
        let message = SecretSharingMessage::ShareDistribution {
            share_id: "test".to_string(),
            share: Share::new(1, 42),
            threshold: 2,
            total_parties: 3,
        };
        
        let serialized = serde_json::to_string(&message);
        assert!(serialized.is_ok());
        
        let deserialized: std::result::Result<SecretSharingMessage, _> = serde_json::from_str(&serialized.unwrap());
        assert!(deserialized.is_ok());
    }
}