//! # 简化的 MPC 网络演示程序 (Simple MPC Network Demo)
//!
//! 这个示例展示了如何使用 MPC API 的网络模块进行基本的网络通信。
//! 包括 P2P 节点创建、HTTP API 使用等核心功能。

use mpc_api::{
    network::{
        NetworkManager,
        p2p::{P2PNode, PeerConfig, NodeRole, MessageHandler},
        http::{HttpServer, HttpClient, RestConfig},
        protocol::NetworkMessage,
        common::{NetworkResult, NetworkError},
    },
    secret_sharing::ShamirSecretSharing,
    SecretSharing,
};
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::RwLock,
    time::sleep,
};

/// MPC 会话信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcSession {
    pub id: String,
    pub participants: Vec<String>,
    pub threshold: usize,
    pub status: SessionStatus,
}

/// 会话状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionStatus {
    Initializing,
    ShareDistribution,
    Computing,
    Completed,
    Failed(String),
}

/// MPC 消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcMessage {
    /// 加入会话请求
    JoinSession {
        session_id: String,
        participant_id: String,
    },
    /// 计算请求
    ComputeRequest {
        session_id: String,
        operation: String,
    },
    /// 计算结果
    ComputeResult {
        session_id: String,
        result: String,
        participant_id: String,
    },
}

/// MPC 节点
pub struct MpcNode {
    pub node_id: String,
    pub role: NodeRole,
    pub p2p_node: Option<P2PNode>,
    pub sessions: Arc<RwLock<HashMap<String, MpcSession>>>,
}

/// MPC 消息处理器
pub struct MpcMessageHandler {
    node_id: String,
    sessions: Arc<RwLock<HashMap<String, MpcSession>>>,
}

impl MessageHandler for MpcMessageHandler {
    fn handle_message(
        &self,
        from_peer: &str,
        message: &NetworkMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<Option<NetworkMessage>>> + Send + '_>> {
        let node_id = self.node_id.clone();
        let sessions = Arc::clone(&self.sessions);
        let from_peer = from_peer.to_string();
        let message_type = message.message_type.clone();
        let payload = message.payload.clone();
        
        Box::pin(async move {
            println!("🔄 节点 {} 收到来自 {} 的消息: {}", node_id, from_peer, message_type);
            
            match message_type.as_str() {
                "mpc_message" => {
                    // 解析 MPC 消息
                    match serde_json::from_slice::<MpcMessage>(&payload) {
                        Ok(mpc_msg) => {
                            Self::handle_mpc_message(&node_id, &sessions, mpc_msg).await
                        }
                        Err(e) => {
                            println!("❌ 解析 MPC 消息失败: {}", e);
                            Err(NetworkError::DeserializationError(e.to_string()))
                        }
                    }
                }
                "ping" => {
                    println!("💓 收到来自 {} 的 ping", from_peer);
                    let pong = NetworkMessage::new("pong", b"pong_response")
                        .with_sender(node_id);
                    Ok(Some(pong))
                }
                _ => {
                    println!("❓ 未知消息类型: {}", message_type);
                    Ok(None)
                }
            }
        })
    }
}

impl MpcMessageHandler {
    pub fn new(node_id: String, sessions: Arc<RwLock<HashMap<String, MpcSession>>>) -> Self {
        Self { node_id, sessions }
    }
    
    async fn handle_mpc_message(
        node_id: &str,
        sessions: &Arc<RwLock<HashMap<String, MpcSession>>>,
        mpc_msg: MpcMessage,
    ) -> NetworkResult<Option<NetworkMessage>> {
        match mpc_msg {
            MpcMessage::JoinSession { session_id, participant_id } => {
                println!("🤝 节点 {} 请求加入会话 {}", participant_id, session_id);
                
                let mut sessions_write = sessions.write().await;
                if let Some(session) = sessions_write.get_mut(&session_id) {
                    if !session.participants.contains(&participant_id) {
                        session.participants.push(participant_id.clone());
                        println!("✅ 节点 {} 成功加入会话 {}", participant_id, session_id);
                    }
                }
                Ok(None)
            }
            
            MpcMessage::ComputeRequest { session_id, operation } => {
                println!("📊 收到计算请求: {} (会话: {})", operation, session_id);
                
                let result = format!("计算结果: {} 完成", operation);
                
                let response = MpcMessage::ComputeResult {
                    session_id,
                    result,
                    participant_id: node_id.to_string(),
                };
                
                let response_bytes = serde_json::to_vec(&response)
                    .map_err(|e| NetworkError::SerializationError(e.to_string()))?;
                let response_msg = NetworkMessage::new("mpc_message", &response_bytes)
                    .with_sender(node_id.to_string());
                Ok(Some(response_msg))
            }
            
            MpcMessage::ComputeResult { session_id, result, participant_id } => {
                println!("📋 收到来自 {} 的计算结果: {} (会话: {})", 
                         participant_id, result, session_id);
                
                let mut sessions_write = sessions.write().await;
                if let Some(session) = sessions_write.get_mut(&session_id) {
                    session.status = SessionStatus::Completed;
                }
                Ok(None)
            }
        }
    }
}

impl MpcNode {
    /// 创建新的 MPC 节点
    pub async fn new(node_id: String, role: NodeRole, port: u16) -> NetworkResult<Self> {
        println!("🚀 创建 MPC 节点: {} (角色: {:?}, 端口: {})", node_id, role, port);
        
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        
        let mut node = MpcNode {
            node_id: node_id.clone(),
            role: role.clone(),
            p2p_node: None,
            sessions,
        };
        
        // 配置 P2P 节点
        let p2p_config = PeerConfig {
            host: "127.0.0.1".to_string(),
            port,
            node_role: role,
            max_connections: 10,
            enable_discovery: false,
            bootstrap_nodes: Vec::new(),
            network_id: "mpc_demo".to_string(),
            ..Default::default()
        };
        
        let p2p_node = P2PNode::new(p2p_config).await?;
        
        // 注册 MPC 消息处理器
        let handler = Box::new(MpcMessageHandler::new(
            node.node_id.clone(),
            Arc::clone(&node.sessions)
        ));
        p2p_node.register_handler("mpc_message".to_string(), handler).await;
        
        node.p2p_node = Some(p2p_node);
        
        Ok(node)
    }
    
    /// 创建 MPC 会话
    pub async fn create_session(&self, session_id: String, threshold: usize) -> NetworkResult<()> {
        println!("📝 节点 {} 创建 MPC 会话: {} (门限: {})", self.node_id, session_id, threshold);
        
        let session = MpcSession {
            id: session_id.clone(),
            participants: vec![self.node_id.clone()],
            threshold,
            status: SessionStatus::Initializing,
        };
        
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);
        
        println!("✅ 会话 {} 创建成功", session_id);
        Ok(())
    }
    
    /// 发送消息到特定对等节点
    pub async fn send_message(&self, target_peer: &str, mpc_msg: MpcMessage) -> NetworkResult<()> {
        if let Some(_p2p_node) = &self.p2p_node {
            let msg_bytes = serde_json::to_vec(&mpc_msg)
                .map_err(|e| NetworkError::SerializationError(e.to_string()))?;
            let _network_msg = NetworkMessage::new("mpc_message", &msg_bytes)
                .with_sender(self.node_id.clone());
            
            // 注意：在实际实现中，这里应该调用真正的 send_to_peer 方法
            // p2p_node.send_to_peer(target_peer, network_msg).await?;
            println!("📤 向 {} 发送消息", target_peer);
        }
        Ok(())
    }
    
    /// 获取会话状态
    pub async fn get_session_status(&self, session_id: &str) -> Option<SessionStatus> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|s| s.status.clone())
    }
    
    /// 列出所有会话
    pub async fn list_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }
}

/// 演示函数：创建多节点 MPC 网络
pub async fn demo_multi_node_mpc() -> NetworkResult<()> {
    println!("🎬 开始多节点 MPC 演示");
    println!("=====================");
    
    // 创建三个 MPC 节点
    let node1 = MpcNode::new("alice".to_string(), NodeRole::Bootstrap, 28000).await?;
    let node2 = MpcNode::new("bob".to_string(), NodeRole::Participant, 28001).await?;
    let node3 = MpcNode::new("charlie".to_string(), NodeRole::Participant, 28002).await?;
    
    println!("✅ 成功创建 3 个 MPC 节点");
    
    // Alice 创建 MPC 会话
    let session_id = "demo_session_001".to_string();
    node1.create_session(session_id.clone(), 2).await?;
    
    // 模拟节点间通信
    let join_msg = MpcMessage::JoinSession {
        session_id: session_id.clone(),
        participant_id: "bob".to_string(),
    };
    node1.send_message("bob", join_msg).await?;
    
    let join_msg2 = MpcMessage::JoinSession {
        session_id: session_id.clone(),
        participant_id: "charlie".to_string(),
    };
    node1.send_message("charlie", join_msg2).await?;
    
    // 执行计算
    let compute_msg = MpcMessage::ComputeRequest {
        session_id: session_id.clone(),
        operation: "add".to_string(),
    };
    node1.send_message("bob", compute_msg).await?;
    
    // 等待处理
    sleep(Duration::from_millis(100)).await;
    
    // 检查会话状态
    for node in [&node1, &node2, &node3] {
        let sessions = node.list_sessions().await;
        println!("节点 {} 的会话: {:?}", node.node_id, sessions);
    }
    
    println!("✅ 多节点 MPC 演示完成");
    Ok(())
}

/// 演示函数：HTTP API 管理
pub async fn demo_http_api_management() -> NetworkResult<()> {
    println!("\n🌐 开始 HTTP API 管理演示");
    println!("==========================");
    
    // 创建 HTTP 服务器配置
    let config = RestConfig {
        host: "127.0.0.1".to_string(),
        port: 23000,
        enable_cors: true,
        ..Default::default()
    };
    
    println!("创建 HTTP 服务器配置...");
    let _server = HttpServer::new(config).await?;
    println!("✅ HTTP 服务器创建成功");
    
    // 创建 HTTP 客户端
    let _client = HttpClient::new("http://127.0.0.1:23000")?;
    println!("✅ HTTP 客户端创建成功");
    
    println!("✅ HTTP API 管理演示完成");
    Ok(())
}

/// 演示函数：秘密分享基础功能
pub async fn demo_secret_sharing_basics() -> NetworkResult<()> {
    println!("\n🔐 开始秘密分享基础演示");
    println!("========================");
    
    // 创建秘密和分享
    let secret = 12345u64;
    let threshold = 2;
    let num_shares = 3;
    
    println!("原始秘密: {}", secret);
    println!("门限设置: {}-out-of-{}", threshold, num_shares);
    
    // 生成 Shamir 秘密分享
    let shares = ShamirSecretSharing::share(&secret, threshold, num_shares)
        .map_err(|e| NetworkError::ProtocolError(format!("秘密分享失败: {}", e)))?;
    println!("生成了 {} 个秘密分享", shares.len());
    
    // 重构秘密（使用前两个分享）
    let reconstruction_shares = &shares[0..threshold];
    let reconstructed = ShamirSecretSharing::reconstruct(reconstruction_shares, threshold)
        .map_err(|e| NetworkError::ProtocolError(format!("秘密重构失败: {}", e)))?;
    
    println!("重构的秘密: {}", reconstructed);
    println!("验证结果: {}", if reconstructed == secret { "✅ 成功" } else { "❌ 失败" });
    
    // 演示序列化
    for (i, share) in shares.iter().enumerate() {
        let serialized = serde_json::to_string(share)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;
        println!("分享 {} 序列化长度: {} bytes", i + 1, serialized.len());
    }
    
    println!("✅ 秘密分享基础演示完成");
    Ok(())
}

/// 演示函数：网络管理器使用
pub async fn demo_network_manager() -> NetworkResult<()> {
    println!("\n📡 开始网络管理器演示");
    println!("====================");
    
    // 创建网络管理器
    let config = mpc_api::network::common::NetworkConfig::default();
    let network_manager = NetworkManager::new(config);
    
    // 获取统计信息
    let stats = network_manager.get_stats().await;
    println!("初始连接统计:");
    println!("  P2P 连接数: {}", stats.p2p_connections);
    println!("  HTTP 连接数: {}", stats.http_connections);
    println!("  发送字节数: {}", stats.bytes_sent);
    println!("  接收字节数: {}", stats.bytes_received);
    
    // 健康检查
    let health = network_manager.health_check().await;
    println!("网络健康状态: {:?}", health.overall_status);
    println!("P2P 状态: {:?}", health.p2p_status);
    println!("HTTP 状态: {:?}", health.http_status);
    
    println!("✅ 网络管理器演示完成");
    Ok(())
}

/// 错误处理演示
pub async fn demo_error_handling() -> NetworkResult<()> {
    println!("\n⚠️  开始错误处理演示");
    println!("===================");
    
    // 演示消息解析错误
    println!("1. 消息解析错误处理...");
    let invalid_json = b"{ invalid json }";
    match serde_json::from_slice::<MpcMessage>(invalid_json) {
        Ok(_) => println!("   意外：无效 JSON 被解析成功"),
        Err(e) => println!("   ✅ 正确捕获 JSON 解析错误: {}", e),
    }
    
    // 演示网络配置验证
    println!("2. 网络配置验证...");
    let mut config = RestConfig::default();
    config.port = 0; // 无效端口
    
    match HttpServer::new(config).await {
        Ok(_) => println!("   意外：无效配置被接受"),
        Err(e) => println!("   ✅ 正确捕获配置错误: {}", e),
    }
    
    // 演示端口冲突
    println!("3. 端口冲突处理...");
    let result1 = MpcNode::new("test1".to_string(), NodeRole::Participant, 29000).await;
    let result2 = MpcNode::new("test2".to_string(), NodeRole::Participant, 29000).await;
    
    match (result1.is_ok(), result2.is_ok()) {
        (true, true) => println!("   两个节点都创建成功"),
        (true, false) => println!("   ✅ 正确检测到端口冲突"),
        (false, _) => println!("   第一个节点创建失败"),
    }
    
    println!("✅ 错误处理演示完成");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎭 简化的 MPC 网络演示程序");
    println!("==========================");
    println!("这个程序展示了 MPC API 网络模块的核心功能");
    println!();
    
    // 1. 网络管理器演示
    if let Err(e) = demo_network_manager().await {
        println!("❌ 网络管理器演示失败: {}", e);
    }
    
    // 2. 多节点 MPC 网络演示
    if let Err(e) = demo_multi_node_mpc().await {
        println!("❌ 多节点 MPC 演示失败: {}", e);
    }
    
    // 3. HTTP API 管理演示
    if let Err(e) = demo_http_api_management().await {
        println!("❌ HTTP API 管理演示失败: {}", e);
    }
    
    // 4. 秘密分享基础演示
    if let Err(e) = demo_secret_sharing_basics().await {
        println!("❌ 秘密分享基础演示失败: {}", e);
    }
    
    // 5. 错误处理演示
    if let Err(e) = demo_error_handling().await {
        println!("❌ 错误处理演示失败: {}", e);
    }
    
    println!("\n🎉 所有演示完成！");
    println!("要运行此演示，请使用: cargo run --example simple_network_demo");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_mpc_node_creation() {
        let node = MpcNode::new("test_node".to_string(), NodeRole::Participant, 30000).await;
        assert!(node.is_ok(), "Failed to create MPC node");
        
        let node = node.unwrap();
        assert_eq!(node.node_id, "test_node");
        assert!(matches!(node.role, NodeRole::Participant));
    }
    
    #[tokio::test]
    async fn test_session_management() {
        let node = MpcNode::new("test_node".to_string(), NodeRole::Participant, 30001).await.unwrap();
        
        // 测试创建会话
        let session_id = "test_session".to_string();
        let result = node.create_session(session_id.clone(), 2).await;
        assert!(result.is_ok(), "Failed to create session");
        
        // 测试获取会话状态
        let status = node.get_session_status(&session_id).await;
        assert!(status.is_some(), "Session should exist");
        assert!(matches!(status.unwrap(), SessionStatus::Initializing));
        
        // 测试列出会话
        let sessions = node.list_sessions().await;
        assert!(sessions.contains(&session_id), "Session should be in the list");
    }
    
    #[test]
    fn test_mpc_message_serialization() {
        let msg = MpcMessage::JoinSession {
            session_id: "test".to_string(),
            participant_id: "alice".to_string(),
        };
        
        let serialized = serde_json::to_vec(&msg);
        assert!(serialized.is_ok(), "Failed to serialize MpcMessage");
        
        let deserialized: Result<MpcMessage, _> = serde_json::from_slice(&serialized.unwrap());
        assert!(deserialized.is_ok(), "Failed to deserialize MpcMessage");
    }
    
    #[test]
    fn test_secret_sharing_basic() {
        let secret = 42u64;
        let threshold = 2;
        let num_shares = 3;
        
        let shares = ShamirSecretSharing::share(&secret, threshold, num_shares);
        assert!(shares.is_ok(), "Failed to create shares");
        
        let shares = shares.unwrap();
        assert_eq!(shares.len(), num_shares, "Wrong number of shares");
        
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold);
        assert!(reconstructed.is_ok(), "Failed to reconstruct secret");
        assert_eq!(reconstructed.unwrap(), secret, "Reconstructed secret doesn't match");
    }
}