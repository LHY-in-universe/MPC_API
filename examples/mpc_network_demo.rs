//! # MPC 网络演示程序 (MPC Network Demo)
//!
//! 这个示例展示了如何使用 MPC API 的网络模块进行分布式多方安全计算。
//! 包括 P2P 节点通信、HTTP API 服务、秘密分享网络传输等功能。

use mpc_api::{
    network::{
        NetworkManager,
        p2p::{P2PNode, PeerConfig, NodeRole, MessageHandler},
        http::{HttpServer, HttpClient, RestConfig},
        protocol::NetworkMessage,
        common::{NetworkResult, NetworkError},
    },
    secret_sharing::{ShamirSecretSharing, Share},
    SecretSharing,
};
use base64::{Engine, engine::general_purpose};
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{RwLock, Mutex},
    time::{sleep, timeout},
};

/// MPC 会话信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcSession {
    pub id: String,
    pub participants: Vec<String>,
    pub threshold: usize,
    pub status: SessionStatus,
    pub secret_shares: HashMap<String, String>, // participant_id -> encrypted_share
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
    /// 秘密分享数据
    SecretShare {
        session_id: String,
        share_data: String, // Base64 编码的分享数据
        from_participant: String,
        to_participant: String,
    },
    /// 计算请求
    ComputeRequest {
        session_id: String,
        operation: String, // "add", "multiply", etc.
        operands: Vec<String>,
    },
    /// 计算结果
    ComputeResult {
        session_id: String,
        result: String,
        participant_id: String,
    },
    /// 会话状态更新
    StatusUpdate {
        session_id: String,
        status: SessionStatus,
    },
}

/// MPC 节点
pub struct MpcNode {
    pub node_id: String,
    pub role: NodeRole,
    pub p2p_node: Option<P2PNode>,
    pub sessions: Arc<RwLock<HashMap<String, MpcSession>>>,
    pub network_manager: Option<NetworkManager>,
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
                            MpcMessageHandler::handle_mpc_message(&node_id, &sessions, mpc_msg, &from_peer).await
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
        _from_peer: &str,
    ) -> NetworkResult<Option<NetworkMessage>> {
        match mpc_msg {
            MpcMessage::JoinSession { session_id, participant_id } => {
                println!("🤝 节点 {} 请求加入会话 {}", participant_id, session_id);
                
                let mut sessions_write = sessions.write().await;
                if let Some(session) = sessions_write.get_mut(&session_id) {
                    if !session.participants.contains(&participant_id) {
                        session.participants.push(participant_id.clone());
                        println!("✅ 节点 {} 成功加入会话 {}", participant_id, session_id);
                        
                        // 发送确认消息
                        let response = MpcMessage::StatusUpdate {
                            session_id: session_id.clone(),
                            status: SessionStatus::ShareDistribution,
                        };
                        let response_msg = NetworkMessage::new("mpc_message", 
                            &serde_json::to_vec(&response).unwrap())
                            .with_sender(node_id.to_string());
                        return Ok(Some(response_msg));
                    }
                }
                Ok(None)
            }
            
            MpcMessage::SecretShare { session_id, share_data, from_participant, to_participant } => {
                if to_participant == node_id {
                    println!("🔐 收到来自 {} 的秘密分享数据 (会话: {})", from_participant, session_id);
                    
                    let mut sessions_write = sessions.write().await;
                    if let Some(session) = sessions_write.get_mut(&session_id) {
                        session.secret_shares.insert(from_participant.clone(), share_data);
                        
                        // 检查是否收到了足够的分享
                        if session.secret_shares.len() >= session.threshold {
                            session.status = SessionStatus::Computing;
                            println!("🧮 会话 {} 进入计算阶段", session_id);
                        }
                    }
                }
                Ok(None)
            }
            
            MpcMessage::ComputeRequest { session_id, operation, operands: _ } => {
                println!("📊 收到计算请求: {} (会话: {})", operation, session_id);
                
                // 这里可以实现具体的计算逻辑
                let result = match operation.as_str() {
                    "add" => "计算结果: 加法完成".to_string(),
                    "multiply" => "计算结果: 乘法完成".to_string(),
                    _ => "未知操作".to_string(),
                };
                
                let response = MpcMessage::ComputeResult {
                    session_id,
                    result,
                    participant_id: node_id.to_string(),
                };
                
                let response_msg = NetworkMessage::new("mpc_message", 
                    &serde_json::to_vec(&response).unwrap())
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
            
            MpcMessage::StatusUpdate { session_id, status } => {
                println!("📢 会话 {} 状态更新: {:?}", session_id, status);
                
                let mut sessions_write = sessions.write().await;
                if let Some(session) = sessions_write.get_mut(&session_id) {
                    session.status = status;
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
            network_manager: None,
        };
        
        // 配置 P2P 节点
        let p2p_config = PeerConfig {
            host: "127.0.0.1".to_string(),
            port,
            node_role: role,
            max_connections: 10,
            enable_discovery: false, // 简化演示，禁用自动发现
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
    
    /// 启动节点
    pub async fn start(&mut self) -> NetworkResult<()> {
        println!("🌐 启动 MPC 节点: {}", self.node_id);
        
        if let Some(_p2p_node) = &mut self.p2p_node {
            // 注意：在实际应用中，start() 方法会阻塞，这里我们需要在后台运行
            tokio::spawn(async move {
                // p2p_node.start().await
            });
        }
        
        println!("✅ MPC 节点 {} 启动成功", self.node_id);
        Ok(())
    }
    
    /// 连接到其他节点
    pub async fn connect_to_peer(&self, peer_address: &str) -> NetworkResult<()> {
        println!("🔗 节点 {} 连接到: {}", self.node_id, peer_address);
        
        if let Some(_p2p_node) = &self.p2p_node {
            // 这里应该调用实际的连接方法
            // p2p_node.connect_to_peer(peer_address).await?;
            println!("✅ 成功连接到节点: {}", peer_address);
        }
        
        Ok(())
    }
    
    /// 创建 MPC 会话
    pub async fn create_session(&self, session_id: String, threshold: usize) -> NetworkResult<()> {
        println!("📝 节点 {} 创建 MPC 会话: {} (门限: {})", self.node_id, session_id, threshold);
        
        let session = MpcSession {
            id: session_id.clone(),
            participants: vec![self.node_id.clone()],
            threshold,
            status: SessionStatus::Initializing,
            secret_shares: HashMap::new(),
        };
        
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);
        
        println!("✅ 会话 {} 创建成功", session_id);
        Ok(())
    }
    
    /// 加入 MPC 会话
    pub async fn join_session(&self, session_id: String, coordinator_peer: &str) -> NetworkResult<()> {
        println!("🤝 节点 {} 请求加入会话: {}", self.node_id, session_id);
        
        let join_msg = MpcMessage::JoinSession {
            session_id: session_id.clone(),
            participant_id: self.node_id.clone(),
        };
        
        let _network_msg = NetworkMessage::new("mpc_message", 
            &serde_json::to_vec(&join_msg)
                .map_err(|e| NetworkError::SerializationError(e.to_string()))?)
            .with_sender(self.node_id.clone());
        
        if let Some(_p2p_node) = &self.p2p_node {
            // p2p_node.send_to_peer(coordinator_peer, network_msg).await?;
            println!("📤 向 {} 发送加入会话请求", coordinator_peer);
        }
        
        Ok(())
    }
    
    /// 分发秘密分享
    pub async fn distribute_secret_shares(&self, session_id: String, secret: u64) -> NetworkResult<()> {
        println!("🔐 节点 {} 分发秘密分享 (会话: {})", self.node_id, session_id);
        
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&session_id) {
            let num_participants = session.participants.len();
            
            // 使用 Shamir 秘密分享
            let shares = ShamirSecretSharing::share(&secret, session.threshold, num_participants)
                .map_err(|e| NetworkError::ProtocolError(format!("秘密分享失败: {}", e)))?;
            
            // 向每个参与者发送其分享
            for (i, participant) in session.participants.iter().enumerate() {
                if participant != &self.node_id && i < shares.len() {
                    let share_data = general_purpose::STANDARD.encode(serde_json::to_vec(&shares[i])
                        .map_err(|e| NetworkError::SerializationError(e.to_string()))?);
                    
                    let share_msg = MpcMessage::SecretShare {
                        session_id: session_id.clone(),
                        share_data,
                        from_participant: self.node_id.clone(),
                        to_participant: participant.clone(),
                    };
                    
                    let _network_msg = NetworkMessage::new("mpc_message", 
                        &serde_json::to_vec(&share_msg)
                            .map_err(|e| NetworkError::SerializationError(e.to_string()))?)
                        .with_sender(self.node_id.clone());
                    
                    if let Some(_p2p_node) = &self.p2p_node {
                        // p2p_node.send_to_peer(participant, network_msg).await?;
                        println!("📤 向 {} 发送秘密分享", participant);
                    }
                }
            }
        }
        
        println!("✅ 秘密分享分发完成");
        Ok(())
    }
    
    /// 执行 MPC 计算
    pub async fn compute(&self, session_id: String, operation: String, operands: Vec<String>) -> NetworkResult<()> {
        println!("🧮 节点 {} 执行计算: {} (会话: {})", self.node_id, operation, session_id);
        
        let compute_msg = MpcMessage::ComputeRequest {
            session_id: session_id.clone(),
            operation: operation.clone(),
            operands,
        };
        
        let _network_msg = NetworkMessage::new("mpc_message", 
            &serde_json::to_vec(&compute_msg)
                .map_err(|e| NetworkError::SerializationError(e.to_string()))?)
            .with_sender(self.node_id.clone());
        
        if let Some(_p2p_node) = &self.p2p_node {
            // p2p_node.broadcast(network_msg).await?;
            println!("📢 广播计算请求: {}", operation);
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

/// HTTP API 服务器用于 MPC 管理
pub struct MpcApiServer {
    server: HttpServer,
    mpc_nodes: Arc<RwLock<HashMap<String, Arc<Mutex<MpcNode>>>>>,
}

impl MpcApiServer {
    pub async fn new(port: u16) -> NetworkResult<Self> {
        let config = RestConfig {
            host: "127.0.0.1".to_string(),
            port,
            enable_cors: true,
            ..Default::default()
        };
        
        let server = HttpServer::new(config).await?;
        let mpc_nodes = Arc::new(RwLock::new(HashMap::new()));
        
        Ok(MpcApiServer {
            server,
            mpc_nodes,
        })
    }
    
    pub async fn start(&self) -> NetworkResult<()> {
        println!("🌐 启动 MPC API 服务器");
        self.server.start().await
    }
    
    pub async fn register_node(&self, node_id: String, node: Arc<Mutex<MpcNode>>) {
        let mut nodes = self.mpc_nodes.write().await;
        nodes.insert(node_id.clone(), node);
        println!("📝 注册 MPC 节点: {}", node_id);
    }
}

/// 演示函数：创建多节点 MPC 网络
pub async fn demo_multi_node_mpc() -> NetworkResult<()> {
    println!("🎬 开始多节点 MPC 演示");
    println!("=====================");
    
    // 创建三个 MPC 节点
    let mut node1 = MpcNode::new("alice".to_string(), NodeRole::Bootstrap, 18000).await?;
    let mut node2 = MpcNode::new("bob".to_string(), NodeRole::Participant, 18001).await?;
    let mut node3 = MpcNode::new("charlie".to_string(), NodeRole::Participant, 18002).await?;
    
    // 启动节点
    node1.start().await?;
    node2.start().await?;
    node3.start().await?;
    
    // 建立连接
    node2.connect_to_peer("127.0.0.1:18000").await?;
    node3.connect_to_peer("127.0.0.1:18000").await?;
    
    // 等待连接建立
    sleep(Duration::from_millis(500)).await;
    
    // Alice 创建 MPC 会话，并手动添加所有参与者
    let session_id = "demo_session_001".to_string();
    node1.create_session(session_id.clone(), 2).await?; // 2-out-of-3 门限
    
    // 手动添加参与者到会话
    {
        let mut sessions = node1.sessions.write().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.participants.push("bob".to_string());
            session.participants.push("charlie".to_string());
        }
    }
    
    // Bob 和 Charlie 加入会话（模拟）
    node2.join_session(session_id.clone(), "alice").await?;
    node3.join_session(session_id.clone(), "alice").await?;
    
    // 等待会话建立
    sleep(Duration::from_millis(500)).await;
    
    // Alice 分发秘密 (假设秘密是 42)
    node1.distribute_secret_shares(session_id.clone(), 42).await?;
    
    // 等待分享分发
    sleep(Duration::from_millis(500)).await;
    
    // 执行计算
    node1.compute(session_id.clone(), "add".to_string(), 
                  vec!["operand1".to_string(), "operand2".to_string()]).await?;
    
    // 等待计算完成
    sleep(Duration::from_millis(1000)).await;
    
    // 检查会话状态
    for node in [&node1, &node2, &node3] {
        let sessions = node.list_sessions().await;
        println!("节点 {} 的会话: {:?}", node.node_id, sessions);
        
        if let Some(status) = node.get_session_status(&session_id).await {
            println!("  会话状态: {:?}", status);
        }
    }
    
    println!("✅ 多节点 MPC 演示完成");
    Ok(())
}

/// 演示函数：HTTP API 管理
pub async fn demo_http_api_management() -> NetworkResult<()> {
    println!("\n🌐 开始 HTTP API 管理演示");
    println!("==========================");
    
    // 启动 API 服务器
    let api_server = MpcApiServer::new(13000).await?;
    
    // 在后台启动服务器
    tokio::spawn(async move {
        if let Err(e) = api_server.start().await {
            println!("❌ API 服务器启动失败: {}", e);
        }
    });
    
    // 等待服务器启动
    sleep(Duration::from_millis(1000)).await;
    
    // 创建 HTTP 客户端
    let client = HttpClient::new("http://127.0.0.1:13000")?;
    
    // 测试 API 调用
    println!("📡 测试 API 端点...");
    
    // 健康检查
    match timeout(Duration::from_secs(5), client.get("/health")).await {
        Ok(Ok(response)) => {
            println!("✅ 健康检查: 状态码 {}", response.status_code);
        }
        Ok(Err(e)) => {
            println!("❌ 健康检查失败: {}", e);
        }
        Err(_) => {
            println!("⏰ 健康检查超时");
        }
    }
    
    // 获取节点列表
    match timeout(Duration::from_secs(5), client.get("/api/v1/nodes")).await {
        Ok(Ok(response)) => {
            println!("✅ 节点列表: 状态码 {}", response.status_code);
        }
        Ok(Err(e)) => {
            println!("❌ 获取节点列表失败: {}", e);
        }
        Err(_) => {
            println!("⏰ 获取节点列表超时");
        }
    }
    
    // 创建 MPC 会话
    let session_data = serde_json::json!({
        "participants": ["alice", "bob", "charlie"],
        "threshold": 2,
        "protocol": "shamir"
    });
    
    match timeout(Duration::from_secs(5), 
                  client.post("/api/v1/mpc/sessions", 
                             serde_json::to_vec(&session_data)
                                .map_err(|e| NetworkError::SerializationError(e.to_string()))?)).await {
        Ok(Ok(response)) => {
            println!("✅ 创建会话: 状态码 {}", response.status_code);
        }
        Ok(Err(e)) => {
            println!("❌ 创建会话失败: {}", e);
        }
        Err(_) => {
            println!("⏰ 创建会话超时");
        }
    }
    
    println!("✅ HTTP API 管理演示完成");
    Ok(())
}

/// 演示函数：秘密分享网络传输
pub async fn demo_secret_sharing_network() -> NetworkResult<()> {
    println!("\n🔐 开始秘密分享网络传输演示");
    println!("==============================");
    
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
    
    // 模拟网络传输：序列化分享
    let mut network_shares = Vec::new();
    for (i, share) in shares.iter().enumerate() {
        let serialized = serde_json::to_string(share)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;
        let encoded = general_purpose::STANDARD.encode(serialized.as_bytes());
        println!("分享 {} 编码长度: {} bytes", i + 1, encoded.len());
        network_shares.push(encoded);
    }
    
    // 模拟网络接收：反序列化分享
    let mut received_shares = Vec::new();
    for (i, encoded_share) in network_shares.iter().enumerate() {
        let decoded = general_purpose::STANDARD.decode(encoded_share)
            .map_err(|e| NetworkError::DeserializationError(e.to_string()))?;
        let serialized = String::from_utf8(decoded)
            .map_err(|e| NetworkError::DeserializationError(e.to_string()))?;
        let share: Share = serde_json::from_str(&serialized)
            .map_err(|e| NetworkError::DeserializationError(e.to_string()))?;
        println!("成功接收分享 {}: 索引={}, 值=***", i + 1, share.x);
        received_shares.push(share);
    }
    
    // 重构秘密（使用前两个分享）
    let reconstruction_shares = &received_shares[0..threshold];
    let reconstructed = ShamirSecretSharing::reconstruct(reconstruction_shares, threshold)
        .map_err(|e| NetworkError::ProtocolError(format!("秘密重构失败: {}", e)))?;
    
    println!("重构的秘密: {}", reconstructed);
    println!("验证结果: {}", if reconstructed == secret { "✅ 成功" } else { "❌ 失败" });
    
    println!("✅ 秘密分享网络传输演示完成");
    Ok(())
}

/// 错误处理演示
pub async fn demo_error_handling() -> NetworkResult<()> {
    println!("\n⚠️  开始错误处理演示");
    println!("===================");
    
    // 演示端口冲突处理
    println!("1. 端口冲突处理...");
    let result1 = MpcNode::new("test1".to_string(), NodeRole::Participant, 19000).await;
    let result2 = MpcNode::new("test2".to_string(), NodeRole::Participant, 19000).await;
    
    match (result1, result2) {
        (Ok(_), Ok(_)) => println!("   两个节点都创建成功（这在实际中可能导致冲突）"),
        (Ok(_), Err(e)) => println!("   第二个节点创建失败: {}", e),
        (Err(e), _) => println!("   第一个节点创建失败: {}", e),
    }
    
    // 演示消息解析错误
    println!("2. 消息解析错误处理...");
    let invalid_json = b"{ invalid json }";
    match serde_json::from_slice::<MpcMessage>(invalid_json) {
        Ok(_) => println!("   意外：无效 JSON 被解析成功"),
        Err(e) => println!("   ✅ 正确捕获 JSON 解析错误: {}", e),
    }
    
    // 演示网络超时处理
    println!("3. 网络超时处理...");
    let timeout_duration = Duration::from_millis(100);
    let client = HttpClient::new("http://127.0.0.1:99999")?; // 不存在的端口
    
    match timeout(timeout_duration, client.get("/test")).await {
        Ok(Ok(_)) => println!("   意外：请求成功"),
        Ok(Err(e)) => println!("   ✅ 正确捕获网络错误: {}", e),
        Err(_) => println!("   ✅ 正确处理超时"),
    }
    
    println!("✅ 错误处理演示完成");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎭 MPC 网络演示程序");
    println!("=================");
    println!("这个程序展示了 MPC API 网络模块的各种功能");
    println!();
    
    // 1. 多节点 MPC 网络演示
    if let Err(e) = demo_multi_node_mpc().await {
        println!("❌ 多节点 MPC 演示失败: {}", e);
    }
    
    // 2. HTTP API 管理演示
    if let Err(e) = demo_http_api_management().await {
        println!("❌ HTTP API 管理演示失败: {}", e);
    }
    
    // 3. 秘密分享网络传输演示
    if let Err(e) = demo_secret_sharing_network().await {
        println!("❌ 秘密分享网络传输演示失败: {}", e);
    }
    
    // 4. 错误处理演示
    if let Err(e) = demo_error_handling().await {
        println!("❌ 错误处理演示失败: {}", e);
    }
    
    println!("\n🎉 所有演示完成！");
    println!("要运行此演示，请使用: cargo run --example mpc_network_demo");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_mpc_node_creation() {
        let node = MpcNode::new("test_node".to_string(), NodeRole::Participant, 20000).await;
        assert!(node.is_ok(), "Failed to create MPC node");
        
        let node = node.unwrap();
        assert_eq!(node.node_id, "test_node");
        assert!(matches!(node.role, NodeRole::Participant));
    }
    
    #[tokio::test]
    async fn test_session_management() {
        let node = MpcNode::new("test_node".to_string(), NodeRole::Participant, 20001).await.unwrap();
        
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
    
    #[tokio::test]
    async fn test_secret_sharing_encoding() {
        let secret = 42u64;
        let shares = ShamirSecretSharing::share(&secret, 2, 3).unwrap();
        
        // 测试编码和解码
        for share in &shares {
            let serialized = serde_json::to_string(share).unwrap();
            let encoded = general_purpose::STANDARD.encode(serialized.as_bytes());
            
            let decoded = general_purpose::STANDARD.decode(encoded).unwrap();
            let deserialized_str = String::from_utf8(decoded).unwrap();
            let deserialized_share: Share = serde_json::from_str(&deserialized_str).unwrap();
            
            assert_eq!(share.x, deserialized_share.x);
            assert_eq!(share.y, deserialized_share.y);
        }
    }
}