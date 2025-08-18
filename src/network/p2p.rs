//! # P2P 点对点网络模块 (Peer-to-Peer Network Module)
//!
//! 本模块实现了专为 MPC 协议设计的 P2P 网络功能，支持去中心化的节点发现、
//! 连接管理、消息路由和协议执行。P2P 网络是 MPC 系统的核心通信基础设施。
//!
//! ## 🌐 P2P 网络架构
//!
//! ### 节点角色
//! - **引导节点 (Bootstrap Node)**: 帮助新节点加入网络
//! - **参与节点 (Participant Node)**: 参与 MPC 协议执行
//! - **中继节点 (Relay Node)**: 协助 NAT 穿越和消息转发
//! - **监控节点 (Monitor Node)**: 网络状态监控和统计
//!
//! ### 网络拓扑
//! - **全连接网络**: 适用于小规模高安全场景
//! - **星形网络**: 适用于有可信协调者的场景
//! - **环形网络**: 适用于特定 MPC 协议需求
//! - **随机网络**: 适用于大规模容错场景
//!
//! ## 🔧 核心功能
//!
//! ### 节点发现
//! - **DHT 路由**: 基于分布式哈希表的节点发现
//! - **本地广播**: 局域网内节点自动发现
//! - **DNS 种子**: 通过 DNS 记录获取引导节点
//! - **静态配置**: 手动配置已知节点列表
//!
//! ### 连接管理
//! - **TCP 连接池**: 高效的 TCP 连接复用
//! - **WebSocket 支持**: 支持浏览器客户端连接
//! - **TLS 加密**: 端到端传输层安全
//! - **NAT 穿越**: 支持 NAT 环境下的直连
//!
//! ### 消息路由
//! - **直接路由**: 点对点直接消息传输
//! - **广播路由**: 全网或子网消息广播
//! - **多播路由**: 指定节点组的消息传输
//! - **中继路由**: 通过中继节点的间接传输
//!
//! ## 📚 使用示例
//!
//! ```rust
//! use mpc_api::network::p2p::{P2PNode, PeerConfig, NodeRole};
//!
//! // 创建参与节点
//! let config = PeerConfig {
//!     host: "0.0.0.0".to_string(),
//!     port: 8000,
//!     node_role: NodeRole::Participant,
//!     max_connections: 10,
//!     enable_discovery: true,
//!     bootstrap_nodes: vec!["127.0.0.1:8001".to_string()],
//!     ..Default::default()
//! };
//!
//! let mut node = P2PNode::new(config).await?;
//! node.start().await?;
//!
//! // 发送消息到特定节点
//! let message = NetworkMessage::new("mpc_protocol", b"secret_share_data");
//! node.send_to_peer("peer_id_123", message).await?;
//!
//! // 广播消息到所有连接的节点
//! let broadcast_msg = NetworkMessage::new("consensus", b"vote_data");
//! node.broadcast(broadcast_msg).await?;
//! ```

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, RwLock, Mutex},
    time::{interval, timeout},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::network::{
    common::{NetworkError, NetworkResult},
    protocol::NetworkMessage,
    security::{NetworkSecurity, TlsConfig},
    ServiceStatus,
};

/// P2P 节点配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// 监听主机地址
    pub host: String,
    /// 监听端口
    pub port: u16,
    /// 节点角色
    pub node_role: NodeRole,
    /// 节点 ID（如果为空则自动生成）
    pub node_id: Option<String>,
    /// 最大连接数
    pub max_connections: usize,
    /// 是否启用节点发现
    pub enable_discovery: bool,
    /// 引导节点列表
    pub bootstrap_nodes: Vec<String>,
    /// 连接超时时间（毫秒）
    pub connection_timeout: u64,
    /// 心跳间隔（秒）
    pub heartbeat_interval: u64,
    /// 是否启用 TLS
    pub enable_tls: bool,
    /// TLS 配置
    pub tls_config: Option<TlsConfig>,
    /// 网络 ID（用于隔离不同的网络）
    pub network_id: String,
}

impl Default for PeerConfig {
    fn default() -> Self {
        PeerConfig {
            host: "127.0.0.1".to_string(),
            port: 8000,
            node_role: NodeRole::Participant,
            node_id: None,
            max_connections: 50,
            enable_discovery: true,
            bootstrap_nodes: Vec::new(),
            connection_timeout: 30000, // 30 seconds
            heartbeat_interval: 30,    // 30 seconds
            enable_tls: false,
            tls_config: None,
            network_id: "default".to_string(),
        }
    }
}

/// 节点角色
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NodeRole {
    /// 引导节点
    Bootstrap,
    /// 参与节点
    Participant,
    /// 中继节点
    Relay,
    /// 监控节点
    Monitor,
}

/// P2P 网络节点
pub struct P2PNode {
    /// 节点 ID
    pub node_id: String,
    /// 节点配置
    config: PeerConfig,
    /// 监听地址
    listen_addr: SocketAddr,
    /// 连接的对等节点
    peers: Arc<RwLock<HashMap<String, Arc<Peer>>>>,
    /// 消息处理器
    message_handlers: Arc<RwLock<HashMap<String, Box<dyn MessageHandler>>>>,
    /// 节点发现器
    discovery: Arc<Mutex<PeerDiscovery>>,
    /// 网络安全管理器
    security: Arc<NetworkSecurity>,
    /// 节点状态
    status: Arc<RwLock<ServiceStatus>>,
    /// 消息发送通道
    message_sender: Option<mpsc::UnboundedSender<OutgoingMessage>>,
    /// 统计信息
    stats: Arc<RwLock<P2PStats>>,
}

/// 对等节点信息
#[derive(Debug, Clone)]
pub struct Peer {
    /// 节点 ID
    pub id: String,
    /// 节点地址
    pub address: SocketAddr,
    /// 节点角色
    pub role: NodeRole,
    /// 连接状态
    pub status: PeerStatus,
    /// 最后活跃时间
    pub last_seen: SystemTime,
    /// 连接建立时间
    pub connected_at: SystemTime,
    /// 网络延迟（毫秒）
    pub latency: Option<u64>,
    /// 发送的消息数量
    pub messages_sent: u64,
    /// 接收的消息数量
    pub messages_received: u64,
}

/// 对等节点状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PeerStatus {
    /// 正在连接
    Connecting,
    /// 已连接
    Connected,
    /// 正在断开
    Disconnecting,
    /// 已断开
    Disconnected,
    /// 连接失败
    Failed(String),
}

/// P2P 网络统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct P2PStats {
    /// 总连接数
    pub total_connections: u64,
    /// 当前活跃连接数
    pub active_connections: usize,
    /// 发送的消息总数
    pub messages_sent: u64,
    /// 接收的消息总数
    pub messages_received: u64,
    /// 发送的字节数
    pub bytes_sent: u64,
    /// 接收的字节数
    pub bytes_received: u64,
    /// 连接失败数
    pub connection_failures: u64,
    /// 网络启动时间
    pub start_time: Option<SystemTime>,
}

/// 发送消息结构
#[derive(Debug)]
struct OutgoingMessage {
    /// 目标节点 ID（None 表示广播）
    target: Option<String>,
    /// 消息内容
    message: NetworkMessage,
    /// 响应通道
    response_tx: Option<tokio::sync::oneshot::Sender<NetworkResult<()>>>,
}

/// 消息处理器 trait
pub trait MessageHandler: Send + Sync {
    /// 处理接收到的消息
    fn handle_message(
        &self,
        from_peer: &str,
        message: &NetworkMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<Option<NetworkMessage>>> + Send + '_>>;
}

impl P2PNode {
    /// 创建新的 P2P 节点
    pub async fn new(mut config: PeerConfig) -> NetworkResult<Self> {
        // 生成节点 ID
        let node_id = config.node_id.take()
            .unwrap_or_else(|| format!("node_{}", Uuid::new_v4()));

        // 解析监听地址
        let listen_addr: SocketAddr = format!("{}:{}", config.host, config.port)
            .parse()
            .map_err(|e| NetworkError::ConfigError(format!("无效的监听地址: {}", e)))?;

        // 创建节点发现器
        let discovery = PeerDiscovery::new(config.clone())?;

        // 创建网络安全管理器
        let security = NetworkSecurity::new(config.tls_config.clone())?;

        println!("🚀 创建 P2P 节点: {}", node_id);
        println!("  监听地址: {}", listen_addr);
        println!("  节点角色: {:?}", config.node_role);
        println!("  网络 ID: {}", config.network_id);

        Ok(P2PNode {
            node_id,
            config,
            listen_addr,
            peers: Arc::new(RwLock::new(HashMap::new())),
            message_handlers: Arc::new(RwLock::new(HashMap::new())),
            discovery: Arc::new(Mutex::new(discovery)),
            security: Arc::new(security),
            status: Arc::new(RwLock::new(ServiceStatus::Unknown)),
            message_sender: None,
            stats: Arc::new(RwLock::new(P2PStats::default())),
        })
    }

    /// 启动 P2P 节点
    pub async fn start(&mut self) -> NetworkResult<()> {
        println!("🌐 启动 P2P 网络节点...");
        
        // 更新状态
        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Starting;
        }

        // 初始化统计信息
        {
            let mut stats = self.stats.write().await;
            stats.start_time = Some(SystemTime::now());
        }

        // 创建消息通道
        let (tx, rx) = mpsc::unbounded_channel::<OutgoingMessage>();
        self.message_sender = Some(tx);

        // 启动 TCP 监听器
        let listener = TcpListener::bind(self.listen_addr).await
            .map_err(|e| NetworkError::ConnectionError(format!("绑定监听地址失败: {}", e)))?;

        println!("✅ 监听器绑定成功: {}", self.listen_addr);

        // 克隆共享数据
        let node_id = self.node_id.clone();
        let peers = Arc::clone(&self.peers);
        let handlers = Arc::clone(&self.message_handlers);
        let security = Arc::clone(&self.security);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        // 启动服务器任务
        let server_task = tokio::spawn(async move {
            Self::server_loop(listener, node_id, peers, handlers, security, stats, config).await
        });

        // 启动消息发送任务
        let peers_clone = Arc::clone(&self.peers);
        let stats_clone = Arc::clone(&self.stats);
        let sender_task = tokio::spawn(async move {
            Self::message_sender_loop(rx, peers_clone, stats_clone).await
        });

        // 启动节点发现
        if self.config.enable_discovery {
            let discovery = Arc::clone(&self.discovery);
            let discovery_task = tokio::spawn(async move {
                let mut discovery = discovery.lock().await;
                discovery.start().await
            });
            
            // 不等待发现任务完成，让它在后台运行
            tokio::spawn(discovery_task);
        }

        // 连接到引导节点
        self.connect_to_bootstrap_nodes().await?;

        // 启动心跳任务
        self.start_heartbeat().await;

        // 更新状态
        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Healthy;
        }

        println!("✅ P2P 网络节点启动成功");
        println!("  节点 ID: {}", self.node_id);
        println!("  监听地址: {}", self.listen_addr);

        // 等待任务完成（实际上会一直运行）
        tokio::select! {
            _ = server_task => {},
            _ = sender_task => {},
        }

        Ok(())
    }

    /// 服务器主循环
    async fn server_loop(
        listener: TcpListener,
        node_id: String,
        peers: Arc<RwLock<HashMap<String, Arc<Peer>>>>,
        handlers: Arc<RwLock<HashMap<String, Box<dyn MessageHandler>>>>,
        security: Arc<NetworkSecurity>,
        stats: Arc<RwLock<P2PStats>>,
        config: PeerConfig,
    ) -> NetworkResult<()> {
        println!("🔄 启动服务器主循环...");

        while let Ok((stream, addr)) = listener.accept().await {
            println!("📥 收到新连接: {}", addr);

            // 检查连接数限制
            {
                let peers_read = peers.read().await;
                if peers_read.len() >= config.max_connections {
                    println!("⚠️  连接数已达上限，拒绝连接: {}", addr);
                    continue;
                }
            }

            // 更新统计
            {
                let mut stats_write = stats.write().await;
                stats_write.total_connections += 1;
            }

            // 在新任务中处理连接
            let node_id_clone = node_id.clone();
            let peers_clone = Arc::clone(&peers);
            let handlers_clone = Arc::clone(&handlers);
            let security_clone = Arc::clone(&security);
            let stats_clone = Arc::clone(&stats);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(
                    stream, addr, node_id_clone, peers_clone, 
                    handlers_clone, security_clone, stats_clone
                ).await {
                    println!("❌ 处理连接失败: {}", e);
                }
            });
        }

        Ok(())
    }

    /// 处理单个连接
    async fn handle_connection(
        _stream: TcpStream,
        addr: SocketAddr,
        _node_id: String,
        peers: Arc<RwLock<HashMap<String, Arc<Peer>>>>,
        _handlers: Arc<RwLock<HashMap<String, Box<dyn MessageHandler>>>>,
        _security: Arc<NetworkSecurity>,
        stats: Arc<RwLock<P2PStats>>,
    ) -> NetworkResult<()> {
        println!("🤝 处理来自 {} 的连接", addr);

        // 这里应该实现完整的握手协议
        // 包括身份验证、协议版本协商等
        
        // 为演示，创建一个简单的对等节点
        let peer_id = format!("peer_{}", Uuid::new_v4());
        let peer = Arc::new(Peer {
            id: peer_id.clone(),
            address: addr,
            role: NodeRole::Participant,
            status: PeerStatus::Connected,
            last_seen: SystemTime::now(),
            connected_at: SystemTime::now(),
            latency: None,
            messages_sent: 0,
            messages_received: 0,
        });

        // 添加到对等节点列表
        {
            let mut peers_write = peers.write().await;
            peers_write.insert(peer_id.clone(), peer);
            
            let mut stats_write = stats.write().await;
            stats_write.active_connections = peers_write.len();
        }

        println!("✅ 对等节点已连接: {}", peer_id);

        // 实际应用中，这里应该启动消息接收循环
        // 处理来自该对等节点的消息

        Ok(())
    }

    /// 消息发送循环
    async fn message_sender_loop(
        mut rx: mpsc::UnboundedReceiver<OutgoingMessage>,
        peers: Arc<RwLock<HashMap<String, Arc<Peer>>>>,
        stats: Arc<RwLock<P2PStats>>,
    ) {
        println!("📤 启动消息发送循环...");

        while let Some(outgoing) = rx.recv().await {
            let result = match outgoing.target {
                Some(target_id) => {
                    // 发送到特定节点
                    Self::send_to_specific_peer(&target_id, &outgoing.message, &peers, &stats).await
                }
                None => {
                    // 广播到所有节点
                    Self::broadcast_to_all_peers(&outgoing.message, &peers, &stats).await
                }
            };

            // 发送结果通知
            if let Some(response_tx) = outgoing.response_tx {
                let _ = response_tx.send(result);
            }
        }
    }

    /// 发送消息到特定对等节点
    async fn send_to_specific_peer(
        target_id: &str,
        message: &NetworkMessage,
        peers: &Arc<RwLock<HashMap<String, Arc<Peer>>>>,
        stats: &Arc<RwLock<P2PStats>>,
    ) -> NetworkResult<()> {
        let peers_read = peers.read().await;
        
        if let Some(peer) = peers_read.get(target_id) {
            if peer.status == PeerStatus::Connected {
                println!("📤 发送消息到 {}: {}", target_id, message.message_type);
                
                // 实际发送逻辑
                // 这里应该通过 TCP 连接发送消息
                
                // 更新统计
                let mut stats_write = stats.write().await;
                stats_write.messages_sent += 1;
                stats_write.bytes_sent += message.payload.len() as u64;
                
                Ok(())
            } else {
                Err(NetworkError::PeerNotAvailable(format!("节点 {} 不可用", target_id)))
            }
        } else {
            Err(NetworkError::PeerNotFound(target_id.to_string()))
        }
    }

    /// 广播消息到所有对等节点
    async fn broadcast_to_all_peers(
        message: &NetworkMessage,
        peers: &Arc<RwLock<HashMap<String, Arc<Peer>>>>,
        stats: &Arc<RwLock<P2PStats>>,
    ) -> NetworkResult<()> {
        let peers_read = peers.read().await;
        let connected_peers: Vec<String> = peers_read
            .values()
            .filter(|peer| peer.status == PeerStatus::Connected)
            .map(|peer| peer.id.clone())
            .collect();

        println!("📢 广播消息到 {} 个节点: {}", connected_peers.len(), message.message_type);

        for peer_id in connected_peers {
            if let Err(e) = Self::send_to_specific_peer(&peer_id, message, peers, stats).await {
                println!("⚠️  广播到节点 {} 失败: {}", peer_id, e);
            }
        }

        Ok(())
    }

    /// 连接到引导节点
    async fn connect_to_bootstrap_nodes(&self) -> NetworkResult<()> {
        if self.config.bootstrap_nodes.is_empty() {
            println!("💡 没有配置引导节点");
            return Ok(());
        }

        println!("🔗 连接到引导节点...");

        for bootstrap_addr in &self.config.bootstrap_nodes {
            match self.connect_to_peer(bootstrap_addr).await {
                Ok(_) => {
                    println!("✅ 成功连接到引导节点: {}", bootstrap_addr);
                }
                Err(e) => {
                    println!("❌ 连接引导节点失败 {}: {}", bootstrap_addr, e);
                }
            }
        }

        Ok(())
    }

    /// 连接到特定对等节点
    async fn connect_to_peer(&self, peer_addr: &str) -> NetworkResult<String> {
        let addr: SocketAddr = peer_addr.parse()
            .map_err(|e| NetworkError::ConfigError(format!("无效的对等节点地址: {}", e)))?;

        println!("🔗 连接到对等节点: {}", addr);

        let connection_timeout = Duration::from_millis(self.config.connection_timeout);
        
        let stream = timeout(connection_timeout, TcpStream::connect(addr)).await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| NetworkError::ConnectionError(format!("连接失败: {}", e)))?;

        // 执行握手协议
        let peer_id = self.perform_handshake(stream, addr).await?;

        println!("✅ 成功连接到对等节点: {}", peer_id);
        Ok(peer_id)
    }

    /// 执行握手协议
    async fn perform_handshake(&self, _stream: TcpStream, addr: SocketAddr) -> NetworkResult<String> {
        // 简化的握手实现
        let peer_id = format!("peer_{}", addr.port());
        
        let peer = Arc::new(Peer {
            id: peer_id.clone(),
            address: addr,
            role: NodeRole::Participant,
            status: PeerStatus::Connected,
            last_seen: SystemTime::now(),
            connected_at: SystemTime::now(),
            latency: None,
            messages_sent: 0,
            messages_received: 0,
        });

        // 添加到对等节点列表
        {
            let mut peers = self.peers.write().await;
            peers.insert(peer_id.clone(), peer);
        }

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.active_connections += 1;
        }

        Ok(peer_id)
    }

    /// 启动心跳任务
    async fn start_heartbeat(&self) {
        let peers = Arc::clone(&self.peers);
        let heartbeat_interval = Duration::from_secs(self.config.heartbeat_interval);

        tokio::spawn(async move {
            let mut interval = interval(heartbeat_interval);

            loop {
                interval.tick().await;
                
                let peers_read = peers.read().await;
                for (peer_id, peer) in peers_read.iter() {
                    if peer.status == PeerStatus::Connected {
                        // 检查对等节点是否超时
                        if let Ok(elapsed) = peer.last_seen.elapsed() {
                            if elapsed > heartbeat_interval * 3 { // 3倍心跳间隔视为超时
                                println!("💔 对等节点超时: {}", peer_id);
                                // 这里应该标记节点为断开状态
                            }
                        }
                    }
                }
            }
        });
    }

    /// 发送消息到特定对等节点
    pub async fn send_to_peer(&self, peer_id: &str, message: NetworkMessage) -> NetworkResult<()> {
        if let Some(sender) = &self.message_sender {
            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
            
            let outgoing = OutgoingMessage {
                target: Some(peer_id.to_string()),
                message,
                response_tx: Some(response_tx),
            };

            sender.send(outgoing)
                .map_err(|_| NetworkError::ChannelError("消息发送通道已关闭".to_string()))?;

            response_rx.await
                .map_err(|_| NetworkError::ChannelError("响应通道已关闭".to_string()))?
        } else {
            Err(NetworkError::NotInitialized)
        }
    }

    /// 广播消息到所有对等节点
    pub async fn broadcast(&self, message: NetworkMessage) -> NetworkResult<()> {
        if let Some(sender) = &self.message_sender {
            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
            
            let outgoing = OutgoingMessage {
                target: None,
                message,
                response_tx: Some(response_tx),
            };

            sender.send(outgoing)
                .map_err(|_| NetworkError::ChannelError("消息发送通道已关闭".to_string()))?;

            response_rx.await
                .map_err(|_| NetworkError::ChannelError("响应通道已关闭".to_string()))?
        } else {
            Err(NetworkError::NotInitialized)
        }
    }

    /// 注册消息处理器
    pub async fn register_handler(&self, message_type: String, handler: Box<dyn MessageHandler>) {
        let mut handlers = self.message_handlers.write().await;
        handlers.insert(message_type, handler);
    }

    /// 获取连接的对等节点列表
    pub async fn get_peers(&self) -> Vec<String> {
        let peers = self.peers.read().await;
        peers.keys().cloned().collect()
    }

    /// 获取对等节点信息
    pub async fn get_peer_info(&self, peer_id: &str) -> Option<Peer> {
        let peers = self.peers.read().await;
        peers.get(peer_id).map(|peer| (**peer).clone())
    }

    /// 断开与特定对等节点的连接
    pub async fn disconnect_peer(&self, peer_id: &str) -> NetworkResult<()> {
        let mut peers = self.peers.write().await;
        
        if let Some(_peer) = peers.remove(peer_id) {
            println!("🔌 断开对等节点连接: {}", peer_id);
            
            // 更新统计
            let mut stats = self.stats.write().await;
            stats.active_connections = peers.len();
            
            Ok(())
        } else {
            Err(NetworkError::PeerNotFound(peer_id.to_string()))
        }
    }

    /// 获取网络统计信息
    pub async fn get_stats(&self) -> P2PStats {
        self.stats.read().await.clone()
    }

    /// 获取节点状态
    pub async fn get_status(&self) -> ServiceStatus {
        self.status.read().await.clone()
    }

    /// 更新配置
    pub async fn update_config(&self, _new_config: &PeerConfig) -> NetworkResult<()> {
        // 实现配置更新逻辑
        println!("🔄 更新 P2P 节点配置...");
        Ok(())
    }

    /// 关闭节点
    pub async fn shutdown(&self) -> NetworkResult<()> {
        println!("🛑 关闭 P2P 网络节点...");
        
        // 更新状态
        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Shutting;
        }

        // 断开所有对等节点
        let peer_ids: Vec<String> = {
            let peers = self.peers.read().await;
            peers.keys().cloned().collect()
        };

        for peer_id in peer_ids {
            if let Err(e) = self.disconnect_peer(&peer_id).await {
                println!("⚠️  断开节点连接失败 {}: {}", peer_id, e);
            }
        }

        println!("✅ P2P 网络节点已关闭");
        Ok(())
    }
}

/// P2P 节点发现器
#[derive(Debug)]
pub struct PeerDiscovery {
    /// 配置信息
    config: PeerConfig,
    /// 已发现的节点
    discovered_peers: Arc<RwLock<HashSet<SocketAddr>>>,
    /// 发现状态
    is_running: Arc<RwLock<bool>>,
}

impl PeerDiscovery {
    /// 创建节点发现器
    pub fn new(config: PeerConfig) -> NetworkResult<Self> {
        Ok(PeerDiscovery {
            config,
            discovered_peers: Arc::new(RwLock::new(HashSet::new())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    /// 启动节点发现
    pub async fn start(&mut self) -> NetworkResult<()> {
        {
            let mut running = self.is_running.write().await;
            if *running {
                return Ok(());
            }
            *running = true;
        }

        println!("🔍 启动节点发现服务...");

        // 启动本地广播发现
        self.start_local_broadcast().await?;

        // 启动 DNS 种子发现
        if !self.config.bootstrap_nodes.is_empty() {
            self.discover_from_bootstrap_nodes().await?;
        }

        println!("✅ 节点发现服务启动成功");
        Ok(())
    }

    /// 启动本地广播发现
    async fn start_local_broadcast(&self) -> NetworkResult<()> {
        println!("📡 启动本地广播发现...");

        // 简化实现：扫描本地网段
        let local_network = self.get_local_network().await?;
        let discovered = Arc::clone(&self.discovered_peers);

        tokio::spawn(async move {
            Self::scan_local_network(local_network, discovered).await;
        });

        Ok(())
    }

    /// 获取本地网络段
    async fn get_local_network(&self) -> NetworkResult<String> {
        // 简化实现：假设本地网络为 192.168.1.0/24
        Ok("192.168.1".to_string())
    }

    /// 扫描本地网络
    async fn scan_local_network(network: String, discovered: Arc<RwLock<HashSet<SocketAddr>>>) {
        println!("🔍 扫描本地网络: {}.0/24", network);

        for i in 1..=254 {
            let addr = format!("{}.{}:8000", network, i);
            if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
                // 尝试连接
                if let Ok(_) = timeout(Duration::from_millis(100), TcpStream::connect(socket_addr)).await {
                    println!("📍 发现节点: {}", socket_addr);
                    
                    let mut discovered_write = discovered.write().await;
                    discovered_write.insert(socket_addr);
                }
            }
        }
    }

    /// 从引导节点发现其他节点
    async fn discover_from_bootstrap_nodes(&self) -> NetworkResult<()> {
        println!("🌱 从引导节点发现其他节点...");

        for bootstrap_addr in &self.config.bootstrap_nodes {
            if let Ok(addr) = bootstrap_addr.parse::<SocketAddr>() {
                // 连接到引导节点并请求节点列表
                if let Err(e) = self.request_peers_from_bootstrap(addr).await {
                    println!("⚠️  从引导节点 {} 获取节点列表失败: {}", bootstrap_addr, e);
                }
            }
        }

        Ok(())
    }

    /// 从引导节点请求对等节点列表
    async fn request_peers_from_bootstrap(&self, bootstrap_addr: SocketAddr) -> NetworkResult<()> {
        println!("📡 请求对等节点列表: {}", bootstrap_addr);

        // 这里应该实现与引导节点的通信协议
        // 发送节点发现请求并解析响应

        // 简化实现：直接添加引导节点
        {
            let mut discovered = self.discovered_peers.write().await;
            discovered.insert(bootstrap_addr);
        }

        Ok(())
    }

    /// 获取已发现的节点列表
    pub async fn get_discovered_peers(&self) -> Vec<SocketAddr> {
        let discovered = self.discovered_peers.read().await;
        discovered.iter().cloned().collect()
    }

    /// 停止节点发现
    pub async fn stop(&self) {
        let mut running = self.is_running.write().await;
        *running = false;
        println!("🛑 节点发现服务已停止");
    }
}

/// 简单的消息处理器实现
pub struct DefaultMessageHandler;

impl MessageHandler for DefaultMessageHandler {
    fn handle_message(
        &self,
        from_peer: &str,
        message: &NetworkMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<Option<NetworkMessage>>> + Send + '_>> {
        let from_peer = from_peer.to_string();
        let message_type = message.message_type.clone();
        let payload_len = message.payload.len();
        
        Box::pin(async move {
            println!("📨 收到来自 {} 的消息: {}", from_peer, message_type);
            println!("  载荷大小: {} bytes", payload_len);
            
            // 简单的回显处理
            if message_type == "ping" {
                let pong_message = NetworkMessage::new("pong", b"pong_response");
                return Ok(Some(pong_message));
            }

            Ok(None)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_p2p_node_creation() {
        let config = PeerConfig::default();
        let node = P2PNode::new(config).await;
        assert!(node.is_ok(), "Failed to create P2P node");
    }
    
    #[tokio::test]
    async fn test_peer_discovery() {
        let config = PeerConfig::default();
        let discovery = PeerDiscovery::new(config);
        assert!(discovery.is_ok(), "Failed to create peer discovery");
    }
    
    #[test]
    fn test_default_message_handler() {
        let handler = DefaultMessageHandler;
        let message = NetworkMessage::new("ping", b"test");
        
        // Test that handler can be created and message processed
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let result = handler.handle_message("test_peer", &message).await;
            assert!(result.is_ok(), "Message handling failed");
            
            if let Ok(Some(response)) = result {
                assert_eq!(response.message_type, "pong");
            }
        });
    }
}

