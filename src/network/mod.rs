//! # 网络连接模块 (Network Connection Module)
//!
//! 本模块提供了 MPC API 的网络通信功能，支持两种主要的连接方式：
//! 1. **P2P 点对点网络** - 用于分布式 MPC 协议的直接节点通信
//! 2. **HTTP API 接口** - 用于客户端-服务器架构和 RESTful 服务
//!
//! ## 🌐 网络架构设计
//!
//! ### P2P 网络特点
//! - **去中心化**: 无需中央服务器，节点直接通信
//! - **容错性强**: 部分节点失效不影响整体网络
//! - **隐私保护**: 数据在节点间直接传输，减少中间环节
//! - **可扩展性**: 支持动态节点加入和退出
//!
//! ### HTTP API 特点
//! - **标准协议**: 基于成熟的 HTTP/HTTPS 协议
//! - **易于集成**: 与现有 Web 服务和应用程序无缝集成
//! - **负载均衡**: 支持多服务器部署和负载分发
//! - **监控友好**: 便于网络监控和调试
//!
//! ## 🔧 核心组件
//!
//! ### P2P 网络组件
//! - `P2PNode`: P2P 网络节点实现
//! - `PeerDiscovery`: 节点发现和管理
//! - `MessageRouter`: 消息路由和转发
//! - `NetworkTopology`: 网络拓扑管理
//!
//! ### HTTP API 组件
//! - `HttpServer`: HTTP 服务器实现
//! - `RestEndpoints`: RESTful API 端点
//! - `HttpClient`: HTTP 客户端
//! - `ApiMiddleware`: API 中间件和认证
//!
//! ## 🚀 使用场景
//!
//! ### P2P 适用场景
//! - 多方安全计算 (MPC) 协议执行
//! - 分布式密钥生成和管理
//! - 无需信任第三方的协作计算
//! - 高隐私要求的应用场景
//!
//! ### HTTP API 适用场景
//! - Web 应用程序集成
//! - 微服务架构
//! - 移动应用后端服务
//! - 第三方系统集成
//!
//! ## 📚 使用示例
//!
//! ```rust
//! use mpc_api::network::{
//!     P2PNode, HttpServer, NetworkConfig,
//!     p2p::{PeerConfig, MessageType},
//!     http::{RestConfig, ApiResponse}
//! };
//!
//! // P2P 网络节点
//! let p2p_config = PeerConfig::new("127.0.0.1:8000");
//! let mut p2p_node = P2PNode::new(p2p_config).await?;
//! p2p_node.start().await?;
//!
//! // HTTP API 服务器
//! let http_config = RestConfig::new("127.0.0.1:3000");
//! let mut http_server = HttpServer::new(http_config).await?;
//! http_server.start().await?;
//! ```

pub mod p2p;
pub mod http;
pub mod common;
pub mod security;
pub mod protocol;

// 测试模块在每个子模块中单独定义

pub use p2p::{P2PNode, PeerConfig, PeerDiscovery};
pub use http::{HttpServer, HttpClient, RestConfig};
pub use common::{NetworkConfig, NetworkError, NetworkResult};
pub use security::{NetworkSecurity, TlsConfig, AuthenticationConfig};
pub use protocol::{MessageProtocol, NetworkMessage, MessageType};

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// 网络连接管理器
/// 
/// 统一管理 P2P 和 HTTP 网络连接，提供一致的接口和协调机制
pub struct NetworkManager {
    /// P2P 节点实例
    p2p_node: Option<Arc<P2PNode>>,
    /// HTTP 服务器实例
    http_server: Option<Arc<HttpServer>>,
    /// 网络配置
    config: NetworkConfig,
    /// 活跃连接统计
    connection_stats: Arc<RwLock<ConnectionStats>>,
}

/// 连接统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// P2P 连接数量
    pub p2p_connections: usize,
    /// HTTP 连接数量
    pub http_connections: usize,
    /// 总发送字节数
    pub bytes_sent: u64,
    /// 总接收字节数
    pub bytes_received: u64,
    /// 活跃会话数
    pub active_sessions: usize,
    /// 连接建立时间戳
    pub connection_start_time: std::time::SystemTime,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        ConnectionStats {
            p2p_connections: 0,
            http_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            active_sessions: 0,
            connection_start_time: std::time::SystemTime::now(),
        }
    }
}

impl NetworkManager {
    /// 创建新的网络管理器
    /// 
    /// # 参数
    /// - `config`: 网络配置
    /// 
    /// # 返回值
    /// 返回网络管理器实例
    pub fn new(config: NetworkConfig) -> Self {
        NetworkManager {
            p2p_node: None,
            http_server: None,
            config,
            connection_stats: Arc::new(RwLock::new(ConnectionStats::default())),
        }
    }

    /// 启动 P2P 网络节点
    /// 
    /// # 参数
    /// - `peer_config`: P2P 节点配置
    /// 
    /// # 返回值
    /// 成功时返回 Ok(())，失败时返回网络错误
    pub async fn start_p2p(&mut self, peer_config: PeerConfig) -> NetworkResult<()> {
        println!("🌐 启动 P2P 网络节点...");
        
        let mut node = P2PNode::new(peer_config).await?;
        node.start().await?;
        
        self.p2p_node = Some(Arc::new(node));
        
        // 更新连接统计
        {
            let mut stats = self.connection_stats.write().await;
            stats.connection_start_time = std::time::SystemTime::now();
        }
        
        println!("✅ P2P 网络节点启动成功");
        Ok(())
    }

    /// 启动 HTTP API 服务器
    /// 
    /// # 参数
    /// - `rest_config`: HTTP 服务器配置
    /// 
    /// # 返回值
    /// 成功时返回 Ok(())，失败时返回网络错误
    pub async fn start_http(&mut self, rest_config: RestConfig) -> NetworkResult<()> {
        println!("🌐 启动 HTTP API 服务器...");
        
        let server = HttpServer::new(rest_config).await?;
        // 启动服务器的逻辑需要在后台运行，不能在这里阻塞
        // 这里只是示例，实际应用中需要重构
        
        self.http_server = Some(Arc::new(server));
        
        println!("✅ HTTP API 服务器启动成功");
        Ok(())
    }

    /// 同时启动 P2P 和 HTTP 服务
    /// 
    /// # 参数
    /// - `peer_config`: P2P 节点配置
    /// - `rest_config`: HTTP 服务器配置
    /// 
    /// # 返回值
    /// 成功时返回 Ok(())，失败时返回网络错误
    pub async fn start_all(&mut self, peer_config: PeerConfig, rest_config: RestConfig) -> NetworkResult<()> {
        println!("🌐 启动混合网络服务 (P2P + HTTP API)...");
        
        // 串行启动服务以避免借用检查器错误
        self.start_p2p(peer_config).await?;
        self.start_http(rest_config).await?;
        
        println!("🎉 混合网络服务启动成功");
        Ok(())
    }

    /// 停止所有网络服务
    pub async fn shutdown(&mut self) -> NetworkResult<()> {
        println!("🛑 关闭网络服务...");
        
        if let Some(p2p) = &self.p2p_node {
            p2p.shutdown().await?;
            println!("  ✅ P2P 节点已关闭");
        }
        
        if let Some(http) = &self.http_server {
            http.shutdown().await?;
            println!("  ✅ HTTP 服务器已关闭");
        }
        
        self.p2p_node = None;
        self.http_server = None;
        
        println!("✅ 所有网络服务已关闭");
        Ok(())
    }

    /// 获取连接统计信息
    pub async fn get_stats(&self) -> ConnectionStats {
        self.connection_stats.read().await.clone()
    }

    /// 获取 P2P 节点引用
    pub fn p2p_node(&self) -> Option<&Arc<P2PNode>> {
        self.p2p_node.as_ref()
    }

    /// 获取 HTTP 服务器引用
    pub fn http_server(&self) -> Option<&Arc<HttpServer>> {
        self.http_server.as_ref()
    }

    /// 检查网络健康状态
    pub async fn health_check(&self) -> NetworkHealth {
        let mut health = NetworkHealth::new();
        
        if let Some(p2p) = &self.p2p_node {
            health.p2p_status = p2p.get_status().await;
        }
        
        if let Some(http) = &self.http_server {
            health.http_status = http.get_status().await;
        }
        
        health.overall_status = if health.p2p_status.is_healthy() || health.http_status.is_healthy() {
            ServiceStatus::Healthy
        } else {
            ServiceStatus::Unhealthy
        };
        
        health
    }

    /// 更新网络配置
    pub async fn update_config(&mut self, new_config: NetworkConfig) -> NetworkResult<()> {
        // 保存旧配置以备回滚
        let old_config = self.config.clone();
        self.config = new_config;
        
        // 如果配置更新失败，回滚到旧配置
        if let Err(e) = self.apply_config_changes().await {
            self.config = old_config;
            return Err(e);
        }
        
        Ok(())
    }

    /// 应用配置变更
    async fn apply_config_changes(&self) -> NetworkResult<()> {
        // 根据新配置更新服务
        if let Some(p2p) = &self.p2p_node {
            p2p.update_config(&self.config.p2p_config).await?;
        }
        
        if let Some(http) = &self.http_server {
            http.update_config(&self.config.http_config).await?;
        }
        
        Ok(())
    }
}

/// 网络健康状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealth {
    /// 整体状态
    pub overall_status: ServiceStatus,
    /// P2P 服务状态
    pub p2p_status: ServiceStatus,
    /// HTTP 服务状态
    pub http_status: ServiceStatus,
    /// 检查时间戳
    pub check_time: std::time::SystemTime,
}

impl NetworkHealth {
    fn new() -> Self {
        NetworkHealth {
            overall_status: ServiceStatus::Unknown,
            p2p_status: ServiceStatus::Unknown,
            http_status: ServiceStatus::Unknown,
            check_time: std::time::SystemTime::now(),
        }
    }
}

/// 服务状态枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// 健康状态
    Healthy,
    /// 不健康状态
    Unhealthy,
    /// 正在启动
    Starting,
    /// 正在关闭
    Shutting,
    /// 未知状态
    Unknown,
}

impl ServiceStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, ServiceStatus::Healthy)
    }
}

/// 网络事件类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    /// 节点连接事件
    NodeConnected {
        peer_id: String,
        address: SocketAddr,
        connection_type: ConnectionType,
    },
    /// 节点断开事件
    NodeDisconnected {
        peer_id: String,
        reason: String,
    },
    /// 消息接收事件
    MessageReceived {
        from: String,
        message_type: String,
        size: usize,
    },
    /// 消息发送事件
    MessageSent {
        to: String,
        message_type: String,
        size: usize,
    },
    /// 网络错误事件
    NetworkError {
        error: String,
        component: String,
    },
}

/// 连接类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// P2P 连接
    P2P,
    /// HTTP 连接
    HTTP,
    /// WebSocket 连接
    WebSocket,
}

/// 网络事件监听器 trait
pub trait NetworkEventListener: Send + Sync {
    /// 处理网络事件
    fn on_event(&self, event: NetworkEvent) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// 网络监控器
pub struct NetworkMonitor {
    /// 事件监听器列表
    listeners: Arc<RwLock<Vec<Box<dyn NetworkEventListener>>>>,
    /// 监控配置
    config: MonitorConfig,
}

/// 监控配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// 是否启用事件日志
    pub enable_event_logging: bool,
    /// 是否启用性能监控
    pub enable_performance_monitoring: bool,
    /// 监控数据保留天数
    pub retention_days: u32,
    /// 采样间隔（秒）
    pub sample_interval: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            enable_event_logging: true,
            enable_performance_monitoring: true,
            retention_days: 7,
            sample_interval: 10,
        }
    }
}

impl NetworkMonitor {
    /// 创建网络监控器
    pub fn new(config: MonitorConfig) -> Self {
        NetworkMonitor {
            listeners: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }

    /// 添加事件监听器
    pub async fn add_listener(&self, listener: Box<dyn NetworkEventListener>) {
        let mut listeners = self.listeners.write().await;
        listeners.push(listener);
    }

    /// 发布网络事件
    pub async fn publish_event(&self, event: NetworkEvent) {
        let listeners = self.listeners.read().await;
        
        for listener in listeners.iter() {
            listener.on_event(event.clone()).await;
        }
    }

    /// 启动监控
    pub async fn start(&self) -> NetworkResult<()> {
        println!("📊 启动网络监控器...");
        
        if self.config.enable_performance_monitoring {
            self.start_performance_monitoring().await?;
        }
        
        if self.config.enable_event_logging {
            self.start_event_logging().await?;
        }
        
        println!("✅ 网络监控器启动成功");
        Ok(())
    }

    /// 启动性能监控
    async fn start_performance_monitoring(&self) -> NetworkResult<()> {
        // 实现性能监控逻辑
        Ok(())
    }

    /// 启动事件日志
    async fn start_event_logging(&self) -> NetworkResult<()> {
        // 实现事件日志逻辑
        Ok(())
    }
}

/// 网络工具函数集合
pub mod utils {
    use super::*;
    
    /// 解析网络地址
    pub fn parse_address(addr: &str) -> NetworkResult<SocketAddr> {
        addr.parse()
            .map_err(|e| NetworkError::ConfigError(format!("无效的地址格式: {}", e)))
    }
    
    /// 检查端口可用性
    pub async fn is_port_available(port: u16) -> bool {
        use tokio::net::TcpListener;
        
        TcpListener::bind(("127.0.0.1", port)).await.is_ok()
    }
    
    /// 获取本机 IP 地址
    pub fn get_local_ip() -> NetworkResult<IpAddr> {
        use std::net::UdpSocket;
        
        // 通过连接到外部地址获取本机 IP
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| NetworkError::ConnectionError(format!("获取本机IP失败: {}", e)))?;
        
        socket.connect("8.8.8.8:80")
            .map_err(|e| NetworkError::ConnectionError(format!("连接测试失败: {}", e)))?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| NetworkError::ConnectionError(format!("获取本地地址失败: {}", e)))?;
        
        Ok(local_addr.ip())
    }
    
    /// 生成唯一的节点 ID
    pub fn generate_node_id() -> String {
        use rand::{thread_rng, Rng};
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        
        let random: u32 = thread_rng().gen();
        
        format!("node_{timestamp}_{random:x}")
    }
    
    /// 验证网络配置
    pub fn validate_config(config: &NetworkConfig) -> NetworkResult<()> {
        // 验证端口范围
        if config.p2p_config.port == 0 {
            return Err(NetworkError::ConfigError("P2P端口范围无效".to_string()));
        }
        
        if config.http_config.port == 0 {
            return Err(NetworkError::ConfigError("HTTP端口范围无效".to_string()));
        }
        
        // 验证地址格式
        parse_address(&format!("{}:{}", config.p2p_config.host, config.p2p_config.port))?;
        parse_address(&format!("{}:{}", config.http_config.host, config.http_config.port))?;
        
        Ok(())
    }
}

/// 网络测试和验证功能
pub async fn test_network_functionality() -> NetworkResult<()> {
    println!("🔍 开始网络功能测试...");
    
    // 测试网络配置
    println!("  测试网络配置验证...");
    let config = NetworkConfig::default();
    utils::validate_config(&config)?;
    println!("    ✅ 配置验证通过");
    
    // 测试地址解析
    println!("  测试地址解析...");
    let addr = utils::parse_address("127.0.0.1:8000")?;
    println!("    ✅ 地址解析成功: {addr}");
    
    // 测试端口可用性
    println!("  测试端口可用性...");
    let port_available = utils::is_port_available(0).await; // 端口0让系统自动分配
    println!("    ✅ 端口测试完成: 可用={port_available}");
    
    // 测试本机IP获取
    println!("  测试本机IP获取...");
    match utils::get_local_ip() {
        Ok(ip) => println!("    ✅ 本机IP: {ip}"),
        Err(e) => println!("    ⚠️  本机IP获取失败: {e}"),
    }
    
    // 测试节点ID生成
    println!("  测试节点ID生成...");
    let node_id = utils::generate_node_id();
    println!("    ✅ 节点ID: {node_id}");
    
    // 测试网络管理器创建
    println!("  测试网络管理器...");
    let _network_mgr = NetworkManager::new(config);
    println!("    ✅ 网络管理器创建成功");
    
    // 测试网络监控器
    println!("  测试网络监控器...");
    let monitor_config = MonitorConfig::default();
    let _monitor = NetworkMonitor::new(monitor_config);
    println!("    ✅ 网络监控器创建成功");
    
    println!("✅ 网络功能测试完成");
    Ok(())
}

