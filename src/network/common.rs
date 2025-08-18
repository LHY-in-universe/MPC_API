//! # 网络通用模块 (Network Common Module)
//!
//! 本模块定义了网络层的通用数据结构、错误类型、配置参数和工具函数。
//! 为 P2P 和 HTTP 网络模块提供共享的基础功能。

use std::{fmt, net::SocketAddr, time::Duration};
use serde::{Deserialize, Serialize};
use crate::network::p2p::PeerConfig;
use crate::network::http::RestConfig;

/// 网络操作结果类型
pub type NetworkResult<T> = std::result::Result<T, NetworkError>;

/// 网络错误类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkError {
    /// 连接错误
    ConnectionError(String),
    /// 配置错误
    ConfigError(String),
    /// 认证失败
    AuthenticationFailed(String),
    /// 授权失败
    AuthorizationFailed(String),
    /// 序列化错误
    SerializationError(String),
    /// 反序列化错误
    DeserializationError(String),
    /// 超时错误
    Timeout,
    /// 节点未找到
    PeerNotFound(String),
    /// 节点不可用
    PeerNotAvailable(String),
    /// 通道错误
    ChannelError(String),
    /// 限流错误
    RateLimited(String),
    /// 未初始化
    NotInitialized,
    /// 协议错误
    ProtocolError(String),
    /// TLS 错误
    TlsError(String),
    /// IO 错误
    IoError(String),
    /// 其他错误
    Other(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::ConnectionError(msg) => write!(f, "连接错误: {}", msg),
            NetworkError::ConfigError(msg) => write!(f, "配置错误: {}", msg),
            NetworkError::AuthenticationFailed(msg) => write!(f, "认证失败: {}", msg),
            NetworkError::AuthorizationFailed(msg) => write!(f, "授权失败: {}", msg),
            NetworkError::SerializationError(msg) => write!(f, "序列化错误: {}", msg),
            NetworkError::DeserializationError(msg) => write!(f, "反序列化错误: {}", msg),
            NetworkError::Timeout => write!(f, "操作超时"),
            NetworkError::PeerNotFound(peer) => write!(f, "节点未找到: {}", peer),
            NetworkError::PeerNotAvailable(peer) => write!(f, "节点不可用: {}", peer),
            NetworkError::ChannelError(msg) => write!(f, "通道错误: {}", msg),
            NetworkError::RateLimited(msg) => write!(f, "请求限流: {}", msg),
            NetworkError::NotInitialized => write!(f, "服务未初始化"),
            NetworkError::ProtocolError(msg) => write!(f, "协议错误: {}", msg),
            NetworkError::TlsError(msg) => write!(f, "TLS 错误: {}", msg),
            NetworkError::IoError(msg) => write!(f, "IO 错误: {}", msg),
            NetworkError::Other(msg) => write!(f, "其他错误: {}", msg),
        }
    }
}

impl std::error::Error for NetworkError {}

/// 统一网络配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// P2P 网络配置
    pub p2p_config: PeerConfig,
    /// HTTP API 配置
    pub http_config: RestConfig,
    /// 全局网络设置
    pub global_settings: GlobalNetworkSettings,
}

/// 全局网络设置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalNetworkSettings {
    /// 网络标识符
    pub network_id: String,
    /// 是否启用调试模式
    pub debug_mode: bool,
    /// 日志级别
    pub log_level: LogLevel,
    /// 监控设置
    pub monitoring: MonitoringSettings,
    /// 安全设置
    pub security: SecuritySettings,
}

/// 日志级别
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogLevel {
    /// 跟踪级别
    Trace,
    /// 调试级别
    Debug,
    /// 信息级别
    Info,
    /// 警告级别
    Warn,
    /// 错误级别
    Error,
}

/// 监控设置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringSettings {
    /// 是否启用监控
    pub enabled: bool,
    /// 指标收集间隔（秒）
    pub metrics_interval: u64,
    /// 监控端点
    pub monitoring_endpoint: Option<String>,
    /// 是否导出到外部系统
    pub export_metrics: bool,
}

/// 安全设置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// 是否启用加密
    pub enable_encryption: bool,
    /// 加密算法
    pub encryption_algorithm: String,
    /// 密钥轮换间隔（小时）
    pub key_rotation_interval: u64,
    /// 是否启用访问控制
    pub enable_access_control: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            p2p_config: PeerConfig::default(),
            http_config: RestConfig::default(),
            global_settings: GlobalNetworkSettings::default(),
        }
    }
}

impl Default for GlobalNetworkSettings {
    fn default() -> Self {
        GlobalNetworkSettings {
            network_id: "mpc_network".to_string(),
            debug_mode: false,
            log_level: LogLevel::Info,
            monitoring: MonitoringSettings::default(),
            security: SecuritySettings::default(),
        }
    }
}

impl Default for MonitoringSettings {
    fn default() -> Self {
        MonitoringSettings {
            enabled: true,
            metrics_interval: 30,
            monitoring_endpoint: None,
            export_metrics: false,
        }
    }
}

impl Default for SecuritySettings {
    fn default() -> Self {
        SecuritySettings {
            enable_encryption: true,
            encryption_algorithm: "AES-256-GCM".to_string(),
            key_rotation_interval: 24,
            enable_access_control: true,
        }
    }
}

/// 连接信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// 连接 ID
    pub id: String,
    /// 远程地址
    pub remote_addr: SocketAddr,
    /// 本地地址
    pub local_addr: SocketAddr,
    /// 连接类型
    pub connection_type: ConnectionType,
    /// 连接状态
    pub status: ConnectionStatus,
    /// 建立时间
    pub established_at: std::time::SystemTime,
    /// 最后活跃时间
    pub last_activity: std::time::SystemTime,
}

/// 连接类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// TCP 连接
    Tcp,
    /// TLS 加密连接
    Tls,
    /// WebSocket 连接
    WebSocket,
    /// HTTP 连接
    Http,
    /// HTTPS 连接
    Https,
}

/// 连接状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    /// 正在建立
    Establishing,
    /// 已建立
    Established,
    /// 正在关闭
    Closing,
    /// 已关闭
    Closed,
    /// 错误状态
    Error(String),
}

/// 网络指标
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// 总连接数
    pub total_connections: u64,
    /// 活跃连接数
    pub active_connections: u32,
    /// 发送的数据包数
    pub packets_sent: u64,
    /// 接收的数据包数
    pub packets_received: u64,
    /// 发送的字节数
    pub bytes_sent: u64,
    /// 接收的字节数
    pub bytes_received: u64,
    /// 连接失败数
    pub connection_failures: u64,
    /// 平均延迟（毫秒）
    pub average_latency: f64,
    /// 数据包丢失率
    pub packet_loss_rate: f64,
}

/// 网络工具函数
pub mod utils {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// 验证 IP 地址格式
    pub fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<IpAddr>().is_ok()
    }

    /// 验证端口号
    pub fn is_valid_port(port: u16) -> bool {
        port > 0
    }

    /// 解析网络地址
    pub fn parse_socket_addr(addr: &str) -> NetworkResult<SocketAddr> {
        addr.parse()
            .map_err(|e| NetworkError::ConfigError(format!("无效的网络地址: {}", e)))
    }

    /// 检查是否为本地地址
    pub fn is_local_address(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback() || 
                ipv4.is_private() ||
                ipv4 == Ipv4Addr::new(0, 0, 0, 0)
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
            }
        }
    }

    /// 生成连接 ID
    pub fn generate_connection_id() -> String {
        format!("conn_{}", uuid::Uuid::new_v4())
    }

    /// 计算两个时间点之间的延迟
    pub fn calculate_latency(start: std::time::SystemTime, end: std::time::SystemTime) -> Duration {
        end.duration_since(start).unwrap_or_default()
    }

    /// 格式化字节数
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        format!("{:.2} {}", size, UNITS[unit_index])
    }

    /// 格式化网络速度
    pub fn format_speed(bytes_per_second: f64) -> String {
        format!("{}/s", format_bytes(bytes_per_second as u64))
    }

    /// 检查网络端口是否被占用
    pub async fn is_port_in_use(port: u16, addr: Option<IpAddr>) -> bool {
        use tokio::net::TcpListener;
        
        let bind_addr = addr.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let socket_addr = SocketAddr::new(bind_addr, port);
        
        TcpListener::bind(socket_addr).await.is_err()
    }

    /// 获取下一个可用端口
    pub async fn find_available_port(start_port: u16, end_port: u16) -> Option<u16> {
        for port in start_port..=end_port {
            if !is_port_in_use(port, None).await {
                return Some(port);
            }
        }
        None
    }

    /// 验证网络配置
    pub fn validate_network_config(config: &NetworkConfig) -> NetworkResult<()> {
        // 验证 P2P 配置
        if !is_valid_port(config.p2p_config.port) {
            return Err(NetworkError::ConfigError("P2P 端口无效".to_string()));
        }

        // 验证 HTTP 配置  
        if !is_valid_port(config.http_config.port) {
            return Err(NetworkError::ConfigError("HTTP 端口无效".to_string()));
        }

        // 验证端口冲突
        if config.p2p_config.port == config.http_config.port {
            return Err(NetworkError::ConfigError("P2P 和 HTTP 端口不能相同".to_string()));
        }

        Ok(())
    }

    /// 创建默认的网络配置
    pub fn create_default_config() -> NetworkConfig {
        NetworkConfig::default()
    }

    /// 合并网络指标
    pub fn merge_metrics(metrics1: &NetworkMetrics, metrics2: &NetworkMetrics) -> NetworkMetrics {
        NetworkMetrics {
            total_connections: metrics1.total_connections + metrics2.total_connections,
            active_connections: metrics1.active_connections + metrics2.active_connections,
            packets_sent: metrics1.packets_sent + metrics2.packets_sent,
            packets_received: metrics1.packets_received + metrics2.packets_received,
            bytes_sent: metrics1.bytes_sent + metrics2.bytes_sent,
            bytes_received: metrics1.bytes_received + metrics2.bytes_received,
            connection_failures: metrics1.connection_failures + metrics2.connection_failures,
            average_latency: (metrics1.average_latency + metrics2.average_latency) / 2.0,
            packet_loss_rate: (metrics1.packet_loss_rate + metrics2.packet_loss_rate) / 2.0,
        }
    }
}

/// 网络常量定义
pub mod constants {
    use std::time::Duration;

    /// 默认连接超时时间
    pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
    
    /// 默认读取超时时间
    pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);
    
    /// 默认写入超时时间
    pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
    
    /// 默认心跳间隔
    pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
    
    /// 默认重连间隔
    pub const DEFAULT_RECONNECT_INTERVAL: Duration = Duration::from_secs(5);
    
    /// 最大重连次数
    pub const MAX_RECONNECT_ATTEMPTS: u32 = 3;
    
    /// 默认缓冲区大小
    pub const DEFAULT_BUFFER_SIZE: usize = 8192;
    
    /// 最大缓冲区大小
    pub const MAX_BUFFER_SIZE: usize = 1024 * 1024; // 1MB
    
    /// 默认 P2P 端口
    pub const DEFAULT_P2P_PORT: u16 = 8000;
    
    /// 默认 HTTP 端口
    pub const DEFAULT_HTTP_PORT: u16 = 3000;
    
    /// 协议版本
    pub const PROTOCOL_VERSION: &str = "1.0";
    
    /// 用户代理字符串
    pub const USER_AGENT: &str = "MPC-API/1.0";
}

