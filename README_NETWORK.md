# MPC API 网络模块使用指南 (Network Module Usage Guide)

本文档介绍如何使用 MPC API 的网络模块进行多方安全计算中的网络通信。

## 🌐 网络模块概述

MPC API 网络模块提供了两种主要的网络通信方式：

1. **P2P 点对点网络** - 用于分布式 MPC 协议的直接节点通信
2. **HTTP API 接口** - 用于客户端-服务器架构和 RESTful 服务

## 📦 模块结构

```
src/network/
├── mod.rs          # 网络管理器和主要接口
├── common.rs       # 通用数据结构和工具函数
├── p2p.rs          # P2P 点对点网络实现
├── http.rs         # HTTP API 服务器和客户端
├── protocol.rs     # 网络协议和消息格式
└── security.rs     # 网络安全和认证
```

## 🚀 快速开始

### 基本用法

```rust
use mpc_api::network::{
    NetworkManager, NetworkConfig,
    p2p::PeerConfig,
    http::RestConfig
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建网络配置
    let config = NetworkConfig::default();
    
    // 创建网络管理器
    let mut network_manager = NetworkManager::new(config);
    
    // 配置 P2P 节点
    let p2p_config = PeerConfig {
        host: "0.0.0.0".to_string(),
        port: 8000,
        max_connections: 10,
        enable_discovery: true,
        ..Default::default()
    };
    
    // 配置 HTTP 服务器
    let http_config = RestConfig {
        host: "0.0.0.0".to_string(),
        port: 3000,
        max_connections: 100,
        enable_cors: true,
        ..Default::default()
    };
    
    // 启动网络服务
    network_manager.start_all(p2p_config, http_config).await?;
    
    println!("🎉 网络服务启动成功！");
    
    // 保持服务运行
    tokio::signal::ctrl_c().await?;
    
    // 关闭网络服务
    network_manager.shutdown().await?;
    
    Ok(())
}
```

## 🔗 P2P 网络使用

### 1. 创建 P2P 节点

```rust
use mpc_api::network::p2p::{P2PNode, PeerConfig, NodeRole};

async fn create_p2p_node() -> Result<P2PNode, Box<dyn std::error::Error>> {
    let config = PeerConfig {
        host: "127.0.0.1".to_string(),
        port: 8000,
        node_role: NodeRole::Participant,
        max_connections: 50,
        enable_discovery: true,
        bootstrap_nodes: vec!["127.0.0.1:8001".to_string()],
        connection_timeout: 30000,
        heartbeat_interval: 30,
        enable_tls: false,
        network_id: "mpc_network".to_string(),
        ..Default::default()
    };
    
    let mut node = P2PNode::new(config).await?;
    node.start().await?;
    
    Ok(node)
}
```

### 2. 发送 P2P 消息

```rust
use mpc_api::network::protocol::NetworkMessage;

async fn send_p2p_message(node: &P2PNode) -> Result<(), Box<dyn std::error::Error>> {
    // 创建消息
    let message = NetworkMessage::new("mpc_protocol", b"secret_share_data")
        .with_sender("node_001".to_string())
        .with_header("protocol".to_string(), "shamir".to_string());
    
    // 发送到特定节点
    node.send_to_peer("peer_id_123", message.clone()).await?;
    
    // 广播到所有节点
    let broadcast_msg = NetworkMessage::new("consensus", b"vote_data");
    node.broadcast(broadcast_msg).await?;
    
    Ok(())
}
```

### 3. 注册消息处理器

```rust
use mpc_api::network::p2p::{MessageHandler, DefaultMessageHandler};
use mpc_api::network::protocol::NetworkMessage;
use mpc_api::network::common::NetworkResult;

struct CustomMessageHandler;

impl MessageHandler for CustomMessageHandler {
    fn handle_message(
        &self,
        from_peer: &str,
        message: &NetworkMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<Option<NetworkMessage>>> + Send + '_>> {
        let from_peer = from_peer.to_string();
        let message_type = message.message_type.clone();
        
        Box::pin(async move {
            match message_type.as_str() {
                "mpc_protocol" => {
                    println!("🔒 处理来自 {} 的 MPC 协议消息", from_peer);
                    // 处理 MPC 协议消息
                    let response = NetworkMessage::new("mpc_response", b"processed");
                    Ok(Some(response))
                }
                "heartbeat" => {
                    println!("💓 心跳来自: {}", from_peer);
                    Ok(None)
                }
                _ => {
                    println!("❓ 未知消息类型: {}", message_type);
                    Ok(None)
                }
            }
        })
    }
}

async fn register_message_handler(node: &P2PNode) {
    let handler = Box::new(CustomMessageHandler);
    node.register_handler("custom".to_string(), handler).await;
}
```

## 🌐 HTTP API 使用

### 1. 创建 HTTP 服务器

```rust
use mpc_api::network::http::{HttpServer, RestConfig};

async fn create_http_server() -> Result<HttpServer, Box<dyn std::error::Error>> {
    let config = RestConfig {
        host: "0.0.0.0".to_string(),
        port: 3000,
        enable_tls: false,
        max_connections: 100,
        request_timeout: 30000,
        max_body_size: 1024 * 1024, // 1MB
        enable_cors: true,
        allowed_origins: vec!["*".to_string()],
        jwt_secret: "your_jwt_secret_here".to_string(),
        api_version: "v1".to_string(),
        log_level: "info".to_string(),
        ..Default::default()
    };
    
    let server = HttpServer::new(config).await?;
    server.start().await?;
    
    Ok(server)
}
```

### 2. 使用 HTTP 客户端

```rust
use mpc_api::network::http::HttpClient;

async fn use_http_client() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::new("http://localhost:3000")?
        .with_timeout(std::time::Duration::from_secs(30))
        .with_header("Authorization".to_string(), "Bearer your_token".to_string());
    
    // GET 请求
    let response = client.get("/api/v1/nodes").await?;
    println!("节点列表: {:?}", response);
    
    // POST 请求
    let payload = serde_json::json!({
        "participants": ["node_001", "node_002", "node_003"],
        "protocol": "shamir_secret_sharing"
    });
    
    let response = client.post("/api/v1/mpc/sessions", 
                              serde_json::to_vec(&payload)?).await?;
    println!("创建会话: {:?}", response);
    
    Ok(())
}
```

## 📡 API 端点

### 节点管理
- `GET /api/v1/nodes` - 获取网络节点列表
- `POST /api/v1/nodes` - 注册新节点
- `GET /api/v1/nodes/{id}` - 获取特定节点信息
- `DELETE /api/v1/nodes/{id}` - 注销节点

### MPC 协议
- `POST /api/v1/mpc/sessions` - 创建 MPC 会话
- `GET /api/v1/mpc/sessions/{id}` - 获取会话状态
- `POST /api/v1/mpc/sessions/{id}/messages` - 发送协议消息
- `GET /api/v1/mpc/sessions/{id}/result` - 获取计算结果

### 密钥管理
- `POST /api/v1/keys/generate` - 生成密钥对
- `GET /api/v1/keys` - 获取公钥列表
- `POST /api/v1/keys/share` - 分享密钥
- `DELETE /api/v1/keys/{id}` - 删除密钥

### 系统状态
- `GET /health` - 健康检查
- `GET /api/v1/info` - 获取 API 信息

## 🔒 安全配置

### TLS/SSL 配置

```rust
use mpc_api::network::security::{TlsConfig, TlsVersion};
use std::path::PathBuf;

let tls_config = TlsConfig {
    cert_path: PathBuf::from("/path/to/cert.pem"),
    key_path: PathBuf::from("/path/to/private.key"),
    ca_path: Some(PathBuf::from("/path/to/ca.pem")),
    verify_client: true,
    min_version: TlsVersion::V1_3,
    cipher_suites: vec![
        "TLS_AES_256_GCM_SHA384".to_string(),
        "TLS_CHACHA20_POLY1305_SHA256".to_string(),
    ],
};
```

### JWT 认证

```rust
use mpc_api::network::security::{AuthenticationConfig, AuthMethod};

let auth_config = AuthenticationConfig {
    jwt_secret: "your_secure_jwt_secret_key".to_string(),
    token_expiry: 3600, // 1 hour
    auth_methods: vec![AuthMethod::Jwt, AuthMethod::Certificate],
    enable_2fa: true,
};
```

## 📊 监控和统计

### 获取网络统计

```rust
async fn get_network_stats(network_manager: &NetworkManager) {
    // 获取连接统计
    let stats = network_manager.get_stats().await;
    println!("P2P 连接数: {}", stats.p2p_connections);
    println!("HTTP 连接数: {}", stats.http_connections);
    println!("发送字节数: {}", stats.bytes_sent);
    println!("接收字节数: {}", stats.bytes_received);
    
    // 健康检查
    let health = network_manager.health_check().await;
    println!("网络健康状态: {:?}", health.overall_status);
}
```

### P2P 节点统计

```rust
async fn get_p2p_stats(node: &P2PNode) {
    let stats = node.get_stats().await;
    println!("活跃连接数: {}", stats.active_connections);
    println!("发送消息数: {}", stats.messages_sent);
    println!("接收消息数: {}", stats.messages_received);
    
    // 获取连接的节点列表
    let peers = node.get_peers().await;
    println!("连接的节点: {:?}", peers);
}
```

## 🔧 配置选项

### 网络配置

```rust
use mpc_api::network::common::{NetworkConfig, GlobalNetworkSettings, LogLevel};

let config = NetworkConfig {
    p2p_config: PeerConfig {
        // P2P 配置
        port: 8000,
        max_connections: 50,
        enable_discovery: true,
        ..Default::default()
    },
    http_config: RestConfig {
        // HTTP 配置
        port: 3000,
        max_connections: 100,
        enable_cors: true,
        ..Default::default()
    },
    global_settings: GlobalNetworkSettings {
        network_id: "production_mpc_network".to_string(),
        debug_mode: false,
        log_level: LogLevel::Info,
        monitoring: MonitoringSettings {
            enabled: true,
            metrics_interval: 30,
            export_metrics: true,
            ..Default::default()
        },
        security: SecuritySettings {
            enable_encryption: true,
            encryption_algorithm: "AES-256-GCM".to_string(),
            key_rotation_interval: 24,
            enable_access_control: true,
        },
    },
};
```

## 🔍 故障排除

### 常见问题

1. **端口被占用**
```rust
use mpc_api::network::common::utils;

// 检查端口可用性
let port_available = utils::is_port_available(8000).await;
if !port_available {
    println!("端口 8000 被占用，请选择其他端口");
}

// 查找可用端口
if let Some(available_port) = utils::find_available_port(8000, 8100).await {
    println!("可用端口: {}", available_port);
}
```

2. **网络连接失败**
```rust
// 验证网络配置
match utils::validate_network_config(&config) {
    Ok(_) => println!("网络配置有效"),
    Err(e) => println!("配置错误: {}", e),
}

// 获取本机IP
match utils::get_local_ip() {
    Ok(ip) => println!("本机IP: {}", ip),
    Err(e) => println!("获取IP失败: {}", e),
}
```

3. **消息发送失败**
```rust
// 检查节点连接状态
for peer_id in node.get_peers().await {
    if let Some(peer_info) = node.get_peer_info(&peer_id).await {
        println!("节点 {} 状态: {:?}", peer_id, peer_info.status);
    }
}
```

## 🧪 测试

运行网络模块测试：

```bash
# 运行所有网络测试
cargo test network

# 运行特定模块测试
cargo test network::p2p
cargo test network::http

# 运行网络功能测试
cargo test test_network_functionality
```

## 📝 最佳实践

1. **生产环境配置**
   - 启用 TLS 加密
   - 使用强 JWT 密钥
   - 限制并发连接数
   - 启用日志和监控

2. **性能优化**
   - 合理设置连接池大小
   - 调整超时时间
   - 使用连接复用
   - 定期清理无效连接

3. **安全措施**
   - 定期更新密钥
   - 实施访问控制
   - 监控异常连接
   - 使用白名单机制

## 🔗 相关资源

- [MPC API 主文档](README.md)
- [椭圆曲线密码学模块](src/elliptic_curve/README.md)
- [同态加密模块](src/homomorphic_encryption/README.md)
- [秘密分享模块](src/secret_sharing/README.md)

## 📄 许可证

本项目采用 MIT 或 Apache-2.0 双重许可证。详见 [LICENSE](LICENSE) 文件。