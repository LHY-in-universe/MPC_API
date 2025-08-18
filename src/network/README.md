# Network Module - 网络模块

本模块为 MPC API 提供完整的网络通信功能，支持分布式多方安全计算的 P2P 网络和 HTTP API 服务。

## 📁 模块结构

```
src/network/
├── README.md           # 本文档
├── mod.rs             # 网络管理器和主要接口
├── common.rs          # 通用数据结构、错误类型和工具函数
├── p2p.rs            # P2P 点对点网络实现
├── http.rs           # HTTP API 服务器和客户端
├── protocol.rs       # 网络协议和消息格式定义
└── security.rs       # 网络安全、TLS 和认证功能
```

## 🌐 功能概述

### 1. 网络管理器 (NetworkManager)
- 统一管理 P2P 和 HTTP 网络服务
- 提供服务状态监控和健康检查
- 支持动态配置更新

### 2. P2P 点对点网络 (P2P Network)
- 去中心化节点发现和连接管理
- 支持多种节点角色（引导节点、参与节点、中继节点）
- 消息路由和广播机制
- 心跳检测和连接维护

### 3. HTTP API 服务 (HTTP API)
- RESTful API 接口设计
- 支持 JSON 格式通信
- 内置认证和授权中间件
- CORS 支持和请求限流

### 4. 网络协议 (Network Protocol)
- 统一的消息格式定义
- 消息序列化和反序列化
- 协议版本管理
- 消息验证和签名

### 5. 网络安全 (Network Security)
- TLS/SSL 加密支持
- JWT 身份认证
- 数字证书管理
- 访问控制和权限管理

## 🚀 快速开始

### 基本使用示例

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

## 📡 P2P 网络使用

### 创建 P2P 节点

```rust
use mpc_api::network::p2p::{P2PNode, PeerConfig, NodeRole};

let config = PeerConfig {
    host: "127.0.0.1".to_string(),
    port: 8000,
    node_role: NodeRole::Participant,
    max_connections: 50,
    enable_discovery: true,
    bootstrap_nodes: vec!["127.0.0.1:8001".to_string()],
    network_id: "mpc_network".to_string(),
    ..Default::default()
};

let mut node = P2PNode::new(config).await?;
node.start().await?;
```

### 发送 P2P 消息

```rust
use mpc_api::network::protocol::NetworkMessage;

// 创建消息
let message = NetworkMessage::new("mpc_protocol", b"secret_share_data")
    .with_sender("node_001".to_string())
    .with_header("protocol".to_string(), "shamir".to_string());

// 发送到特定节点
node.send_to_peer("peer_id_123", message.clone()).await?;

// 广播到所有节点
let broadcast_msg = NetworkMessage::new("consensus", b"vote_data");
node.broadcast(broadcast_msg).await?;
```

### 注册消息处理器

```rust
use mpc_api::network::p2p::MessageHandler;

struct MpcMessageHandler;

impl MessageHandler for MpcMessageHandler {
    fn handle_message(
        &self,
        from_peer: &str,
        message: &NetworkMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<Option<NetworkMessage>>> + Send + '_>> {
        Box::pin(async move {
            match message.message_type.as_str() {
                "mpc_protocol" => {
                    // 处理 MPC 协议消息
                    println!("处理来自 {} 的 MPC 消息", from_peer);
                    Ok(None)
                }
                _ => Ok(None)
            }
        })
    }
}

// 注册处理器
let handler = Box::new(MpcMessageHandler);
node.register_handler("mpc_protocol".to_string(), handler).await;
```

## 🌐 HTTP API 使用

### 创建 HTTP 服务器

```rust
use mpc_api::network::http::{HttpServer, RestConfig};

let config = RestConfig {
    host: "0.0.0.0".to_string(),
    port: 3000,
    enable_tls: false,
    max_connections: 100,
    enable_cors: true,
    jwt_secret: "your_secret_key".to_string(),
    ..Default::default()
};

let server = HttpServer::new(config).await?;
server.start().await?;
```

### 使用 HTTP 客户端

```rust
use mpc_api::network::http::HttpClient;

let client = HttpClient::new("http://localhost:3000")?
    .with_timeout(std::time::Duration::from_secs(30));

// GET 请求
let response = client.get("/api/v1/nodes").await?;

// POST 请求
let payload = serde_json::json!({
    "participants": ["node_001", "node_002"],
    "protocol": "shamir"
});
let response = client.post("/api/v1/mpc/sessions", 
                          serde_json::to_vec(&payload)?).await?;
```

## 🔒 安全配置

### TLS 配置

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
    jwt_secret: "your_secure_jwt_secret".to_string(),
    token_expiry: 3600, // 1 hour
    auth_methods: vec![AuthMethod::Jwt],
    enable_2fa: false,
};
```

## 📋 API 端点

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

## 📊 监控和统计

### 获取网络统计

```rust
// 网络管理器统计
let stats = network_manager.get_stats().await;
println!("P2P 连接数: {}", stats.p2p_connections);
println!("HTTP 连接数: {}", stats.http_connections);

// P2P 节点统计
let p2p_stats = node.get_stats().await;
println!("活跃连接: {}", p2p_stats.active_connections);
println!("发送消息: {}", p2p_stats.messages_sent);

// HTTP 服务器统计
let http_stats = server.get_stats().await;
println!("总请求数: {}", http_stats.total_requests);
println!("成功请求: {}", http_stats.successful_requests);
```

### 健康检查

```rust
let health = network_manager.health_check().await;
println!("网络状态: {:?}", health.overall_status);
println!("P2P 状态: {:?}", health.p2p_status);
println!("HTTP 状态: {:?}", health.http_status);
```

## 🔧 配置选项

### 网络配置结构

```rust
use mpc_api::network::common::{NetworkConfig, GlobalNetworkSettings};

let config = NetworkConfig {
    p2p_config: PeerConfig {
        port: 8000,
        max_connections: 50,
        enable_discovery: true,
        heartbeat_interval: 30,
        connection_timeout: 30000,
        ..Default::default()
    },
    http_config: RestConfig {
        port: 3000,
        max_connections: 100,
        enable_cors: true,
        request_timeout: 30000,
        max_body_size: 1024 * 1024, // 1MB
        ..Default::default()
    },
    global_settings: GlobalNetworkSettings {
        network_id: "production_network".to_string(),
        debug_mode: false,
        monitoring: MonitoringSettings {
            enabled: true,
            metrics_interval: 30,
            ..Default::default()
        },
        security: SecuritySettings {
            enable_encryption: true,
            enable_access_control: true,
            ..Default::default()
        },
        ..Default::default()
    },
};
```

## 🔍 故障排除

### 常见问题解决

```rust
use mpc_api::network::common::utils;

// 检查端口可用性
let port_available = utils::is_port_available(8000).await;
if !port_available {
    println!("端口 8000 被占用");
}

// 查找可用端口
if let Some(port) = utils::find_available_port(8000, 8100).await {
    println!("可用端口: {}", port);
}

// 验证网络配置
match utils::validate_network_config(&config) {
    Ok(_) => println!("配置有效"),
    Err(e) => println!("配置错误: {}", e),
}

// 获取本机IP
match utils::get_local_ip() {
    Ok(ip) => println!("本机IP: {}", ip),
    Err(e) => println!("获取IP失败: {}", e),
}
```

## 🧪 测试

### 运行网络模块测试

```bash
# 运行所有网络测试
cargo test network

# 运行特定模块测试
cargo test network::p2p
cargo test network::http
cargo test network::common

# 运行示例程序
cargo run --example network_example
```

### 测试用例说明

- **P2P 测试**: 节点创建、消息处理、节点发现
- **HTTP 测试**: 服务器创建、客户端请求、JSON 响应
- **协议测试**: 消息序列化、验证、类型检查
- **安全测试**: TLS 配置、证书验证、认证流程

## 📝 最佳实践

### 生产环境建议

1. **安全配置**
   ```rust
   // 启用 TLS
   let mut config = RestConfig::default();
   config.enable_tls = true;
   config.tls_config = Some(tls_config);
   
   // 使用强 JWT 密钥
   config.jwt_secret = "your_256_bit_secret_key".to_string();
   ```

2. **性能优化**
   ```rust
   // 合理设置连接限制
   config.max_connections = 1000;
   config.request_timeout = 10000; // 10 seconds
   
   // P2P 心跳间隔
   p2p_config.heartbeat_interval = 30; // 30 seconds
   ```

3. **监控配置**
   ```rust
   // 启用监控
   config.global_settings.monitoring.enabled = true;
   config.global_settings.monitoring.metrics_interval = 10;
   ```

### 错误处理

```rust
use mpc_api::network::common::{NetworkError, NetworkResult};

async fn handle_network_operation() -> NetworkResult<()> {
    match node.send_to_peer("peer_123", message).await {
        Ok(_) => println!("消息发送成功"),
        Err(NetworkError::PeerNotFound(peer_id)) => {
            println!("节点未找到: {}", peer_id);
        }
        Err(NetworkError::ConnectionError(msg)) => {
            println!("连接错误: {}", msg);
        }
        Err(e) => {
            println!("其他错误: {}", e);
        }
    }
    Ok(())
}
```

## 🔗 相关文档

- [项目主 README](../../README.md)
- [网络模块详细使用指南](../../README_NETWORK.md)
- [示例代码](../../examples/network_example.rs)
- [MPC 协议文档](../protocols/README.md)
- [安全模块文档](../security/README.md)

## 📄 许可证

本项目采用 MIT 或 Apache-2.0 双重许可证。