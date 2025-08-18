//! # 网络模块使用示例 (Network Module Usage Example)
//!
//! 本示例展示如何使用 MPC API 的网络模块进行 P2P 和 HTTP 通信

use mpc_api::network::{
    NetworkManager, NetworkConfig,
    p2p::{P2PNode, PeerConfig, NodeRole, DefaultMessageHandler},
    http::{HttpServer, HttpClient, RestConfig},
    protocol::NetworkMessage,
    common::NetworkResult,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> NetworkResult<()> {
    println!("🌐 MPC API 网络模块示例");
    println!("========================");

    // 1. 演示网络管理器使用
    demo_network_manager().await?;
    
    // 2. 演示 P2P 网络
    demo_p2p_network().await?;
    
    // 3. 演示 HTTP API
    demo_http_api().await?;
    
    // 4. 演示网络协议
    demo_network_protocol().await?;
    
    // 5. 演示网络工具
    demo_network_utils().await?;
    
    println!("✅ 所有网络演示完成！");
    Ok(())
}

/// 演示网络管理器使用
async fn demo_network_manager() -> NetworkResult<()> {
    println!("\n📡 演示：网络管理器");
    println!("-------------------");
    
    // 创建网络配置
    let config = NetworkConfig::default();
    
    // 创建网络管理器
    let network_manager = NetworkManager::new(config);
    
    // 获取统计信息
    let stats = network_manager.get_stats().await;
    println!("初始连接统计: P2P={}, HTTP={}", 
             stats.p2p_connections, stats.http_connections);
    
    // 健康检查
    let health = network_manager.health_check().await;
    println!("网络健康状态: {:?}", health.overall_status);
    
    Ok(())
}

/// 演示 P2P 网络功能
async fn demo_p2p_network() -> NetworkResult<()> {
    println!("\n🔗 演示：P2P 网络");
    println!("----------------");
    
    // 创建第一个节点（引导节点）
    let mut bootstrap_config = PeerConfig::default();
    bootstrap_config.port = 18000; // 使用不同端口避免冲突
    bootstrap_config.node_role = NodeRole::Bootstrap;
    
    println!("创建引导节点...");
    let _bootstrap_node = P2PNode::new(bootstrap_config).await?;
    
    // 创建参与节点
    let mut participant_config = PeerConfig::default();
    participant_config.port = 18001;
    participant_config.node_role = NodeRole::Participant;
    participant_config.bootstrap_nodes = vec!["127.0.0.1:18000".to_string()];
    
    println!("创建参与节点...");
    let participant_node = P2PNode::new(participant_config).await?;
    
    // 注册消息处理器
    let handler = Box::new(DefaultMessageHandler);
    participant_node.register_handler("demo".to_string(), handler).await;
    
    // 创建和发送消息
    let message = NetworkMessage::new("ping", b"Hello from participant!")
        .with_sender("participant_001".to_string());
    
    println!("消息类型: {}", message.message_type);
    println!("消息ID: {}", message.id);
    
    // 获取节点统计
    let stats = participant_node.get_stats().await;
    println!("节点统计: 活跃连接={}, 发送消息={}", 
             stats.active_connections, stats.messages_sent);
    
    Ok(())
}

/// 演示 HTTP API 功能
async fn demo_http_api() -> NetworkResult<()> {
    println!("\n🌐 演示：HTTP API");
    println!("----------------");
    
    // 创建 HTTP 服务器配置
    let mut server_config = RestConfig::default();
    server_config.port = 13000; // 使用不同端口避免冲突
    server_config.enable_cors = true;
    
    println!("创建 HTTP 服务器...");
    let server = HttpServer::new(server_config).await?;
    
    // 获取服务器状态
    let status = server.get_status().await;
    println!("服务器状态: {:?}", status);
    
    // 创建 HTTP 客户端
    println!("创建 HTTP 客户端...");
    let _client = HttpClient::new("http://localhost:13000")?
        .with_timeout(Duration::from_secs(10));
    
    // 模拟 API 调用（注意：实际的服务器没有启动，所以这只是演示客户端创建）
    println!("HTTP 客户端创建成功，基础URL: http://localhost:13000");
    
    // 获取服务器统计
    let http_stats = server.get_stats().await;
    println!("HTTP 统计: 总请求={}, 成功请求={}", 
             http_stats.total_requests, http_stats.successful_requests);
    
    Ok(())
}

/// 演示网络协议和消息
async fn demo_network_protocol() -> NetworkResult<()> {
    println!("\n📨 演示：网络协议");
    println!("----------------");
    
    // 创建不同类型的消息
    let messages = vec![
        NetworkMessage::new("handshake", b"node_handshake_data"),
        NetworkMessage::new("mpc_protocol", b"secret_share_data"),
        NetworkMessage::new("heartbeat", b"ping"),
        NetworkMessage::new("discovery", b"node_discovery_request"),
    ];
    
    for message in messages {
        println!("消息类型: {}", message.message_type);
        println!("  ID: {}", message.id);
        println!("  载荷大小: {} bytes", message.payload.len());
        
        // 验证消息
        match message.validate() {
            Ok(_) => println!("  ✅ 消息验证通过"),
            Err(e) => println!("  ❌ 消息验证失败: {}", e),
        }
        
        // 序列化和反序列化测试
        match message.serialize() {
            Ok(serialized) => {
                println!("  📦 序列化大小: {} bytes", serialized.len());
                
                match NetworkMessage::deserialize(&serialized) {
                    Ok(_) => println!("  ✅ 反序列化成功"),
                    Err(e) => println!("  ❌ 反序列化失败: {}", e),
                }
            }
            Err(e) => println!("  ❌ 序列化失败: {}", e),
        }
        
        println!();
    }
    
    Ok(())
}

/// 演示网络工具函数
async fn demo_network_utils() -> NetworkResult<()> {
    println!("\n🔧 演示：网络工具");
    println!("----------------");
    
    use mpc_api::network::common::utils;
    
    // 端口可用性检查
    let test_ports = vec![13000, 13001, 13002];
    for port in test_ports {
        let available = utils::is_port_in_use(port, None).await;
        println!("端口 {} 被占用: {}", port, available);
    }
    
    // 查找可用端口
    if let Some(available_port) = utils::find_available_port(14000, 14100).await {
        println!("找到可用端口: {}", available_port);
    }
    
    // 生成连接ID
    let conn_id = utils::generate_connection_id();
    println!("生成的连接ID: {}", conn_id);
    
    // 格式化字节数
    let bytes_examples = vec![1024, 1048576, 1073741824];
    for bytes in bytes_examples {
        let formatted = utils::format_bytes(bytes);
        println!("{} bytes = {}", bytes, formatted);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_network_example() {
        // 测试网络组件创建
        let config = NetworkConfig::default();
        let network_manager = NetworkManager::new(config);
        
        let stats = network_manager.get_stats().await;
        assert_eq!(stats.p2p_connections, 0);
        assert_eq!(stats.http_connections, 0);
    }
    
    #[test]
    fn test_message_creation() {
        let message = NetworkMessage::new("test", b"test_data");
        assert_eq!(message.message_type, "test");
        assert_eq!(message.payload, b"test_data");
        assert!(message.validate().is_ok());
    }
}