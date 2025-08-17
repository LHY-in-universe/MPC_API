//! # 网络协议模块 (Network Protocol Module)
//!
//! 本模块定义了网络通信的协议格式、消息类型和编解码规则。
//! 为 P2P 和 HTTP 网络提供统一的消息协议。

use std::{collections::HashMap, time::SystemTime};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::network::common::{NetworkError, NetworkResult};

/// 网络消息协议
#[derive(Debug)]
pub struct MessageProtocol {
    /// 协议版本
    #[allow(dead_code)]
    version: String,
    /// 支持的消息类型
    supported_types: HashMap<String, MessageTypeInfo>,
}

/// 消息类型信息
#[derive(Debug, Clone)]
pub struct MessageTypeInfo {
    /// 类型名称
    pub name: String,
    /// 描述
    pub description: String,
    /// 是否需要认证
    pub requires_auth: bool,
    /// 最大载荷大小
    pub max_payload_size: usize,
}

/// 网络消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// 消息 ID
    pub id: String,
    /// 消息类型
    pub message_type: String,
    /// 协议版本
    pub version: String,
    /// 时间戳
    pub timestamp: SystemTime,
    /// 发送者 ID
    pub sender_id: Option<String>,
    /// 接收者 ID
    pub receiver_id: Option<String>,
    /// 消息载荷
    pub payload: Vec<u8>,
    /// 消息头
    pub headers: HashMap<String, String>,
    /// 数字签名
    pub signature: Option<Vec<u8>>,
}

/// 消息类型枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    /// 握手消息
    Handshake,
    /// 心跳消息
    Heartbeat,
    /// 数据传输
    Data,
    /// MPC 协议消息
    MpcProtocol,
    /// 节点发现
    Discovery,
    /// 认证消息
    Authentication,
    /// 错误消息
    Error,
    /// 控制消息
    Control,
}

impl NetworkMessage {
    /// 创建新消息
    pub fn new(message_type: &str, payload: &[u8]) -> Self {
        NetworkMessage {
            id: Uuid::new_v4().to_string(),
            message_type: message_type.to_string(),
            version: "1.0".to_string(),
            timestamp: SystemTime::now(),
            sender_id: None,
            receiver_id: None,
            payload: payload.to_vec(),
            headers: HashMap::new(),
            signature: None,
        }
    }

    /// 设置发送者
    pub fn with_sender(mut self, sender_id: String) -> Self {
        self.sender_id = Some(sender_id);
        self
    }

    /// 设置接收者
    pub fn with_receiver(mut self, receiver_id: String) -> Self {
        self.receiver_id = Some(receiver_id);
        self
    }

    /// 添加头部
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// 序列化消息
    pub fn serialize(&self) -> NetworkResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))
    }

    /// 反序列化消息
    pub fn deserialize(data: &[u8]) -> NetworkResult<Self> {
        serde_json::from_slice(data)
            .map_err(|e| NetworkError::DeserializationError(e.to_string()))
    }

    /// 验证消息
    pub fn validate(&self) -> NetworkResult<()> {
        if self.message_type.is_empty() {
            return Err(NetworkError::ProtocolError("消息类型不能为空".to_string()));
        }

        if self.payload.len() > 1024 * 1024 { // 1MB limit
            return Err(NetworkError::ProtocolError("消息载荷过大".to_string()));
        }

        Ok(())
    }
}

impl MessageProtocol {
    /// 创建消息协议
    pub fn new() -> Self {
        let mut protocol = MessageProtocol {
            version: "1.0".to_string(),
            supported_types: HashMap::new(),
        };

        // 注册默认消息类型
        protocol.register_default_types();
        protocol
    }

    /// 注册默认消息类型
    fn register_default_types(&mut self) {
        let types = vec![
            MessageTypeInfo {
                name: "handshake".to_string(),
                description: "节点握手消息".to_string(),
                requires_auth: false,
                max_payload_size: 1024,
            },
            MessageTypeInfo {
                name: "heartbeat".to_string(),
                description: "心跳消息".to_string(),
                requires_auth: false,
                max_payload_size: 256,
            },
            MessageTypeInfo {
                name: "mpc_protocol".to_string(),
                description: "MPC 协议消息".to_string(),
                requires_auth: true,
                max_payload_size: 1024 * 1024, // 1MB
            },
            MessageTypeInfo {
                name: "discovery".to_string(),
                description: "节点发现消息".to_string(),
                requires_auth: false,
                max_payload_size: 2048,
            },
        ];

        for type_info in types {
            self.supported_types.insert(type_info.name.clone(), type_info);
        }
    }

    /// 验证消息类型
    pub fn validate_message_type(&self, message_type: &str) -> bool {
        self.supported_types.contains_key(message_type)
    }

    /// 获取消息类型信息
    pub fn get_type_info(&self, message_type: &str) -> Option<&MessageTypeInfo> {
        self.supported_types.get(message_type)
    }
}

impl Default for MessageProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageType {
    /// 获取消息类型名称
    pub fn name(&self) -> &'static str {
        match self {
            MessageType::Handshake => "handshake",
            MessageType::Heartbeat => "heartbeat",
            MessageType::Data => "data",
            MessageType::MpcProtocol => "mpc_protocol",
            MessageType::Discovery => "discovery",
            MessageType::Authentication => "authentication",
            MessageType::Error => "error",
            MessageType::Control => "control",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_message_creation() {
        let message = NetworkMessage::new("test", b"test_payload");
        assert_eq!(message.message_type, "test");
        assert_eq!(message.payload, b"test_payload");
    }

    #[test]
    fn test_message_serialization() {
        let message = NetworkMessage::new("test", b"payload");
        let serialized = message.serialize().unwrap();
        let deserialized = NetworkMessage::deserialize(&serialized).unwrap();
        
        assert_eq!(message.message_type, deserialized.message_type);
        assert_eq!(message.payload, deserialized.payload);
    }

    #[test]
    fn test_message_validation() {
        let message = NetworkMessage::new("test", b"payload");
        assert!(message.validate().is_ok());

        let empty_type = NetworkMessage::new("", b"payload");
        assert!(empty_type.validate().is_err());
    }

    #[test]
    fn test_message_protocol() {
        let protocol = MessageProtocol::new();
        assert!(protocol.validate_message_type("handshake"));
        assert!(!protocol.validate_message_type("invalid_type"));
    }
}