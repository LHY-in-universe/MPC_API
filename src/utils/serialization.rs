//! # 序列化工具函数 (Serialization Utility Functions)
//! 
//! 本模块提供了数据序列化和反序列化的工具函数，用于 MPC 协议中的数据传输和存储。
//! 使用 bincode 库实现高效的二进制序列化，适用于网络传输和持久化存储。
//! 
//! ## 主要功能
//! - 将 Rust 数据结构序列化为字节序列
//! - 从字节序列反序列化为 Rust 数据结构
//! - 错误处理和类型安全保证
//! 
//! 这些函数为 MPC 协议中的数据交换提供了基础支持。

use serde::{Serialize, Deserialize};
use crate::Result;

/// 将数据序列化为字节序列
/// 
/// 使用 bincode 库将实现了 Serialize trait 的数据结构序列化为字节序列。
/// 适用于网络传输、数据存储等场景。
/// 
/// # 参数
/// * `value` - 实现了 Serialize trait 的数据引用
/// 
/// # 返回值
/// * `Result<Vec<u8>>` - 成功时返回序列化后的字节序列，失败时返回序列化错误
/// 
/// # 示例
/// ```rust
/// #[derive(Serialize)]
/// struct Message { content: String }
/// 
/// let msg = Message { content: "Hello".to_string() };
/// let bytes = serialize_to_bytes(&msg)?;
/// ```
pub fn serialize_to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value)
        .map_err(|e| crate::MpcError::SerializationError(e.to_string()))
}

/// 从字节序列反序列化为数据结构
/// 
/// 使用 bincode 库将字节序列反序列化为实现了 Deserialize trait 的数据结构。
/// 适用于接收网络数据、读取存储数据等场景。
/// 
/// # 参数
/// * `bytes` - 包含序列化数据的字节切片
/// 
/// # 返回值
/// * `Result<T>` - 成功时返回反序列化后的数据结构，失败时返回反序列化错误
/// 
/// # 示例
/// ```rust
/// #[derive(Deserialize)]
/// struct Message { content: String }
/// 
/// let msg: Message = deserialize_from_bytes(&bytes)?;
/// println!("{}", msg.content);
/// ```
pub fn deserialize_from_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes)
        .map_err(|e| crate::MpcError::SerializationError(e.to_string()))
}