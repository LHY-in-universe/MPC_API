//! # 消息认证码模块 (Message Authentication Codes)
//! 
//! 本模块实现了各种消息认证码方案，用于确保消息的完整性和真实性。
//! 消息认证码是一种对称密码学原语，允许验证消息是否被篡改以及是否来自预期的发送方。
//! 
//! ## 支持的 MAC 算法
//! 
//! - **HMAC**: 基于哈希函数的消息认证码，使用 SHA-256 作为底层哈希函数
//! - **Poly1305**: 高性能的一次性消息认证码，常与 ChaCha20 流密码配合使用
//! - **GMAC**: 基于 Galois/Counter Mode 的消息认证码，提供认证加密
//! - **CMAC**: 基于分组密码的消息认证码，使用 AES 作为底层分组密码
//! 
//! ## 安全特性
//! 
//! 所有实现的 MAC 算法都提供以下安全保证：
//! - **不可伪造性**: 在不知道密钥的情况下，攻击者无法为新消息生成有效的认证标签
//! - **完整性**: 能够检测消息的任何修改
//! - **真实性**: 能够验证消息确实来自持有密钥的发送方
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::authentication::*;
//! 
//! // 使用 HMAC
//! let key = HmacSha256::generate_key();
//! let message = b"Hello, World!";
//! let tag = HmacSha256::authenticate(&key, message);
//! assert!(HmacSha256::verify(&key, message, &tag));
//! ```

pub mod hmac;
pub mod poly1305;
pub mod gmac;
pub mod cmac;

pub use hmac::*;
pub use poly1305::*;
pub use gmac::*;
pub use cmac::*;

// use crate::{MpcError, Result}; // Unused imports
use serde::{Deserialize, Serialize};

/// 消息认证码的通用特征定义
/// 
/// 定义了所有消息认证码实现必须提供的基本接口。
/// 这个特征抽象了不同 MAC 算法的共同操作。
pub trait MessageAuthenticationCode {
    /// 密钥类型
    type Key;
    /// 消息类型
    type Message;
    /// 认证标签类型
    type Tag;
    
    /// 生成一个新的随机密钥
    /// 
    /// # 返回值
    /// 
    /// 返回一个适用于该 MAC 算法的新密钥
    fn generate_key() -> Self::Key;
    
    /// 为给定消息生成认证标签
    /// 
    /// # 参数
    /// 
    /// * `key` - 用于认证的密钥
    /// * `message` - 要认证的消息
    /// 
    /// # 返回值
    /// 
    /// 返回消息的认证标签
    fn authenticate(key: &Self::Key, message: &Self::Message) -> Self::Tag;
    
    /// 验证消息和认证标签的有效性
    /// 
    /// # 参数
    /// 
    /// * `key` - 用于验证的密钥
    /// * `message` - 要验证的消息
    /// * `tag` - 要验证的认证标签
    /// 
    /// # 返回值
    /// 
    /// 如果标签有效返回 `true`，否则返回 `false`
    fn verify(key: &Self::Key, message: &Self::Message, tag: &Self::Tag) -> bool;
}

/// 不可伪造 MAC 的标记特征
/// 
/// 实现此特征的 MAC 算法提供不可伪造性保证，即在不知道密钥的情况下，
/// 攻击者无法为新消息生成有效的认证标签。
pub trait UnforgeableMac: MessageAuthenticationCode {
    /// 检查 MAC 是否具有不可伪造性
    /// 
    /// # 返回值
    /// 
    /// 对于所有实现此特征的 MAC，都返回 `true`
    fn is_unforgeable() -> bool { true }
}

/// 安全 MAC 的标记特征
/// 
/// 实现此特征的 MAC 算法提供完整的安全性保证，包括不可伪造性、
/// 完整性检查和真实性验证。
pub trait SecureMac: MessageAuthenticationCode {
    /// 检查 MAC 是否安全
    /// 
    /// # 返回值
    /// 
    /// 对于所有实现此特征的 MAC，都返回 `true`
    fn is_secure() -> bool { true }
}

/// 通用的消息认证码标签结构
/// 
/// 这个结构体封装了各种 MAC 算法生成的认证标签，
/// 提供了统一的接口来处理不同长度和格式的标签。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MacTag {
    /// 认证标签的字节表示
    pub tag: Vec<u8>,
}

impl MacTag {
    /// 创建一个新的 MAC 标签
    /// 
    /// # 参数
    /// 
    /// * `tag` - 标签的字节向量
    /// 
    /// # 返回值
    /// 
    /// 返回新创建的 `MacTag` 实例
    pub fn new(tag: Vec<u8>) -> Self {
        MacTag { tag }
    }
    
    /// 从字节切片创建 MAC 标签
    /// 
    /// # 参数
    /// 
    /// * `bytes` - 包含标签数据的字节切片
    /// 
    /// # 返回值
    /// 
    /// 返回新创建的 `MacTag` 实例
    pub fn from_bytes(bytes: &[u8]) -> Self {
        MacTag { tag: bytes.to_vec() }
    }
    
    /// 获取标签的字节表示
    /// 
    /// # 返回值
    /// 
    /// 返回标签字节数据的引用
    pub fn to_bytes(&self) -> &[u8] {
        &self.tag
    }
    
    /// 获取标签的长度（字节数）
    /// 
    /// # 返回值
    /// 
    /// 返回标签的字节长度
    pub fn len(&self) -> usize {
        self.tag.len()
    }
    
    /// 检查标签是否为空
    /// 
    /// # 返回值
    /// 
    /// 如果标签为空返回 `true`，否则返回 `false`
    pub fn is_empty(&self) -> bool {
        self.tag.is_empty()
    }
}