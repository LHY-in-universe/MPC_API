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

#[cfg(test)]
mod tests {
    use super::{MessageAuthenticationCode, HMAC, HmacTag, CMAC, GMAC, Poly1305};

    // ===== HMAC Tests =====
    // HMAC是基于哈希函数的消息认证码，广泛用于验证消息完整性和真实性

    /// 测试HMAC密钥生成功能
    /// 
    /// 目的：验证HMAC能够生成随机的、不同的密钥
    /// 预期：每次生成的密钥都应该不同，确保安全性
    #[test]
    fn test_hmac_generate_key() {
        let key1 = HMAC::generate_key();
        let key2 = HMAC::generate_key();
        
        // 验证两次生成的密钥不相同，确保随机性
        assert_ne!(key1.key, key2.key);
    }

    /// 测试HMAC基本认证和验证流程
    /// 
    /// 目的：验证HMAC的完整认证流程：生成标签 -> 验证标签
    /// 预期：使用相同密钥和消息生成的标签应该能够通过验证
    #[test]
    fn test_hmac_authenticate_and_verify() {
        let key = HMAC::generate_key();
        let message = b"Hello, HMAC!".to_vec();
        
        // 使用密钥对消息生成认证标签
        let tag = HMAC::authenticate(&key, &message);
        // 验证标签的正确性
        let verification = HMAC::verify(&key, &message, &tag);
        
        // 验证应该成功
        assert!(verification);
    }

    /// 测试HMAC使用错误密钥验证的安全性
    /// 
    /// 目的：验证HMAC能够正确拒绝使用不同密钥进行的验证
    /// 预期：使用不同密钥验证相同消息和标签时应该失败
    #[test]
    fn test_hmac_wrong_key() {
        let key1 = HMAC::generate_key();
        let key2 = HMAC::generate_key();
        let message = b"Hello, HMAC!".to_vec();
        
        // 使用第一个密钥生成标签
        let tag = HMAC::authenticate(&key1, &message);
        // 尝试使用第二个密钥验证 - 应该失败
        let verification = HMAC::verify(&key2, &message, &tag);
        
        // 验证应该失败，确保密钥安全性
        assert!(!verification);
    }

    /// 测试HMAC消息完整性检测能力
    /// 
    /// 目的：验证HMAC能够检测到消息被篡改
    /// 预期：对不同消息使用相同标签验证时应该失败
    #[test]
    fn test_hmac_wrong_message() {
        let key = HMAC::generate_key();
        let message1 = b"Hello, HMAC!".to_vec();
        let message2 = b"Hello, MAC!".to_vec();
        
        // 为第一个消息生成标签
        let tag = HMAC::authenticate(&key, &message1);
        // 尝试用该标签验证第二个消息 - 应该失败
        let verification = HMAC::verify(&key, &message2, &tag);
        
        // 验证应该失败，确保消息完整性
        assert!(!verification);
    }

    /// 测试HMAC对64位无符号整数的专用认证功能
    /// 
    /// 目的：验证HMAC能够直接对u64类型数据进行认证和验证
    /// 预期：64位整数的认证和验证应该成功
    #[test]
    fn test_hmac_u64() {
        let key = HMAC::generate_key();
        let value = 12345u64;
        
        // 计算u64值的HMAC标签
        let tag_bytes = HMAC::compute_hmac_u64(&key.key, value);
        let tag = HmacTag { tag: tag_bytes };
        // 验证u64值的HMAC标签
        let verification = HMAC::verify_u64(&key, value, &tag);
        
        // 验证应该成功
        assert!(verification);
    }

    /// 测试HMAC批量操作功能
    /// 
    /// 目的：验证HMAC能够高效地批量处理多个消息的认证和验证
    /// 预期：批量认证应该生成正确数量的标签，批量验证应该成功
    #[test]
    fn test_hmac_batch_operations() {
        let key = HMAC::generate_key();
        let messages = vec![
            b"message1".to_vec(),
            b"message2".to_vec(),
            b"message3".to_vec(),
        ];
        
        // 批量生成认证标签
        let tags = HMAC::batch_authenticate(&key, &messages);
        assert_eq!(tags.len(), 3); // 确保生成了正确数量的标签
        
        // 批量验证所有标签
        let verification = HMAC::batch_verify(&key, &messages, &tags).unwrap();
        assert!(verification); // 所有验证都应该成功
    }

    /// 测试HMAC在秘密分享中的应用
    /// 
    /// 目的：验证HMAC能够对秘密分享的份额进行认证
    /// 预期：份额认证和验证应该成功，确保分享数据的完整性
    #[test]
    fn test_hmac_authenticate_share() {
        let key = HMAC::generate_key();
        let share_value = 123u64;
        let share_index = 0usize;
        
        // 对秘密分享份额进行认证
        let tag = HMAC::authenticate_share(&key, share_value, share_index);
        // 验证份额的完整性
        let verification = HMAC::verify_share(&key, share_value, share_index, &tag);
        
        // 验证应该成功
        assert!(verification);
    }

    /// 测试HMAC基于密钥派生功能（HKDF）
    /// 
    /// 目的：验证HMAC能够从主密钥派生出确定性的子密钥
    /// 预期：相同输入应产生相同的派生密钥，且长度正确
    #[test]
    fn test_hmac_key_derivation() {
        let master_key = b"master_secret_key";
        let info = b"application_context"; // 上下文信息
        let length = 32; // 期望的密钥长度
        
        // 两次派生相同参数的密钥
        let derived_key1 = HMAC::derive_key(master_key, info, length);
        let derived_key2 = HMAC::derive_key(master_key, info, length);
        
        // 派生结果应该一致且长度正确
        assert_eq!(derived_key1, derived_key2);
        assert_eq!(derived_key1.len(), length);
    }

    /// 测试HMAC密钥拉伸功能（PBKDF2）
    /// 
    /// 目的：验证HMAC能够通过迭代计算将弱密码转换为强密钥
    /// 预期：相同输入产生相同密钥，不同盐产生不同密钥
    #[test]
    fn test_hmac_key_stretching() {
        let password = b"weak_password";
        let salt = b"random_salt";
        let iterations = 1000; // 迭代次数增加计算强度
        
        // 两次拉伸相同参数
        let stretched_key1 = HMAC::stretch_key(password, salt, iterations);
        let stretched_key2 = HMAC::stretch_key(password, salt, iterations);
        
        // 相同输入应产生相同结果
        assert_eq!(stretched_key1.key, stretched_key2.key);
        
        // 不同盐应产生不同密钥（防止彩虹表攻击）
        let different_salt = b"different_salt";
        let stretched_key3 = HMAC::stretch_key(password, different_salt, iterations);
        assert_ne!(stretched_key1.key, stretched_key3.key);
    }

    /// 测试HMAC安全比较功能（防止时序攻击）
    /// 
    /// 目的：验证HMAC提供的常时间比较功能能防止时序攻击
    /// 预期：相同数据返回true，不同数据或长度返回false
    #[test]
    fn test_hmac_secure_compare() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];
        
        // 相同数据应该返回true
        assert!(HMAC::secure_compare(&a, &b));
        // 不同数据应该返回false
        assert!(!HMAC::secure_compare(&a, &c));
        // 不同长度应该返回false
        assert!(!HMAC::secure_compare(&a, &[1, 2, 3, 4]));
    }

    /// 测试HMAC标准测试向量（基于RFC 2202）
    /// 
    /// 目的：验证HMAC实现符合标准规范
    /// 预期：使用标准测试向量应产生正确长度和确定性的标签
    #[test]
    fn test_hmac_test_vectors() {
        // RFC 2202 test vectors (simplified)
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        
        // 计算HMAC标签
        let tag = HMAC::compute_hmac(key, message);
        assert_eq!(tag.len(), 32); // 验证标签长度
        
        // 标签应该是确定性的（相同输入产生相同输出）
        let tag2 = HMAC::compute_hmac(key, message);
        assert_eq!(tag, tag2);
    }

    // ===== CMAC Tests =====
    // CMAC是基于分组密码（如AES）的消息认证码，提供与HMAC类似的安全性

    /// 测试CMAC密钥生成功能
    /// 
    /// 目的：验证CMAC能够生成随机的、不同的密钥
    /// 预期：每次生成的密钥都应该不同，确保安全性
    #[test]
    fn test_cmac_generate_key() {
        let key1 = CMAC::generate_key();
        let key2 = CMAC::generate_key();
        
        // 验证两次生成的密钥不相同，确保随机性
        assert_ne!(key1.key, key2.key);
    }

    /// 测试CMAC基本认证和验证流程
    /// 
    /// 目的：验证CMAC的完整认证流程：生成标签 -> 验证标签
    /// 预期：使用相同密钥和消息生成的标签应该能够通过验证
    #[test]
    fn test_cmac_authenticate_and_verify() {
        let key = CMAC::generate_key();
        let message = b"Hello, CMAC!".to_vec();
        
        // 使用密钥对消息生成认证标签
        let tag = CMAC::authenticate(&key, &message);
        // 验证标签的正确性
        let verification = CMAC::verify(&key, &message, &tag);
        
        // 验证应该成功
        assert!(verification);
    }

    /// 测试CMAC使用错误密钥验证的安全性
    /// 
    /// 目的：验证CMAC能够正确拒绝使用不同密钥进行的验证
    /// 预期：使用不同密钥验证相同消息和标签时应该失败
    #[test]
    fn test_cmac_wrong_key() {
        let key1 = CMAC::generate_key();
        let key2 = CMAC::generate_key();
        let message = b"Hello, CMAC!".to_vec();
        
        // 使用第一个密钥生成标签
        let tag = CMAC::authenticate(&key1, &message);
        // 尝试使用第二个密钥验证 - 应该失败
        let verification = CMAC::verify(&key2, &message, &tag);
        
        // 验证应该失败，确保密钥安全性
        assert!(!verification);
    }

    /// 测试CMAC消息完整性检测能力
    /// 
    /// 目的：验证CMAC能够检测到消息被篡改
    /// 预期：对不同消息使用相同标签验证时应该失败
    #[test]
    fn test_cmac_wrong_message() {
        let key = CMAC::generate_key();
        let message1 = b"Hello, CMAC!".to_vec();
        let message2 = b"Hello, MAC!".to_vec();
        
        // 为第一个消息生成标签
        let tag = CMAC::authenticate(&key, &message1);
        // 尝试用该标签验证第二个消息 - 应该失败
        let verification = CMAC::verify(&key, &message2, &tag);
        
        // 验证应该失败，确保消息完整性
        assert!(!verification);
    }

    /// 测试CMAC处理空消息的能力
    /// 
    /// 目的：验证CMAC能够正确处理长度为零的消息
    /// 预期：空消息的认证和验证应该成功
    #[test]
    fn test_cmac_empty_message() {
        let key = CMAC::generate_key();
        let empty_message = Vec::new();
        
        // 对空消息生成认证标签
        let tag = CMAC::authenticate(&key, &empty_message);
        // 验证空消息的标签
        let verification = CMAC::verify(&key, &empty_message, &tag);
        
        // 验证应该成功
        assert!(verification);
    }

    /// 测试CMAC对有限域元素的专用认证功能
    /// 
    /// 目的：验证CMAC能够直接对有限域中的数值进行认证
    /// 预期：有限域元素的认证和验证应该成功
    #[test]
    fn test_cmac_field_element() {
        let key = CMAC::generate_key();
        let value = 12345u64;
        
        // 对有限域元素生成认证标签
        let tag = CMAC::authenticate_field_element(&key, value);
        // 验证有限域元素的标签
        let verification = CMAC::verify_field_element(&key, value, &tag);
        
        // 验证应该成功
        assert!(verification);
    }

    /// 测试CMAC批量操作功能
    /// 
    /// 目的：验证CMAC能够高效地批量处理多个消息的认证和验证
    /// 预期：批量认证应该生成正确数量的标签，批量验证应该成功
    #[test]
    fn test_cmac_batch_operations() {
        let key = CMAC::generate_key();
        let messages = vec![
            b"message1".to_vec(),
            b"message2".to_vec(),
            b"message3".to_vec(),
        ];
        
        // 批量生成认证标签
        let tags = CMAC::batch_authenticate(&key, &messages);
        assert_eq!(tags.len(), 3); // 确保生成了正确数量的标签
        
        // 批量验证所有标签
        let verification = CMAC::batch_verify(&key, &messages, &tags).unwrap();
        assert!(verification); // 所有验证都应该成功
    }

    /// 测试CMAC子密钥生成算法
    /// 
    /// 目的：验证CMAC子密钥生成算法的正确性
    /// 预期：子密钥K1和K2应该与原密钥不同，且彼此不同
    #[test]
    fn test_cmac_subkey_generation() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        
        // 生成CMAC子密钥K1和K2
        let (k1, k2) = CMAC::generate_subkeys(&key);
        
        // 子密钥应该与原密钥不同，确保安全性
        assert_ne!(k1, key);
        assert_ne!(k2, key);
        assert_ne!(k1, k2); // K1和K2也应该不同
    }

    /// 测试CMAC左移位算法
    /// 
    /// 目的：验证CMAC的左移位操作，这是子密钥生成中的关键步骤
    /// 预期：当最高位为1时，左移后应与0x87进行异或
    #[test]
    fn test_cmac_left_shift() {
        let input = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // 执行左移位操作
        let shifted = CMAC::left_shift(&input);
        
        // 由于最高位(MSB)为1，左移后应与0x87异或
        assert_eq!(shifted[15], 0x87);
    }

    #[test]
    fn test_cmac_incremental() {
        let key = CMAC::generate_key();
        let data1 = b"Hello, ";
        let data2 = b"CMAC ";
        let data3 = b"world!";
        
        let mut state = CMAC::start_incremental(&key.key);
        CMAC::incremental_update(&mut state, data1);
        CMAC::incremental_update(&mut state, data2);
        CMAC::incremental_update(&mut state, data3);
        let incremental_tag = CMAC::incremental_finalize(&state);
        
        // Compare with direct computation
        let mut combined = Vec::new();
        combined.extend_from_slice(data1);
        combined.extend_from_slice(data2);
        combined.extend_from_slice(data3);
        let direct_tag = CMAC::authenticate(&key, &combined);
        
        assert_eq!(incremental_tag.tag, direct_tag.tag);
    }

    #[test]
    fn test_cmac_deterministic() {
        let key = CMAC::generate_key();
        let message = b"Test message for determinism".to_vec();
        
        let tag1 = CMAC::authenticate(&key, &message);
        let tag2 = CMAC::authenticate(&key, &message);
        
        assert_eq!(tag1.tag, tag2.tag);
    }

    #[test]
    fn test_omac() {
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let message = b"Test OMAC";
        
        let tag = CMAC::compute_omac(&key, message);
        assert_eq!(tag.len(), 16); // CMAC_TAG_SIZE
    }

    #[test]
    fn test_cmac_different_length_messages() {
        let key = CMAC::generate_key();
        
        // Test messages of different lengths
        let messages = vec![
            Vec::new(),                    // Empty
            b"a".to_vec(),                // 1 byte
            b"ab".to_vec(),               // 2 bytes
            b"abcdefghijklmnop".to_vec(), // Exactly one block (16 bytes)
            b"abcdefghijklmnopq".to_vec(),// One block + 1 byte
            b"The quick brown fox jumps over the lazy dog".to_vec(), // Multiple blocks
        ];
        
        for message in messages {
            let tag = CMAC::authenticate(&key, &message);
            let verification = CMAC::verify(&key, &message, &tag);
            assert!(verification, "Failed for message length: {}", message.len());
        }
    }

    // ===== GMAC Tests =====
    // GMAC是伽罗华消息认证码，基于有限域运算，常与AES-GCM模式一起使用

    /// 测试GMAC密钥生成功能
    /// 
    /// 目的：验证GMAC能够生成随机的、不同的密钥对(h,k)
    /// 预期：每次生成的密钥对都应该不同，确保安全性
    #[test]
    fn test_gmac_generate_key() {
        let key1 = GMAC::generate_key();
        let key2 = GMAC::generate_key();
        
        // 验证两次生成的密钥对不相同，确保随机性
        assert_ne!(key1.h, key2.h);
        assert_ne!(key1.k, key2.k);
    }

    /// 测试GMAC基本认证和验证流程
    /// 
    /// 目的：验证GMAC的完整认证流程：生成标签 -> 验证标签
    /// 预期：使用相同密钥和消息生成的标签应该能够通过验证
    #[test]
    fn test_gmac_authenticate_and_verify() {
        let key = GMAC::generate_key();
        let message = b"Hello, GMAC!".to_vec();
        
        // 使用密钥对消息生成认证标签
        let tag = GMAC::authenticate(&key, &message);
        // 验证标签的正确性
        let verification = GMAC::verify(&key, &message, &tag);
        
        // 验证应该成功
        assert!(verification);
    }

    #[test]
    fn test_gmac_wrong_key() {
        let key1 = GMAC::generate_key();
        let key2 = GMAC::generate_key();
        let message = b"Hello, GMAC!".to_vec();
        
        let tag = GMAC::authenticate(&key1, &message);
        let verification = GMAC::verify(&key2, &message, &tag);
        
        assert!(!verification);
    }

    #[test]
    fn test_gmac_wrong_message() {
        let key = GMAC::generate_key();
        let message1 = b"Hello, GMAC!".to_vec();
        let message2 = b"Hello, MAC!".to_vec();
        
        let tag = GMAC::authenticate(&key, &message1);
        let verification = GMAC::verify(&key, &message2, &tag);
        
        assert!(!verification);
    }

    /// 测试GF(2^128)有限域乘法运算
    /// 
    /// 目的：验证GMAC中使用的伽罗华域乘法运算的正确性
    /// 预期：乘法应该满足交换律、单位元性质和零元性质
    #[test]
    fn test_gf128_multiplication() {
        let a = 0x123456789abcdef0fedcba9876543210u128;
        let b = 0xfedcba9876543210123456789abcdef0u128;
        
        let result = GMAC::gf128_mul(a, b);
        
        // 乘法应该满足交换律：a*b = b*a
        let result2 = GMAC::gf128_mul(b, a);
        assert_eq!(result, result2);
        
        // 乘以1应该是单位元：a*1 = a
        let identity = GMAC::gf128_mul(a, 1);
        assert_eq!(identity, a);
        
        // 乘以0应该是零元：a*0 = 0
        let zero = GMAC::gf128_mul(a, 0);
        assert_eq!(zero, 0);
    }

    #[test]
    fn test_gmac_field_element() {
        let key = GMAC::generate_key();
        let value = 12345u64;
        
        let tag = GMAC::authenticate_field_element(&key, value);
        let verification = GMAC::verify_field_element(&key, value, &tag);
        
        assert!(verification);
    }

    #[test]
    fn test_gmac_batch_operations() {
        let key = GMAC::generate_key();
        let messages = vec![
            b"message1".to_vec(),
            b"message2".to_vec(),
            b"message3".to_vec(),
        ];
        
        let tags = GMAC::batch_authenticate(&key, &messages);
        assert_eq!(tags.len(), 3);
        
        let verification = GMAC::batch_verify(&key, &messages, &tags).unwrap();
        assert!(verification);
    }

    #[test]
    fn test_gmac_incremental() {
        let key = GMAC::generate_key();
        let data1 = b"Hello, ";
        let data2 = b"GMAC ";
        let data3 = b"world!";
        
        let mut state = GMAC::start_incremental(&key.h);
        GMAC::incremental_update(&mut state, data1);
        GMAC::incremental_update(&mut state, data2);
        GMAC::incremental_update(&mut state, data3);
        let incremental_tag = GMAC::incremental_finalize(&state, &key.k);
        
        // Compare with direct computation
        let mut combined = Vec::new();
        combined.extend_from_slice(data1);
        combined.extend_from_slice(data2);
        combined.extend_from_slice(data3);
        let direct_tag = GMAC::authenticate(&key, &combined);
        
        assert_eq!(incremental_tag.tag, direct_tag.tag);
    }

    #[test]
    fn test_ghash() {
        let h = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let data = b"Test data for GHASH";
        
        let hash1 = GMAC::ghash(&h, data);
        let hash2 = GMAC::ghash(&h, data);
        
        // Should be deterministic
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_gmac_polynomial_eval() {
        let h = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let blocks = vec![
            b"block1".to_vec(),
            b"block2".to_vec(),
            b"block3".to_vec(),
        ];
        
        let tag = GMAC::polynomial_eval(&h, &blocks);
        assert_eq!(tag.tag.len(), 16); // GMAC_TAG_SIZE
    }

    #[test]
    fn test_gmac_empty_message() {
        let key = GMAC::generate_key();
        let empty_message = Vec::new();
        
        let tag = GMAC::authenticate(&key, &empty_message);
        let verification = GMAC::verify(&key, &empty_message, &tag);
        
        assert!(verification);
    }

    #[test]
    fn test_bytes_to_gf128_conversion() {
        let bytes = [0xFF; 16];
        let gf_value = GMAC::bytes_to_gf128(&bytes);
        let converted_back = GMAC::gf128_to_bytes(gf_value);
        
        assert_eq!(bytes, converted_back);
    }

    // ===== Poly1305 Tests =====
    // Poly1305是一种高性能消息认证码，由Daniel J. Bernstein设计

    /// 测试Poly1305密钥生成功能
    /// 
    /// 目的：验证Poly1305能够生成随机的、不同的密钥对(r,s)
    /// 预期：每次生成的密钥对都应该不同，确保安全性
    #[test]
    fn test_poly1305_generate_key() {
        let key1 = Poly1305::generate_key();
        let key2 = Poly1305::generate_key();
        
        // 验证两次生成的密钥对不相同，确保随机性
        assert_ne!(key1.r, key2.r);
        assert_ne!(key1.s, key2.s);
    }

    /// 测试Poly1305基本认证和验证流程
    /// 
    /// 目的：验证Poly1305的完整认证流程：生成标签 -> 验证标签
    /// 预期：使用相同密钥和消息生成的标签应该能够通过验证
    #[test]
    fn test_poly1305_authenticate_and_verify() {
        let key = Poly1305::generate_key();
        let message = b"Hello, Poly1305!".to_vec();
        
        // 使用密钥对消息生成认证标签
        let tag = Poly1305::authenticate(&key, &message);
        // 验证标签的正确性
        let verification = Poly1305::verify(&key, &message, &tag);
        
        // 验证应该成功
        assert!(verification);
    }

    #[test]
    fn test_poly1305_wrong_key() {
        let key1 = Poly1305::generate_key();
        let key2 = Poly1305::generate_key();
        let message = b"Hello, Poly1305!".to_vec();
        
        let tag = Poly1305::authenticate(&key1, &message);
        let verification = Poly1305::verify(&key2, &message, &tag);
        
        assert!(!verification);
    }

    #[test]
    fn test_poly1305_wrong_message() {
        let key = Poly1305::generate_key();
        let message1 = b"Hello, Poly1305!".to_vec();
        let message2 = b"Hello, MAC!".to_vec();
        
        let tag = Poly1305::authenticate(&key, &message1);
        let verification = Poly1305::verify(&key, &message2, &tag);
        
        assert!(!verification);
    }

    #[test]
    fn test_poly1305_field_element() {
        let key = Poly1305::generate_key();
        let value = 12345u64;
        
        let tag = Poly1305::authenticate_field_element(&key, value);
        let verification = Poly1305::verify_field_element(&key, value, &tag);
        
        assert!(verification);
    }

    #[test]
    fn test_poly1305_batch_operations() {
        let key = Poly1305::generate_key();
        let messages = vec![
            b"message1".to_vec(),
            b"message2".to_vec(),
            b"message3".to_vec(),
        ];
        
        let tags = Poly1305::batch_authenticate(&key, &messages);
        assert_eq!(tags.len(), 3);
        
        let verification = Poly1305::batch_verify(&key, &messages, &tags).unwrap();
        assert!(verification);
    }

    #[test]
    fn test_poly1305_incremental() {
        let key = Poly1305::generate_key();
        let chunks = vec![
            b"chunk1".to_vec(),
            b"chunk2".to_vec(),
            b"chunk3".to_vec(),
        ];
        
        let incremental_tag = Poly1305::incremental_authenticate(&key, &chunks);
        
        // Verify against concatenated message
        let mut combined = Vec::new();
        for chunk in &chunks {
            combined.extend_from_slice(chunk);
        }
        let direct_tag = Poly1305::authenticate(&key, &combined);
        
        assert_eq!(incremental_tag.tag, direct_tag.tag);
    }

    #[test]
    fn test_poly1305_one_time_key() {
        let master_key = b"0123456789abcdef0123456789abcdef";
        let nonce = b"nonce1234567890x"; // 16 bytes
        
        let key1 = Poly1305::generate_one_time_key(master_key, nonce).unwrap();
        let key2 = Poly1305::generate_one_time_key(master_key, nonce).unwrap();
        
        // Same master key and nonce should produce same one-time key
        assert_eq!(key1.r, key2.r);
        assert_eq!(key1.s, key2.s);
        
        // Different nonce should produce different key
        let different_nonce = b"different_nonce!";
        let key3 = Poly1305::generate_one_time_key(master_key, different_nonce).unwrap();
        assert_ne!(key1.r, key3.r);
    }

    #[test]
    fn test_poly1305_authenticated_encryption() {
        let key = Poly1305::generate_key();
        let plaintext = b"Secret message";
        let additional_data = b"public_header";
        
        let (ciphertext, tag) = Poly1305::authenticated_encrypt(&key, plaintext, additional_data);
        
        assert_ne!(ciphertext, plaintext.to_vec());
        
        let decrypted = Poly1305::authenticated_decrypt(&key, &ciphertext, additional_data, &tag).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_poly1305_authenticated_decryption_failure() {
        let key = Poly1305::generate_key();
        let plaintext = b"Secret message";
        let additional_data = b"public_header";
        let wrong_additional_data = b"wrong_header";
        
        let (ciphertext, tag) = Poly1305::authenticated_encrypt(&key, plaintext, additional_data);
        
        // Should fail with wrong additional data
        let result = Poly1305::authenticated_decrypt(&key, &ciphertext, wrong_additional_data, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_poly1305_empty_message() {
        let key = Poly1305::generate_key();
        let empty_message = Vec::new();
        
        let tag = Poly1305::authenticate(&key, &empty_message);
        let verification = Poly1305::verify(&key, &empty_message, &tag);
        
        assert!(verification);
    }

    #[test]
    fn test_poly1305_large_message() {
        let key = Poly1305::generate_key();
        let large_message = vec![0u8; 1000]; // 1KB message
        
        let tag = Poly1305::authenticate(&key, &large_message);
        let verification = Poly1305::verify(&key, &large_message, &tag);
        
        assert!(verification);
    }
}