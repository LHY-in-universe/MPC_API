//! # 不经意传输模块 (Oblivious Transfer)
//! 
//! 本模块实现了多种不经意传输协议。不经意传输是一种密码学原语，
//! 允许发送方持有多个消息，而接收方只能获取其中一个消息，且发送方不知道接收方选择了哪个。
//! 
//! ## 核心概念
//! 
//! ### 基本 1-out-of-2 OT
//! - 发送方有两个消息 m₀ 和 m₁
//! - 接收方有一个选择位 b ∈ {0,1}
//! - 协议结束后，接收方只获得 mᵦ，不知道 m₁₋ᵦ
//! - 发送方不知道接收方选择了哪个消息
//! 
//! ### 安全性质
//! - **接收方隐私**: 发送方不知道接收方的选择位
//! - **发送方隐私**: 接收方只能获得一个消息
//! 
//! ## 支持的协议
//! 
//! - **基本 1-out-of-2 OT**: 基础不经意传输协议
//! - **相关不经意传输 (COT)**: 两个消息满足特定关系
//! - **随机不经意传输 (ROT)**: 消息由协议随机生成
//! - **OT 扩展**: 使用少量基础 OT 实现大量 OT
//! - **Naor-Pinkas OT**: 基于离散对数的高效实现
//! - **向量不经意线性求值 (VOLE)**: 向量形式的 OLE
//! - **不经意线性求值 (OLE)**: 允许接收方获得线性函数的值
//! 
//! ## 应用场景
//! 
//! - 安全多方计算
//! - 隐私保护机器学习
//! - 零知识证明系统
//! - 私有集合求交
//! - 混淆电路协议
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::oblivious_transfer::*;
//! 
//! // 基本 1-out-of-2 OT
//! let mut ot = BasicOT::new();
//! 
//! // 发送方有两个消息
//! let sender_messages = OTSenderInput {
//!     message0: b"secret0".to_vec(),
//!     message1: b"secret1".to_vec(),
//! };
//! 
//! // 接收方选择第二个消息
//! let receiver_choice = OTReceiverInput {
//!     choice_bit: true,
//! };
//! 
//! // 执行 OT 协议
//! let sender_output = ot.sender_setup(sender_messages)?;
//! let receiver_output = ot.receiver_setup(receiver_choice)?;
//! 
//! // 接收方获得了选择的消息，但不知道另一个
//! assert_eq!(receiver_output.chosen_message, b"secret1".to_vec());
//! ```

pub mod basic_ot;
pub mod correlated_ot;
pub mod random_ot;
pub mod ot_extension;
pub mod naor_pinkas;
pub mod vole;
pub mod ole;

pub use basic_ot::*;
pub use correlated_ot::*;
pub use random_ot::*;
pub use ot_extension::*;
pub use naor_pinkas::*;
pub use vole::*;
pub use ole::*;

use crate::{MpcError, Result};
use crate::secret_sharing::{FIELD_PRIME, field_add, field_mul};
use serde::{Deserialize, Serialize};
use rand::Rng;

/// 不经意传输消息类型
/// 
/// 表示 OT 协议中传输的消息，使用字节向量表示。
pub type OTMessage = Vec<u8>;

/// 选择位类型
/// 
/// 表示接收方的选择，用于指定要接收的消息。
pub type ChoiceBit = bool;

/// 发送方输出结构
/// 
/// 包含发送方在 OT 协议中提供的两个消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTSenderOutput {
    /// 第一个消息（对应选择位 0）
    pub message0: OTMessage,
    /// 第二个消息（对应选择位 1）
    pub message1: OTMessage,
}

/// 接收方输入结构
/// 
/// 包含接收方在 OT 协议中的选择位。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTReceiverInput {
    /// 选择位，决定接收方要获取的消息
    pub choice_bit: ChoiceBit,
}

/// 接收方输出结构
/// 
/// 包含接收方在 OT 协议中获取的消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTReceiverOutput {
    /// 接收方根据选择位获取的消息
    pub chosen_message: OTMessage,
}

/// 基于 Diffie-Hellman 的 OT 设置
/// 
/// 使用 u64 有限域实现的 Diffie-Hellman 不经意传输协议的参数设置。
/// 这是实现基本 OT 协议的密码学基础。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHOTSetup {
    /// 生成元
    pub generator: u64,
    /// 素数模数
    pub prime: u64,
    /// 发送方私钥
    pub sender_private: u64,
    /// 接收方私钥
    pub receiver_private: u64,
}

impl DHOTSetup {
    /// 创建新的 Diffie-Hellman OT 设置
    /// 
    /// 初始化 DH-OT 协议所需的参数，包括生成元、素数模数和双方的私钥。
    /// 私钥是随机生成的，用于确保协议的安全性。
    /// 
    /// # 返回值
    /// 
    /// 返回初始化的 DHOTSetup 实例
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            generator: 3, // 为我们的有限域选择的简单生成元
            prime: FIELD_PRIME,
            sender_private: rng.gen_range(1..FIELD_PRIME),
            receiver_private: rng.gen_range(1..FIELD_PRIME),
        }
    }
    
    /// 模幂运算
    /// 
    /// 计算 base^exp mod prime，使用快速幂算法实现。
    /// 这是 Diffie-Hellman 协议的核心操作。
    /// 
    /// # 参数
    /// 
    /// * `base` - 底数
    /// * `exp` - 指数
    /// 
    /// # 返回值
    /// 
    /// 返回模幂运算的结果
    pub fn pow_mod(&self, base: u64, exp: u64) -> u64 {
        if exp == 0 {
            return 1;
        }
        
        let mut result = 1u64;
        let mut base = base % self.prime;
        let mut exp = exp;
        
        while exp > 0 {
            if exp % 2 == 1 {
                result = field_mul(result, base);
            }
            exp >>= 1;
            base = field_mul(base, base);
        }
        
        result
    }
}

impl Default for DHOTSetup {
    fn default() -> Self {
        Self::new()
    }
}

/// 不经意传输协议 trait
/// 
/// 定义了所有不经意传输协议必须实现的基本操作。
/// 这是所有 OT 协议变种的基础接口。
pub trait ObliviousTransfer {
    /// 发送方输入类型
    type SenderInput;
    /// 接收方输入类型
    type ReceiverInput;
    /// 发送方输出类型
    type SenderOutput;
    /// 接收方输出类型
    type ReceiverOutput;
    
    /// 发送方设置阶段
    /// 
    /// 发送方使用输入消息初始化 OT 协议。这个阶段发送方准备要传输的消息，
    /// 但还不会实际发送给接收方。
    /// 
    /// # 返回值
    /// 
    /// 返回发送方的输出，或者在出错时返回错误
    fn sender_setup(&mut self) -> Result<Self::SenderOutput>;
    
    /// 接收方设置阶段
    /// 
    /// 接收方使用选择位初始化 OT 协议。这个阶段接收方指定要接收的消息，
    /// 但还不会实际从发送方获取消息。
    /// 
    /// # 参数
    /// 
    /// * `input` - 接收方的输入，通常包含选择位
    /// 
    /// # 返回值
    /// 
    /// 返回接收方的输出，或者在出错时返回错误
    fn receiver_setup(&mut self, input: Self::ReceiverInput) -> Result<Self::ReceiverOutput>;
}

// OT 协议的辅助函数

/// 字节数组异或运算
/// 
/// 对两个字节数组执行逐位异或操作。这是密码学协议中常用的操作，
/// 用于加密、解密和掩码操作。
/// 
/// # 参数
/// 
/// * `a` - 第一个字节数组
/// * `b` - 第二个字节数组
/// 
/// # 返回值
/// 
/// 返回异或结果的字节向量
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// random_bytes function removed to avoid duplicate definition
// Use crate::utils::random_bytes instead

/// 将整数哈希为字节数组
/// 
/// 使用 SHA-256 哈希函数将 u64 整数转换为字节数组。
/// 这在 OT 协议中用于生成伪随机掩码和密钥派生。
/// 
/// # 参数
/// 
/// * `input` - 要哈希的 u64 整数
/// 
/// # 返回值
/// 
/// 返回 SHA-256 哈希值的字节向量
pub fn hash_to_bytes(input: u64) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.to_le_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    //! 不经意传输测试
    //! 
    //! 包含基础 OT, OT 扩展, VOLE, Random OT 等不经意传输协议的测试

    use super::*;

    // Tests will be moved here from src/oblivious_transfer/
}