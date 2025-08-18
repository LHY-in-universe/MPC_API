//! # 承诺方案模块 (Commitment Schemes)
//! 
//! 本模块实现了多种密码学承诺方案。承诺方案是一种密码学原语，
//! 允许一方对某个值进行承诺，而不泄露该值的信息，之后可以揭示承诺的值。
//! 
//! ## 核心概念
//! 
//! ### 承诺方案的两个阶段
//! 1. **承诺阶段**: 承诺者选择一个值和随机数，生成承诺
//! 2. **揭示阶段**: 承诺者公开原始值和随机数，验证者验证承诺
//! 
//! ### 安全性质
//! - **隐藏性 (Hiding)**: 承诺不泄露原始值的信息
//! - **绑定性 (Binding)**: 承诺者无法改变已承诺的值
//! 
//! ## 支持的承诺方案
//! 
//! - **Pedersen 承诺**: 基于离散对数的完美隐藏承诺
//! - **哈希承诺**: 基于哈希函数的简单承诺方案
//! - **Merkle 树**: 支持批量承诺的树状结构
//! 
//! ## 应用场景
//! 
//! - 零知识证明系统
//! - 安全多方计算协议
//! - 区块链和加密货币
//! - 电子投票系统
//! - 密封竞价拍卖
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::commitment::*;
//! 
//! // 哈希承诺示例
//! let message = b"secret message";
//! let randomness = generate_randomness();
//! let commitment = HashCommitment::commit(message.to_vec(), randomness);
//! 
//! // 验证承诺
//! let is_valid = HashCommitment::verify(commitment, message.to_vec(), randomness);
//! assert!(is_valid);
//! ```

pub mod pedersen;
pub mod hash_commit;
pub mod merkle_tree;

pub use pedersen::*;
pub use hash_commit::*;
pub use merkle_tree::*;

// use crate::Result; // Unused import
// use serde::{Deserialize, Serialize}; // Unused imports

/// 承诺方案基础 trait
/// 
/// 定义了所有承诺方案必须实现的基本操作：承诺生成和验证。
/// 这是所有承诺方案的核心接口。
pub trait CommitmentScheme {
    /// 承诺类型
    type Commitment;
    /// 消息类型
    type Message;
    /// 随机数类型
    type Randomness;
    
    /// 生成承诺
    /// 
    /// 使用消息和随机数生成承诺值。承诺值隐藏了原始消息，
    /// 但可以在后续的验证阶段用于证明承诺的正确性。
    /// 
    /// # 参数
    /// 
    /// * `message` - 要承诺的消息
    /// * `randomness` - 用于隐藏消息的随机数
    /// 
    /// # 返回值
    /// 
    /// 返回生成的承诺值
    fn commit(message: Self::Message, randomness: Self::Randomness) -> Self::Commitment;
    
    /// 验证承诺
    /// 
    /// 验证给定的承诺、消息和随机数是否匹配。
    /// 这用于在揭示阶段验证承诺的正确性。
    /// 
    /// # 参数
    /// 
    /// * `commitment` - 要验证的承诺值
    /// * `message` - 声称的原始消息
    /// * `randomness` - 声称的随机数
    /// 
    /// # 返回值
    /// 
    /// 如果承诺有效则返回 true，否则返回 false
    fn verify(commitment: Self::Commitment, message: Self::Message, randomness: Self::Randomness) -> bool;
}

/// 绑定性承诺 trait
/// 
/// 标记具有绑定性质的承诺方案。绑定性确保承诺者无法找到
/// 两个不同的消息-随机数对，使得它们产生相同的承诺。
/// 这防止了承诺者在揭示阶段改变原始承诺的值。
pub trait BindingCommitment: CommitmentScheme {
    /// 检查是否具有绑定性
    /// 
    /// # 返回值
    /// 
    /// 如果方案具有绑定性则返回 true
    fn is_binding() -> bool { true }
}

/// 隐藏性承诺 trait
/// 
/// 标记具有隐藏性质的承诺方案。隐藏性确保承诺值不会
/// 泄露关于原始消息的任何信息，即使攻击者具有无限的计算能力。
pub trait HidingCommitment: CommitmentScheme {
    /// 检查是否具有隐藏性
    /// 
    /// # 返回值
    /// 
    /// 如果方案具有隐藏性则返回 true
    fn is_hiding() -> bool { true }
}

