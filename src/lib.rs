//! # MPC API - 安全多方计算 (Secure Multi-Party Computation) 库
//! 
//! 这是一个用 Rust 实现的全面的安全多方计算库，提供了各种密码学原语和协议的实现。
//! 所有计算都在 u64 有限域上进行，使用素数 p = 2^61 - 1 作为模数。
//! 
//! ## 核心组件 (Core Components)
//! 
//! ### 秘密分享 (Secret Sharing)
//! - **Shamir 秘密分享**: 基于多项式插值的 (t,n) 门限秘密分享
//! - **加法秘密分享**: 支持加法同态运算的简单分享方案
//! 
//! ### 混淆电路 (Garbled Circuits)  
//! - **电路混淆**: 将布尔电路转换为混淆电路
//! - **Free XOR 优化**: 提高 XOR 门的效率
//! - **电路求值**: 安全地计算混淆电路
//! 
//! ### 不经意传输 (Oblivious Transfer)
//! - **基础 OT**: 1-out-of-2 不经意传输
//! - **相关 OT**: 具有固定偏移的相关不经意传输  
//! - **随机 OT**: 生成随机共享的不经意传输
//! - **OT 扩展**: 从少量基础 OT 扩展到大量 OT
//! 
//! ### 向量不经意线性求值 (Vector Oblivious Linear Evaluation)
//! - **VOLE**: 向量不经意线性函数求值
//! - **OLE**: 标量不经意线性函数求值
//! 
//! ### 同态加密 (Homomorphic Encryption)
//! - **ElGamal**: 乘法同态加密
//! - **Paillier**: 加法同态加密
//! - **RSA**: 乘法同态加密
//! - **BFV/BGV**: 全同态加密方案 (简化版)
//! 
//! ### 椭圆曲线密码学 (Elliptic Curve Cryptography)
//! - **ECDH**: 椭圆曲线 Diffie-Hellman 密钥交换
//! - **ECDSA**: 椭圆曲线数字签名算法
//! - **点运算**: 椭圆曲线上的基本运算
//! 
//! ### 高级协议 (Advanced Protocols)
//! - **投币协议**: 安全的随机数生成协议
//! - **承诺方案**: Pedersen、Hash-based、Merkle tree 承诺
//! - **消息认证码**: HMAC、Poly1305、GMAC、CMAC
//! - **SPDZ 协议**: 带认证的秘密分享协议
//! 
//! ## 设计原则 (Design Principles)
//! 
//! 1. **安全性**: 所有协议都实现了标准的安全性要求
//! 2. **效率**: 针对批处理操作进行了优化
//! 3. **模块化**: 每个组件都可以独立使用
//! 4. **可扩展性**: 基于特征的设计便于添加新实现
//! 5. **有限域运算**: 所有计算都在 u64 有限域上进行
//! 

pub mod secret_sharing;
pub mod garbled_circuits;
pub mod oblivious_transfer;
pub mod homomorphic_encryption;
pub mod elliptic_curve;
pub mod protocols;
pub mod commitment;
pub mod authentication;
pub mod spdz;
pub mod zero_knowledge;
pub mod beaver_triples;
pub mod utils;
pub mod security;
pub mod network;

pub use secret_sharing::*;
pub use garbled_circuits::*;
pub use oblivious_transfer::*;
pub use homomorphic_encryption::*;
pub use elliptic_curve::*;
pub use protocols::*;
pub use commitment::*;
pub use authentication::*;
pub use spdz::*;
// pub use zero_knowledge::*; // Unused import - zero knowledge not fully implemented
pub use beaver_triples::*;
pub use utils::*;
pub use security::*;
pub use network::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MpcError {
    #[error("Invalid secret share")]
    InvalidSecretShare,
    #[error("Insufficient shares for reconstruction")]
    InsufficientShares,
    #[error("Invalid threshold")]
    InvalidThreshold,
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
}

impl From<String> for MpcError {
    fn from(s: String) -> Self {
        MpcError::ProtocolError(s)
    }
}

impl From<&str> for MpcError {
    fn from(s: &str) -> Self {
        MpcError::ProtocolError(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, MpcError>;

