//! # 椭圆曲线密码学模块 (Elliptic Curve Cryptography)
//! 
//! 本模块实现了椭圆曲线密码学的基本原语，包括椭圆曲线上的点运算、
//! 椭圆曲线 Diffie-Hellman 密钥交换 (ECDH) 和椭圆曲线数字签名算法 (ECDSA)。
//! 
//! ## 支持的椭圆曲线
//! 
//! - **Curve25519**: 高性能的蒙哥马利曲线，用于密钥交换
//! - **secp256k1**: Bitcoin 使用的椭圆曲线，用于数字签名
//! 
//! ## 核心功能
//! 
//! ### 椭圆曲线点运算
//! - 点加法和点倍乘
//! - 标量乘法
//! - 点验证
//! 
//! ### 密钥交换 (ECDH)
//! - 密钥对生成
//! - 共享密钥计算
//! 
//! ### 数字签名 (ECDSA)
//! - 消息签名
//! - 签名验证
//! 
//! ## 数学基础
//! 
//! 椭圆曲线定义为：y² = x³ + ax + b (mod p)
//! 其中 p 是大素数，a 和 b 是曲线参数。
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::elliptic_curve::*;
//! 
//! // ECDH 密钥交换
//! let (alice_private, alice_public) = ECDH::generate_keypair()?;
//! let (bob_private, bob_public) = ECDH::generate_keypair()?;
//! 
//! let alice_shared = ECDH::compute_shared_secret(alice_private, &bob_public)?;
//! let bob_shared = ECDH::compute_shared_secret(bob_private, &alice_public)?;
//! assert_eq!(alice_shared, bob_shared);
//! ```

pub mod curve25519;
pub mod secp256k1;
pub mod point;
pub mod scalar;
pub mod ecdh;
pub mod ecdsa;

// pub use curve25519::*; // Unused import
// pub use secp256k1::*; // Unused import
pub use point::*;
pub use scalar::*;
pub use ecdh::*;
pub use ecdsa::*;

use crate::{MpcError, Result};
use serde::{Deserialize, Serialize};

/// 椭圆曲线上的点表示
/// 
/// 表示椭圆曲线上的一个点，包括坐标和无穷远点标记。
/// 椭圆曲线上的点形成一个阿贝尔群，支持点加法运算。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ECPoint {
    /// 点的 x 坐标
    pub x: u64,
    /// 点的 y 坐标
    pub y: u64,
    /// 是否为无穷远点（群的单位元）
    pub is_infinity: bool,
}

impl ECPoint {
    /// 创建椭圆曲线上的新点
    /// 
    /// # 参数
    /// 
    /// * `x` - 点的 x 坐标
    /// * `y` - 点的 y 坐标
    /// 
    /// # 返回值
    /// 
    /// 返回新创建的椭圆曲线点
    pub fn new(x: u64, y: u64) -> Self {
        Self {
            x,
            y,
            is_infinity: false,
        }
    }
    
    /// 创建无穷远点
    /// 
    /// 无穷远点是椭圆曲线群的单位元，满足 P + O = P 对所有点 P 成立。
    /// 
    /// # 返回值
    /// 
    /// 返回无穷远点
    pub fn infinity() -> Self {
        Self {
            x: 0,
            y: 0,
            is_infinity: true,
        }
    }
    
    /// 检查点是否为无穷远点
    /// 
    /// # 返回值
    /// 
    /// 如果是无穷远点返回 `true`，否则返回 `false`
    pub fn is_infinity(&self) -> bool {
        self.is_infinity
    }
}

/// 椭圆曲线参数
/// 
/// 定义椭圆曲线 y² = x³ + ax + b (mod p) 的所有参数。
/// 这些参数完全确定了一条椭圆曲线及其密码学性质。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECParams {
    /// 曲线参数 a
    pub a: u64,
    /// 曲线参数 b
    pub b: u64,
    /// 素数模数 p，定义有限域 F_p
    pub p: u64,
    /// 曲线的阶（点的总数），用于标量运算
    pub n: u64,
    /// 生成元点，用于生成椭圆曲线群的所有元素
    pub g: ECPoint,
}

/// 椭圆曲线的通用特征
/// 
/// 定义了椭圆曲线必须实现的基本运算，包括点运算和曲线验证。
pub trait EllipticCurve {
    /// 获取椭圆曲线的参数
    /// 
    /// # 返回值
    /// 
    /// 返回椭圆曲线的完整参数
    fn params() -> ECParams;
    
    /// 椭圆曲线点加法
    /// 
    /// 计算两个椭圆曲线点的和：P + Q
    /// 
    /// # 参数
    /// 
    /// * `p1` - 第一个点
    /// * `p2` - 第二个点
    /// 
    /// # 返回值
    /// 
    /// 返回两点之和，如果计算失败返回错误
    fn point_add(p1: &ECPoint, p2: &ECPoint) -> Result<ECPoint>;
    
    /// 椭圆曲线点倍乘
    /// 
    /// 计算点的二倍：2P = P + P
    /// 
    /// # 参数
    /// 
    /// * `point` - 要倍乘的点
    /// 
    /// # 返回值
    /// 
    /// 返回点的二倍，如果计算失败返回错误
    fn point_double(point: &ECPoint) -> Result<ECPoint>;
    
    /// 椭圆曲线标量乘法
    /// 
    /// 计算标量与点的乘积：k * P
    /// 
    /// # 参数
    /// 
    /// * `scalar` - 标量值
    /// * `point` - 椭圆曲线点
    /// 
    /// # 返回值
    /// 
    /// 返回标量乘法的结果，如果计算失败返回错误
    fn scalar_multiply(scalar: u64, point: &ECPoint) -> Result<ECPoint>;
    
    /// 验证点是否在椭圆曲线上
    /// 
    /// 检查点是否满足椭圆曲线方程 y² = x³ + ax + b (mod p)
    /// 
    /// # 参数
    /// 
    /// * `point` - 要验证的点
    /// 
    /// # 返回值
    /// 
    /// 如果点在曲线上返回 `true`，否则返回 `false`
    fn is_on_curve(point: &ECPoint) -> bool;
}

/// 椭圆曲线 Diffie-Hellman 密钥交换特征
/// 
/// 实现椭圆曲线上的 Diffie-Hellman 密钥交换协议，允许两方在不安全的
/// 通道上建立共享密钥。
pub trait ECDH {
    /// 生成 ECDH 密钥对
    /// 
    /// 生成一个随机私钥和对应的公钥。私钥是随机标量，
    /// 公钥是私钥与生成元的标量乘积。
    /// 
    /// # 返回值
    /// 
    /// 返回 (私钥, 公钥) 元组，如果生成失败返回错误
    fn generate_keypair() -> Result<(u64, ECPoint)>;
    
    /// 计算共享密钥
    /// 
    /// 使用自己的私钥和对方的公钥计算共享密钥。
    /// 共享密钥 = 私钥 * 对方公钥
    /// 
    /// # 参数
    /// 
    /// * `private_key` - 自己的私钥
    /// * `public_key` - 对方的公钥
    /// 
    /// # 返回值
    /// 
    /// 返回共享密钥点，如果计算失败返回错误
    fn compute_shared_secret(private_key: u64, public_key: &ECPoint) -> Result<ECPoint>;
}

/// 椭圆曲线数字签名算法特征
/// 
/// 实现椭圆曲线数字签名算法 (ECDSA)，提供消息签名和验证功能。
/// ECDSA 基于椭圆曲线离散对数问题的困难性。
pub trait ECDSA {
    /// 签名类型
    type Signature;
    
    /// 对消息哈希进行签名
    /// 
    /// 使用私钥对消息的哈希值进行签名。签名过程涉及随机数生成
    /// 和椭圆曲线运算。
    /// 
    /// # 参数
    /// 
    /// * `private_key` - 签名者的私钥
    /// * `message_hash` - 消息的哈希值
    /// 
    /// # 返回值
    /// 
    /// 返回数字签名，如果签名失败返回错误
    fn sign(private_key: u64, message_hash: u64) -> Result<Self::Signature>;
    
    /// 验证数字签名
    /// 
    /// 使用公钥验证消息哈希的数字签名是否有效。
    /// 
    /// # 参数
    /// 
    /// * `public_key` - 签名者的公钥
    /// * `message_hash` - 消息的哈希值
    /// * `signature` - 要验证的数字签名
    /// 
    /// # 返回值
    /// 
    /// 如果签名有效返回 `Ok(true)`，无效返回 `Ok(false)`，
    /// 验证过程出错返回 `Err`
    fn verify(public_key: &ECPoint, message_hash: u64, signature: &Self::Signature) -> Result<bool>;
}