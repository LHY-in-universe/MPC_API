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

#[cfg(test)]
mod tests {
    //! 椭圆曲线密码学测试
    //! 
    //! 本文件包含对MPC API椭圆曲线模块的全面测试，覆盖以下算法和操作：
    //! - ECDH (Elliptic Curve Diffie-Hellman) - 椭圆曲线迪菲-赫尔曼密钥交换
    //! - ECDSA (Elliptic Curve Digital Signature Algorithm) - 椭圆曲线数字签名算法
    //! - 椭圆曲线点操作 (Point Operations) - 点加法、点乘法、点否定等
    //! - Curve25519 - 高性能椭圆曲线实现
    //! 
    //! 椭圆曲线密码学提供了相同安全级别下更短的密钥长度，广泛应用于现代密码学协议。

    use super::*;
    use crate::elliptic_curve::{ECPoint, ECDH, ECDSA, EllipticCurve};
    use crate::elliptic_curve::ecdh::*;
    use crate::elliptic_curve::ecdsa::*;
    use crate::elliptic_curve::point::*;
    use crate::secret_sharing::{field_sub, FIELD_PRIME};
    use rand::{thread_rng, Rng};

    // ===== ECDH Tests =====
    // ECDH是一种密钥协商协议，允许两方在不安全信道上安全地交换密钥

    /// 测试ECDH密钥对生成功能
    /// 
    /// 目的：验证ECDH能够生成有效的私钥和公钥对
    /// 预期：私钥应为正数，公钥应为有效的椭圆曲线点
    #[test]
    fn test_ecdh_keypair_generation() {
        let result = ECDiffieHellman::generate_keypair();
        assert!(result.is_ok()); // 密钥生成应该成功
        
        let (private_key, public_key) = result.unwrap();
        assert!(private_key > 0); // 私钥应为正数
        assert!(!public_key.is_infinity()); // 公钥不应该是无穷远点
    }

    /// 测试ECDH共享密钥计算功能
    /// 
    /// 目的：验证ECDH共享密钥协议的正确性，即Alice和Bob计算出相同的共享密钥
    /// 预期：双方使用对方公钥和自己私钥计算出的共享密钥应该相同
    #[test]
    fn test_ecdh_shared_secret() {
        // 为Alice和Bob生成密钥对
        let (alice_private, alice_public) = ECDiffieHellman::generate_keypair().unwrap();
        let (bob_private, bob_public) = ECDiffieHellman::generate_keypair().unwrap();
        
        // 计算共享密钥：Alice使用Bob的公钥，Bob使用Alice的公钥
        let alice_shared = ECDiffieHellman::compute_shared_secret(alice_private, &bob_public).unwrap();
        let bob_shared = ECDiffieHellman::compute_shared_secret(bob_private, &alice_public).unwrap();
        
        // 共享密钥应该相同，这是ECDH协议的核心特性
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_ecdh_key_exchange() {
        let mut rng = thread_rng();
        let alice_private = rng.gen_range(1..1000);
        let bob_private = rng.gen_range(1..1000);
        
        let result = ECDiffieHellman::perform_key_exchange(alice_private, bob_private);
        assert!(result.is_ok());
        
        let (alice_public, bob_public, shared_secret) = result.unwrap();
        
        assert!(!alice_public.is_infinity());
        assert!(!bob_public.is_infinity());
        assert!(!shared_secret.is_infinity());
    }

    /// 测试ECDH密钥派生功能
    /// 
    /// 目的：验证ECDH能够从共享点派生出确定性的对称密钥
    /// 预期：相同输入应产生相同的32字节密钥，确保密钥派生的一致性
    #[test]
    fn test_key_derivation() {
        let shared_point = ECPoint::new(123, 456);
        // 从共享椭圆曲线点派生对称密钥
        let key = ECDiffieHellman::derive_key_from_shared_secret(&shared_point);
        assert!(key.is_ok()); // 密钥派生应该成功
        
        let derived_key = key.unwrap();
        assert_eq!(derived_key.len(), 32); // 派生的密钥应该是32字节（256位）
        
        // 相同输入应该产生相同的密钥（确保确定性）
        let key2 = ECDiffieHellman::derive_key_from_shared_secret(&shared_point).unwrap();
        assert_eq!(derived_key, key2);
    }

    /// 测试完整的ECDH密钥协商协议
    /// 
    /// 目的：验证ECDH密钥协商协议的完整流程，包括密钥生成、交换和派生
    /// 预期：Alice和Bob应该获得相同的32字节共享密钥
    #[test]
    fn test_key_agreement_protocol() {
        // 执行完整的密钥协商协议（模拟Alice和Bob的交互）
        let result = ECDiffieHellman::key_agreement_protocol();
        assert!(result.is_ok()); // 协议执行应该成功
        
        let (alice_key, bob_key) = result.unwrap();
        assert_eq!(alice_key.len(), 32);  // Alice的密钥应该是32字节
        assert_eq!(bob_key.len(), 32);    // Bob的密钥应该是32字节
        assert_eq!(alice_key, bob_key);   // 双方应该获得相同的共享密钥
    }

    /// 测试Curve25519椭圆曲线的密钥对生成
    /// 
    /// 目的：验证Curve25519高性能椭圆曲线的密钥对生成功能
    /// 预期：应该能成功生成有效的私钥和公钥对
    #[test]
    fn test_curve25519_keypair() {
        // 使用Curve25519椭圆曲线生成密钥对
        let result = Curve25519ECDH::generate_keypair_curve25519();
        assert!(result.is_ok()); // 密钥生成应该成功
        
        let (private_key, public_key) = result.unwrap();
        // Curve25519中私钥和公钥都表示为u64，应该为正数
        assert!(private_key > 0);
        assert!(public_key > 0);
    }

    /// 测试Curve25519椭圆曲线的共享密钥计算
    /// 
    /// 目的：验证Curve25519椭圆曲线ECDH协议的正确性和一致性
    /// 预期：Alice和Bob使用对方公钥计算的共享密钥应该相同
    #[test]
    fn test_curve25519_shared_secret() {
        // 为Alice和Bob生成Curve25519密钥对
        let (alice_private, alice_public) = Curve25519ECDH::generate_keypair_curve25519().unwrap();
        let (bob_private, bob_public) = Curve25519ECDH::generate_keypair_curve25519().unwrap();
        
        // Alice使用自己的私钥和Bob的公钥计算共享密钥
        let alice_shared = Curve25519ECDH::compute_shared_secret_curve25519(alice_private, bob_public).unwrap();
        // Bob使用自己的私钥和Alice的公钥计算共享密钥
        let bob_shared = Curve25519ECDH::compute_shared_secret_curve25519(bob_private, alice_public).unwrap();
        
        // 两个共享密钥应该相同，这是ECDH协议的核心特性
        assert_eq!(alice_shared, bob_shared);
    }

    // ===== ECDSA Tests =====
    // ECDSA是一种数字签名算法，用于验证消息的真实性和完整性

    /// 测试ECDSA数字签名的创建和验证
    /// 
    /// 目的：验证ECDSA能够正确生成数字签名并通过验证
    /// 预期：签名的r和s值应为正数，使用相同公钥和消息的验证应该成功
    #[test]
    fn test_ecdsa_signature_creation() {
        let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
        let message_hash = 12345u64;
        
        // 使用私钥对消息哈希进行签名
        let signature = ECDigitalSignature::sign(private_key, message_hash).unwrap();
        
        // ECDSA签名由(r,s)对组成，都应该为正数
        assert!(signature.r > 0);
        assert!(signature.s > 0);
        
        // 使用公钥验证签名的有效性
        let verification = ECDigitalSignature::verify(&public_key, message_hash, &signature).unwrap();
        assert!(verification); // 验证应该成功
    }

    /// 测试ECDSA对完整消息的签名功能
    /// 
    /// 目的：验证ECDSA能够对完整消息进行签名（包括哈希计算）
    /// 预期：消息签名和验证应该成功
    #[test]
    fn test_ecdsa_message_signing() {
        let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
        let message = b"Hello, ECDSA!";
        
        // 对完整消息进行签名（内部先计算SHA-256哈希）
        let signature = ECDigitalSignature::sign_message(message, private_key).unwrap();
        // 验证消息签名的有效性
        let verification = ECDigitalSignature::verify_message(message, &public_key, &signature).unwrap();
        
        // 验证应该成功
        assert!(verification);
    }

    /// 测试ECDSA对无效签名的检测能力
    /// 
    /// 目的：验证ECDSA能够正确拒绝伪造或无效的数字签名
    /// 预期：使用无效签名进行验证时应该失败
    #[test]
    fn test_ecdsa_invalid_signature() {
        let (_, public_key) = ECDigitalSignature::generate_keypair().unwrap();
        let message_hash = 12345u64;
        
        // 创建一个无效的签名（r=1, s=1通常不是有效的ECDSA签名）
        let invalid_signature = ECDSASignature { r: 1, s: 1 };
        
        // 使用无效签名进行验证
        let verification = ECDigitalSignature::verify(&public_key, message_hash, &invalid_signature).unwrap();
        assert!(!verification); // 验证应该失败，确保安全性
    }

    /// 测试ECDSA消息完整性检测能力
    /// 
    /// 目的：验证ECDSA能够检测到消息被篡改，确保签名与特定消息绑定
    /// 预期：签名只能验证对应的原始消息，不能验证其他消息
    #[test]
    fn test_ecdsa_different_message() {
        let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
        let message1 = b"Message 1";
        let message2 = b"Message 2";
        
        // 为消息1生成签名
        let signature1 = ECDigitalSignature::sign_message(message1, private_key).unwrap();
        
        // 消息1的签名不应该能验证消息2（确保消息绑定性）
        let verification = ECDigitalSignature::verify_message(message2, &public_key, &signature1).unwrap();
        assert!(!verification); // 验证应该失败
        
        // 但应该能够验证原始消息1
        let verification = ECDigitalSignature::verify_message(message1, &public_key, &signature1).unwrap();
        assert!(verification); // 验证应该成功
    }

    /// 测试ECDSA密钥对匹配验证
    /// 
    /// 目的：验证ECDSA能够检测到使用错误公钥进行的验证尝试
    /// 预期：使用不匹配的公钥验证签名时应该失败
    #[test]
    fn test_ecdsa_wrong_public_key() {
        let (private_key1, _) = ECDigitalSignature::generate_keypair().unwrap();
        let (_, public_key2) = ECDigitalSignature::generate_keypair().unwrap();
        let message_hash = 12345u64;
        
        // 使用私钥1生成签名
        let signature = ECDigitalSignature::sign(private_key1, message_hash).unwrap();
        
        // 使用不匹配的公钥2验证私钥1的签名应该失败
        let verification = ECDigitalSignature::verify(&public_key2, message_hash, &signature).unwrap();
        assert!(!verification); // 验证应该失败，确保密钥对匹配性
    }

    // ===== EC Point Tests =====
    // 椭圆曲线点操作是椭圆曲线密码学的数学基础，包括点加法、点乘法等运算

    /// 测试椭圆曲线无穷远点的处理
    /// 
    /// 目的：验证椭圆曲线点的无穷远点特性，这是加法群的单位元
    /// 预期：无穷远点应该被正确识别，普通点不应该被识别为无穷远点
    #[test]
    fn test_point_infinity() {
        let inf = ECPoint::infinity();
        assert!(inf.is_infinity()); // 无穷远点应该被正确识别
        
        let p = ECPoint::new(1, 2);
        assert!(!p.is_infinity()); // 普通点不应该被识别为无穷远点
    }

    /// 测试椭圆曲线点的否定操作
    /// 
    /// 目的：验证椭圆曲线点的否定运算，即-P = (x, -y)
    /// 预期：否定点的x坐标不变，y坐标变为其在有限域中的加法逆元
    #[test]
    fn test_point_negate() {
        let p = ECPoint::new(5, 10);
        let neg_p = p.negate();
        
        // 否定点的x坐标保持不变
        assert_eq!(neg_p.x, p.x);
        // y坐标变为其在有限域中的加法逆元
        assert_eq!(neg_p.y, field_sub(0, p.y));
    }

    #[test]
    fn test_point_addition_with_infinity() {
        let p = ECPoint::new(3, 4);
        let inf = ECPoint::infinity();
        
        let result1 = SimpleEC::point_add(&p, &inf).unwrap();
        let result2 = SimpleEC::point_add(&inf, &p).unwrap();
        
        assert_eq!(result1, p);
        assert_eq!(result2, p);
    }

    /// 测试椭圆曲线标量乘法操作
    /// 
    /// 目的：验证椭圆曲线标量乘法的正确性，这是ECC的核心操作
    /// 预期：0*P=O，1*P=P，2*P=P+P等基本性质应该成立
    #[test]
    fn test_scalar_multiplication() {
        let p = ECPoint::new(2, 3);
        
        // 0 * P = O (无穷远点) - 标量乘法的零元性质
        let result = SimpleEC::scalar_multiply(0, &p).unwrap();
        assert!(result.is_infinity());
        
        // 1 * P = P - 标量乘法的单位元性质
        let result = SimpleEC::scalar_multiply(1, &p).unwrap();
        assert_eq!(result, p);
        
        // 2 * P = P + P - 标量乘法与点加法的一致性
        let doubled = SimpleEC::point_double(&p).unwrap();
        let result = SimpleEC::scalar_multiply(2, &p).unwrap();
        assert_eq!(result, doubled);
    }

    #[test]
    fn test_ec_params() {
        let params = SimpleEC::params();
        
        // Test that we can access the parameters
        assert_eq!(params.p, FIELD_PRIME);
        // A and B are private constants, so we just test they're accessible through params
        #[allow(unused_comparisons)]
        {
            assert!(params.a >= 0);
            assert!(params.b >= 0);
        }
    }

    #[test]
    fn test_point_doubling() {
        let p = ECPoint::new(2, 3);
        
        // Verify that 2P = P + P
        let doubled = SimpleEC::point_double(&p).unwrap();
        let added = SimpleEC::point_add(&p, &p).unwrap();
        
        assert_eq!(doubled, added);
    }
}