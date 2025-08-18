//! # 同态加密模块 (Homomorphic Encryption)
//! 
//! 本模块实现了多种同态加密方案，支持在加密数据上直接进行计算。
//! 同态加密是一种特殊的加密技术，允许在不解密的情况下对密文进行运算。
//! 
//! ## 支持的加密方案
//! 
//! ### 部分同态加密
//! - **ElGamal**: 乘法同态加密，支持密文乘法运算
//! - **RSA**: 乘法同态加密，支持密文乘法和幂运算
//! - **Paillier**: 加法同态加密，支持密文加法和标量乘法
//! 
//! ### 全同态加密
//! - **BFV**: 全同态加密方案，支持任意深度的加法和乘法运算
//! - **BGV**: 全同态加密方案，适用于整数运算
//! 
//! ## 同态性质
//! 
//! - **加法同态**: Enc(a) + Enc(b) = Enc(a + b)
//! - **乘法同态**: Enc(a) × Enc(b) = Enc(a × b)
//! - **标量乘法**: k × Enc(a) = Enc(k × a)
//! 
//! ## 应用场景
//! 
//! - 隐私保护计算
//! - 云计算中的数据保护
//! - 安全多方计算
//! - 联邦学习
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::homomorphic_encryption::*;
//! 
//! // Paillier 加法同态加密
//! let (pk, sk) = PaillierScheme::keygen()?;
//! let c1 = PaillierScheme::encrypt(&pk, &42)?;
//! let c2 = PaillierScheme::encrypt(&pk, &58)?;
//! let c_sum = PaillierScheme::add_ciphertexts(&pk, &c1, &c2)?;
//! let result = PaillierScheme::decrypt(&sk, &c_sum)?; // 结果为 100
//! ```

pub mod elgamal;
pub mod rsa;
pub mod paillier;
pub mod bfv;
pub mod bgv;

pub use elgamal::*;
pub use rsa::*;
pub use paillier::*;
pub use bfv::*;
pub use bgv::*;

use crate::{MpcError, Result};
use serde::{Deserialize, Serialize};

/// 同态加密基础 trait
/// 
/// 定义了所有同态加密方案必须实现的基本操作：密钥生成、加密和解密。
/// 这是所有同态加密方案的基础接口。
pub trait HomomorphicEncryption {
    /// 明文空间类型
    type PlaintextSpace;
    /// 密文空间类型
    type CiphertextSpace;
    /// 公钥类型
    type PublicKey;
    /// 私钥类型
    type PrivateKey;
    
    /// 生成密钥对
    /// 
    /// 生成一对公私钥，用于加密和解密操作。
    /// 
    /// # 返回值
    /// 
    /// 返回包含公钥和私钥的元组
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)>;
    
    /// 加密明文
    /// 
    /// 使用公钥将明文加密为密文。
    /// 
    /// # 参数
    /// 
    /// * `pk` - 公钥
    /// * `plaintext` - 要加密的明文
    /// 
    /// # 返回值
    /// 
    /// 返回加密后的密文
    fn encrypt(pk: &Self::PublicKey, plaintext: &Self::PlaintextSpace) -> Result<Self::CiphertextSpace>;
    
    /// 解密密文
    /// 
    /// 使用私钥将密文解密为明文。
    /// 
    /// # 参数
    /// 
    /// * `sk` - 私钥
    /// * `ciphertext` - 要解密的密文
    /// 
    /// # 返回值
    /// 
    /// 返回解密后的明文
    fn decrypt(sk: &Self::PrivateKey, ciphertext: &Self::CiphertextSpace) -> Result<Self::PlaintextSpace>;
}

/// 加法同态加密 trait
/// 
/// 支持在密文上进行加法运算的同态加密方案。
/// 满足性质：Enc(a) + Enc(b) = Enc(a + b)
pub trait AdditivelyHomomorphic: HomomorphicEncryption {
    /// 密文加法
    /// 
    /// 计算两个密文的加法，结果等价于对应明文相加后的加密。
    /// 
    /// # 参数
    /// 
    /// * `pk` - 公钥
    /// * `c1` - 第一个密文
    /// * `c2` - 第二个密文
    /// 
    /// # 返回值
    /// 
    /// 返回两个密文相加的结果
    fn add_ciphertexts(
        pk: &Self::PublicKey,
        c1: &Self::CiphertextSpace,
        c2: &Self::CiphertextSpace,
    ) -> Result<Self::CiphertextSpace>;
    
    /// 标量乘法
    /// 
    /// 将密文与标量相乘，结果等价于明文与标量相乘后的加密。
    /// 
    /// # 参数
    /// 
    /// * `pk` - 公钥
    /// * `ciphertext` - 密文
    /// * `scalar` - 标量值
    /// 
    /// # 返回值
    /// 
    /// 返回密文与标量相乘的结果
    fn scalar_multiply(
        pk: &Self::PublicKey,
        ciphertext: &Self::CiphertextSpace,
        scalar: &Self::PlaintextSpace,
    ) -> Result<Self::CiphertextSpace>;
}

/// 乘法同态加密 trait
/// 
/// 支持在密文上进行乘法运算的同态加密方案。
/// 满足性质：Enc(a) × Enc(b) = Enc(a × b)
pub trait MultiplicativelyHomomorphic: HomomorphicEncryption {
    /// 密文乘法
    /// 
    /// 计算两个密文的乘法，结果等价于对应明文相乘后的加密。
    /// 
    /// # 参数
    /// 
    /// * `pk` - 公钥
    /// * `c1` - 第一个密文
    /// * `c2` - 第二个密文
    /// 
    /// # 返回值
    /// 
    /// 返回两个密文相乘的结果
    fn multiply_ciphertexts(
        pk: &Self::PublicKey,
        c1: &Self::CiphertextSpace,
        c2: &Self::CiphertextSpace,
    ) -> Result<Self::CiphertextSpace>;
    
    /// 密文幂运算
    /// 
    /// 计算密文的幂运算，结果等价于明文的幂运算后的加密。
    /// 
    /// # 参数
    /// 
    /// * `pk` - 公钥
    /// * `ciphertext` - 密文底数
    /// * `exponent` - 指数
    /// 
    /// # 返回值
    /// 
    /// 返回密文的幂运算结果
    fn power(
        pk: &Self::PublicKey,
        ciphertext: &Self::CiphertextSpace,
        exponent: u64,
    ) -> Result<Self::CiphertextSpace>;
}

/// 全同态加密 trait
/// 
/// 支持任意深度加法和乘法运算的同态加密方案。
/// 全同态加密是同态加密的最高形式，可以在密文上执行任意计算。
pub trait FullyHomomorphic: AdditivelyHomomorphic + MultiplicativelyHomomorphic {
    /// 电路求值
    /// 
    /// 在密文上执行任意布尔或算术电路，支持复杂的计算逻辑。
    /// 这是全同态加密的核心功能。
    /// 
    /// # 参数
    /// 
    /// * `pk` - 公钥
    /// * `circuit` - 要执行的电路函数
    /// * `inputs` - 输入密文数组
    /// 
    /// # 返回值
    /// 
    /// 返回电路计算的密文结果
    fn evaluate_circuit<F>(
        pk: &Self::PublicKey,
        circuit: F,
        inputs: &[Self::CiphertextSpace],
    ) -> Result<Self::CiphertextSpace>
    where
        F: Fn(&[Self::CiphertextSpace]) -> Result<Self::CiphertextSpace>;
}

