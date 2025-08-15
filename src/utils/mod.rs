//! # 工具模块 (Utility Functions)
//! 
//! 本模块提供了 MPC API 库中使用的各种工具函数和辅助功能。
//! 这些工具函数为密码学协议的实现提供了基础支持。
//! 
//! ## 子模块
//! 
//! - **数学工具 (math)**: 提供数学运算、有限域操作、多项式计算等功能
//! - **随机数生成 (random)**: 提供密码学安全的随机数生成功能
//! - **序列化工具 (serialization)**: 提供数据序列化和反序列化功能
//! 
//! ## 主要功能
//! 
//! ### 数学运算
//! - 有限域算术运算
//! - 模运算和模逆运算
//! - 多项式插值和求值
//! - 矩阵运算
//! 
//! ### 随机数生成
//! - 密码学安全的随机数生成器
//! - 随机字节序列生成
//! - 随机有限域元素生成
//! 
//! ### 序列化支持
//! - 结构体的二进制序列化
//! - 网络传输格式转换
//! - 跨平台兼容性支持
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::utils::*;
//! 
//! // 生成随机字节
//! let random_bytes = generate_random_bytes(32)?;
//! 
//! // 有限域运算
//! let result = field_multiply(a, b, prime);
//! 
//! // 序列化数据
//! let serialized = serialize_to_bytes(&data)?;
//! ```

pub mod math;
pub mod random;
pub mod serialization;

pub use math::*;
pub use random::*;
pub use serialization::*;