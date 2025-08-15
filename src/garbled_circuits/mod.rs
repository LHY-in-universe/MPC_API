//! # 混淆电路模块 (Garbled Circuits)
//! 
//! 本模块实现了用于安全计算的混淆电路。混淆电路是一种密码学技术，
//! 允许两方在不泄露各自私有输入的情况下计算函数。
//! 
//! ## 核心概念
//! 
//! ### 混淆电路原理
//! - **电路表示**: 将计算表示为布尔电路（AND、OR、XOR、NOT 门）
//! - **线标签**: 每条线有两个随机标签，分别代表 0 和 1
//! - **门混淆**: 将真值表加密，隐藏门的功能
//! - **求值**: 使用输入标签逐门计算，得到输出标签
//! 
//! ### 安全保证
//! - **隐私性**: 输入值对对方保密
//! - **正确性**: 计算结果正确
//! - **一次性**: 每个混淆电路只能使用一次
//! 
//! ## 优化技术
//! 
//! - **Free XOR**: XOR 门无需混淆表，提高效率
//! - **Point-and-Permute**: 减少解密尝试次数
//! - **Row Reduction**: 减少混淆表大小
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::garbled_circuits::*;
//! 
//! // 创建简单的 AND 电路
//! let mut circuit = Circuit::new();
//! let input1 = circuit.add_input_wire();
//! let input2 = circuit.add_input_wire();
//! let output = circuit.add_and_gate(input1, input2);
//! circuit.set_output_wire(output);
//! 
//! // 混淆电路
//! let garbled = garble_circuit(&circuit)?;
//! 
//! // 求值
//! let inputs = vec![true, false]; // Alice: true, Bob: false
//! let result = evaluate_circuit(&garbled, &inputs)?;
//! ```

pub mod circuit;
pub mod gate;
pub mod wire;
pub mod garbler;
pub mod evaluator;
pub mod free_xor;

pub use circuit::*;
// Import from where they are actually defined
// Gate and GateType are both defined in circuit.rs but re-exported
pub use wire::*;
pub use garbler::*;
pub use evaluator::*;
pub use free_xor::*;

use crate::{MpcError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use rand::RngCore;

/// 线标签类型，128 位随机值
/// 
/// 每条线有两个标签，分别对应逻辑值 0 和 1。
/// 标签的随机性确保了混淆电路的安全性。
pub type Label = [u8; 16];

/// 线标识符类型
/// 
/// 用于唯一标识电路中的每条线。
pub type WireId = u32;

/// 门标识符类型
/// 
/// 用于唯一标识电路中的每个门。
pub type GateId = u32;

/// 门类型枚举
/// 
/// 定义了混淆电路中支持的所有门类型。每种门类型对应不同的布尔运算。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GateType {
    /// AND 门：输出 = 输入1 AND 输入2
    And,
    /// OR 门：输出 = 输入1 OR 输入2
    Or,
    /// XOR 门：输出 = 输入1 XOR 输入2（可使用 Free XOR 优化）
    Xor,
    /// NOT 门：输出 = NOT 输入
    Not,
    /// 输入门：电路的输入点
    Input,
    /// 输出门：电路的输出点
    Output,
}

/// 混淆门结构
/// 
/// 表示混淆电路中的一个门，包含门的类型、连接的线和混淆表。
/// 混淆表包含加密的真值表，用于在求值时计算输出标签。
#[derive(Debug, Clone)]
pub struct GarbledGate {
    /// 门的唯一标识符
    pub id: GateId,
    /// 门的类型（AND、OR、XOR 等）
    pub gate_type: GateType,
    /// 输入线的标识符列表
    pub input_wires: Vec<WireId>,
    /// 输出线的标识符
    pub output_wire: WireId,
    /// 混淆表，包含加密的输出标签（XOR 门可能为空）
    pub garbled_table: Option<Vec<Label>>,
}

/// 混淆电路结构
/// 
/// 表示完整的混淆电路，包含所有混淆门、输入输出线和线标签。
/// 这是混淆电路的核心数据结构。
#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    /// 电路中所有混淆门的列表
    pub gates: Vec<GarbledGate>,
    /// 输入线的标识符列表
    pub input_wires: Vec<WireId>,
    /// 输出线的标识符列表
    pub output_wires: Vec<WireId>,
    /// 线标签映射表：线ID -> (标签0, 标签1)
    /// 每条线有两个标签，分别对应逻辑值 0 和 1
    pub wire_labels: std::collections::HashMap<WireId, (Label, Label)>,
}

/// 将字节数据哈希为线标签
/// 
/// 使用 SHA-256 哈希函数将任意长度的字节数据转换为 128 位的线标签。
/// 这用于从种子生成确定性的标签。
/// 
/// # 参数
/// 
/// * `input` - 要哈希的输入字节数据
/// 
/// # 返回值
/// 
/// 返回 128 位的线标签
pub fn hash_to_label(input: &[u8]) -> Label {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut label = [0u8; 16];
    label.copy_from_slice(&result[..16]);
    label
}

/// 计算两个标签的异或
/// 
/// 对两个 128 位标签进行逐字节异或运算。这是 Free XOR 优化的核心操作，
/// 允许 XOR 门无需混淆表即可计算。
/// 
/// # 参数
/// 
/// * `a` - 第一个标签
/// * `b` - 第二个标签
/// 
/// # 返回值
/// 
/// 返回两个标签的异或结果
pub fn xor_labels(a: &Label, b: &Label) -> Label {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// 生成随机线标签
/// 
/// 使用提供的随机数生成器生成 128 位的随机标签。
/// 标签的随机性是混淆电路安全性的基础。
/// 
/// # 参数
/// 
/// * `rng` - 随机数生成器
/// 
/// # 返回值
/// 
/// 返回新生成的随机标签
pub fn generate_random_label<R: RngCore>(rng: &mut R) -> Label {
    let mut label = [0u8; 16];
    rng.fill_bytes(&mut label);
    label
}