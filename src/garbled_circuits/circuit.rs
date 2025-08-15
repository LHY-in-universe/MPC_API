//! # 电路表示和基本操作
//! 
//! 本模块定义了布尔电路的表示方法和基本操作。电路由门和线组成，
//! 是混淆电路的基础结构。支持构建各种逻辑电路，包括加法器、多路选择器等。

use super::*;
// use std::collections::HashMap; // Unused import

/// 布尔电路结构
/// 
/// 表示一个完整的布尔电路，包含所有门、输入线、输出线和线计数器。
/// 这是构建混淆电路的基础数据结构。
#[derive(Debug, Clone)]
pub struct Circuit {
    /// 电路中所有门的列表
    pub gates: Vec<Gate>,
    /// 输入线的标识符列表
    pub input_wires: Vec<WireId>,
    /// 输出线的标识符列表
    pub output_wires: Vec<WireId>,
    /// 线计数器，用于分配新的线ID
    pub wire_count: u32,
}

/// 逻辑门结构
/// 
/// 表示电路中的一个逻辑门，包含门的类型、输入线和输出线。
/// 这是电路的基本计算单元。
#[derive(Debug, Clone)]
pub struct Gate {
    /// 门的唯一标识符
    pub id: GateId,
    /// 门的类型（AND、OR、XOR、NOT）
    pub gate_type: GateType,
    /// 输入线的标识符列表
    pub input_wires: Vec<WireId>,
    /// 输出线的标识符
    pub output_wire: WireId,
}

impl Circuit {
    /// 创建新的空电路
    /// 
    /// 初始化一个不包含任何门或线的空电路。
    /// 
    /// # 返回值
    /// 
    /// 返回新创建的空电路实例
    pub fn new() -> Self {
        Self {
            gates: Vec::new(),
            input_wires: Vec::new(),
            output_wires: Vec::new(),
            wire_count: 0,
        }
    }
    
    /// 添加输入线
    /// 
    /// 在电路中添加一条新的输入线，并返回其标识符。
    /// 输入线用于接收外部输入值。
    /// 
    /// # 返回值
    /// 
    /// 返回新添加的输入线的标识符
    pub fn add_input_wire(&mut self) -> WireId {
        let wire_id = self.wire_count;
        self.wire_count += 1;
        self.input_wires.push(wire_id);
        wire_id
    }
    
    /// 添加输出线
    /// 
    /// 将指定的线标记为输出线。输出线用于提供电路的计算结果。
    /// 
    /// # 参数
    /// 
    /// * `wire_id` - 要标记为输出的线标识符
    pub fn add_output_wire(&mut self, wire_id: WireId) {
        self.output_wires.push(wire_id);
    }
    
    /// 添加逻辑门
    /// 
    /// 在电路中添加一个新的逻辑门，并自动分配输出线。
    /// 这是构建电路的核心方法。
    /// 
    /// # 参数
    /// 
    /// * `gate_type` - 门的类型（AND、OR、XOR、NOT）
    /// * `input_wires` - 输入线的标识符列表
    /// 
    /// # 返回值
    /// 
    /// 返回新创建门的输出线标识符
    pub fn add_gate(&mut self, gate_type: GateType, input_wires: Vec<WireId>) -> WireId {
        let gate_id = self.gates.len() as GateId;
        let output_wire = self.wire_count;
        self.wire_count += 1;
        
        let gate = Gate {
            id: gate_id,
            gate_type,
            input_wires,
            output_wire,
        };
        
        self.gates.push(gate);
        output_wire
    }
    
    /// 添加 AND 门
    /// 
    /// 创建一个 AND 门，输出 = wire1 AND wire2。
    /// 
    /// # 参数
    /// 
    /// * `wire1` - 第一个输入线
    /// * `wire2` - 第二个输入线
    /// 
    /// # 返回值
    /// 
    /// 返回 AND 门的输出线标识符
    pub fn and_gate(&mut self, wire1: WireId, wire2: WireId) -> WireId {
        self.add_gate(GateType::And, vec![wire1, wire2])
    }
    
    /// 添加 OR 门
    /// 
    /// 创建一个 OR 门，输出 = wire1 OR wire2。
    /// 
    /// # 参数
    /// 
    /// * `wire1` - 第一个输入线
    /// * `wire2` - 第二个输入线
    /// 
    /// # 返回值
    /// 
    /// 返回 OR 门的输出线标识符
    pub fn or_gate(&mut self, wire1: WireId, wire2: WireId) -> WireId {
        self.add_gate(GateType::Or, vec![wire1, wire2])
    }
    
    /// 添加 XOR 门
    /// 
    /// 创建一个 XOR 门，输出 = wire1 XOR wire2。
    /// XOR 门在混淆电路中可以使用 Free XOR 优化。
    /// 
    /// # 参数
    /// 
    /// * `wire1` - 第一个输入线
    /// * `wire2` - 第二个输入线
    /// 
    /// # 返回值
    /// 
    /// 返回 XOR 门的输出线标识符
    pub fn xor_gate(&mut self, wire1: WireId, wire2: WireId) -> WireId {
        self.add_gate(GateType::Xor, vec![wire1, wire2])
    }
    
    /// 添加 NOT 门
    /// 
    /// 创建一个 NOT 门，输出 = NOT wire。
    /// 
    /// # 参数
    /// 
    /// * `wire` - 输入线
    /// 
    /// # 返回值
    /// 
    /// 返回 NOT 门的输出线标识符
    pub fn not_gate(&mut self, wire: WireId) -> WireId {
        self.add_gate(GateType::Not, vec![wire])
    }
    
    /// 创建加法器电路
    /// 
    /// 构建一个 n 位二进制加法器电路，可以计算两个 n 位数的和。
    /// 使用全加器链实现，支持进位传播。
    /// 
    /// # 参数
    /// 
    /// * `num_bits` - 加法器的位数
    /// 
    /// # 返回值
    /// 
    /// 返回构建好的加法器电路
    pub fn create_adder(num_bits: usize) -> Self {
        let mut circuit = Self::new();
        
        // Input wires for two numbers
        let mut a_wires = Vec::new();
        let mut b_wires = Vec::new();
        
        for _ in 0..num_bits {
            a_wires.push(circuit.add_input_wire());
            b_wires.push(circuit.add_input_wire());
        }
        
        let mut sum_wires = Vec::new();
        let mut carry = None;
        
        // 为每一位构建全加器
        for i in 0..num_bits {
            let (sum, new_carry) = if i == 0 {
                // 最低位使用半加器
                let sum = circuit.xor_gate(a_wires[i], b_wires[i]);
                let carry = circuit.and_gate(a_wires[i], b_wires[i]);
                (sum, Some(carry))
            } else {
                // 其他位使用全加器
                let temp_sum = circuit.xor_gate(a_wires[i], b_wires[i]);
                let sum = circuit.xor_gate(temp_sum, carry.unwrap());
                
                let temp_carry1 = circuit.and_gate(a_wires[i], b_wires[i]);
                let temp_carry2 = circuit.and_gate(temp_sum, carry.unwrap());
                let new_carry = circuit.or_gate(temp_carry1, temp_carry2);
                
                (sum, Some(new_carry))
            };
            
            sum_wires.push(sum);
            circuit.add_output_wire(sum);
            carry = new_carry;
        }
        
        // 添加最终进位作为输出
        if let Some(carry_wire) = carry {
            circuit.add_output_wire(carry_wire);
        }
        
        circuit
    }
    
    /// 创建多路选择器电路
    /// 
    /// 构建一个 n 位多路选择器电路，根据选择信号选择两个输入中的一个。
    /// 当选择信号为 0 时输出 input_a，为 1 时输出 input_b。
    /// 
    /// # 参数
    /// 
    /// * `num_bits` - 数据输入的位数
    /// 
    /// # 返回值
    /// 
    /// 返回构建好的多路选择器电路
    pub fn create_mux(num_bits: usize) -> Self {
        let mut circuit = Self::new();
        
        // 输入线：选择信号 + 两个数据输入
        let selector = circuit.add_input_wire();
        let mut input_a = Vec::new();
        let mut input_b = Vec::new();
        
        for _ in 0..num_bits {
            input_a.push(circuit.add_input_wire());
            input_b.push(circuit.add_input_wire());
        }
        
        // 对每一位：输出 = (选择信号 AND input_b) OR (!选择信号 AND input_a)
        for i in 0..num_bits {
            let not_selector = circuit.not_gate(selector);
            let path_a = circuit.and_gate(not_selector, input_a[i]);
            let path_b = circuit.and_gate(selector, input_b[i]);
            let output = circuit.or_gate(path_a, path_b);
            circuit.add_output_wire(output);
        }
        
        circuit
    }
}

/// 为 Circuit 实现 Default trait
/// 
/// 提供默认的电路创建方法，等同于调用 `Circuit::new()`。
impl Default for Circuit {
    fn default() -> Self {
        Self::new()
    }
}

// 测试代码已移至 tests/garbled_circuits_tests.rs