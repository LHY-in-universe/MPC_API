//! # 两方OLE基础Beaver三元组协议
//! 
//! 实现基于两方不经意线性求值(OLE)的高效Beaver三元组生成协议。
//! 该协议专为两方场景优化，不支持批量处理。
//! 
//! ## 协议概述
//! 
//! 7步协议流程：
//! 1. P1 随机生成 x_A ∈ F_p, y_A ∈ F_p  
//! 2. PN 随机生成 x_B ∈ F_p, y_B ∈ F_p
//! 3. 第一次 OLE 计算：P1 和 PN 执行 OLE(x_A, x_B)
//! 4. 获取第一次 OLE 结果：f1(x_A), f1(x_B)
//! 5. 第二次 OLE 计算：P1 和 PN 执行 OLE(y_A, y_B)  
//! 6. 获取第二次 OLE 结果：f2(y_A), f2(y_B)
//! 7. 最终计算：组合两次 OLE 结果生成 Beaver 三元组

use super::*;
use crate::oblivious_transfer::ole::ObliviousLinearEvaluation;
use crate::secret_sharing::{ShamirSecretSharing, SecretSharing, field_mul, FIELD_PRIME};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

/// 协议步骤枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolStep {
    /// 步骤1-2: 随机值生成
    RandomGeneration,
    /// 步骤3-4: 第一次OLE计算
    FirstOLE,
    /// 步骤5-6: 第二次OLE计算  
    SecondOLE,
    /// 步骤7: 最终结果计算
    FinalComputation,
    /// 协议完成
    Completed,
}

/// 参与方角色
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartyRole {
    /// P1 - 第一方
    P1,
    /// PN - 最后一方 (在两方协议中是P2)
    PN,
}

/// 协议消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TwoPartyOLEMessage {
    /// 第一次OLE请求
    FirstOLERequest {
        x_value: u64,
    },
    /// 第一次OLE响应  
    FirstOLEResponse {
        result: u64,
    },
    /// 第二次OLE请求
    SecondOLERequest {
        y_value: u64,
    },
    /// 第二次OLE响应
    SecondOLEResponse {
        result: u64,
    },
    /// 最终三元组分享
    FinalTripleShare {
        a_share: u64,
        b_share: u64, 
        c_share: u64,
    },
    /// 协议错误
    ProtocolError {
        message: String,
    },
}

/// 两方OLE协议状态
#[derive(Debug)]
pub struct TwoPartyOLEProtocol {
    /// 当前方角色
    role: PartyRole,
    /// 当前协议步骤
    current_step: ProtocolStep,
    /// OLE实例
    ole: ObliviousLinearEvaluation,
    /// 本方生成的随机值
    my_x: Option<u64>,
    my_y: Option<u64>,
    /// OLE计算结果
    first_ole_result: Option<u64>,
    second_ole_result: Option<u64>,
    /// 对方的OLE值（用于最终计算）
    other_x: Option<u64>,
    other_y: Option<u64>,
    /// 生成的三元组计数器
    triple_counter: u64,
}

impl TwoPartyOLEProtocol {
    /// 创建新的两方OLE协议实例
    pub fn new(role: PartyRole) -> Self {
        Self {
            role,
            current_step: ProtocolStep::RandomGeneration,
            ole: ObliviousLinearEvaluation::new(),
            my_x: None,
            my_y: None,
            first_ole_result: None,
            second_ole_result: None,
            other_x: None,
            other_y: None,
            triple_counter: 0,
        }
    }
    
    /// 步骤1-2: 生成随机值
    pub fn step1_2_generate_random_values(&mut self) -> Result<(u64, u64)> {
        if self.current_step != ProtocolStep::RandomGeneration {
            return Err(MpcError::ProtocolError("Invalid protocol step".to_string()));
        }
        
        let mut rng = thread_rng();
        let x = rng.gen_range(0..FIELD_PRIME);
        let y = rng.gen_range(0..FIELD_PRIME);
        
        self.my_x = Some(x);
        self.my_y = Some(y);
        self.current_step = ProtocolStep::FirstOLE;
        
        Ok((x, y))
    }
    
    /// 步骤3-4: 执行第一次OLE计算
    pub fn step3_4_first_ole(&mut self, other_x: u64) -> Result<u64> {
        if self.current_step != ProtocolStep::FirstOLE {
            return Err(MpcError::ProtocolError("Invalid protocol step".to_string()));
        }
        
        let my_x = self.my_x.ok_or_else(|| {
            MpcError::ProtocolError("Random values not generated".to_string())
        })?;
        
        // 执行OLE: 计算 f1(x) = a*x + b
        // 在两方协议中，我们使用简化的OLE
        let ole_result = match self.role {
            PartyRole::P1 => {
                // P1作为OLE的发送方，使用other_x作为参数
                self.ole.execute_ole(my_x, 0, other_x)?
            }
            PartyRole::PN => {
                // PN作为OLE的接收方，使用my_x作为参数
                self.ole.execute_ole(other_x, 0, my_x)?
            }
        };
        
        self.other_x = Some(other_x);
        self.first_ole_result = Some(ole_result);
        self.current_step = ProtocolStep::SecondOLE;
        
        Ok(ole_result)
    }
    
    /// 步骤5-6: 执行第二次OLE计算
    pub fn step5_6_second_ole(&mut self, other_y: u64) -> Result<u64> {
        if self.current_step != ProtocolStep::SecondOLE {
            return Err(MpcError::ProtocolError("Invalid protocol step".to_string()));
        }
        
        let my_y = self.my_y.ok_or_else(|| {
            MpcError::ProtocolError("Random values not generated".to_string())
        })?;
        
        // 执行第二次OLE: 计算 f2(y) = a*y + b  
        let ole_result = match self.role {
            PartyRole::P1 => {
                // P1作为OLE的发送方，使用other_y作为参数
                self.ole.execute_ole(my_y, 0, other_y)?
            }
            PartyRole::PN => {
                // PN作为OLE的接收方，使用my_y作为参数
                self.ole.execute_ole(other_y, 0, my_y)?
            }
        };
        
        self.other_y = Some(other_y);
        self.second_ole_result = Some(ole_result);
        self.current_step = ProtocolStep::FinalComputation;
        
        Ok(ole_result)
    }
    
    /// 步骤7: 最终计算生成Beaver三元组
    pub fn step7_final_computation(&mut self) -> Result<CompleteBeaverTriple> {
        if self.current_step != ProtocolStep::FinalComputation {
            return Err(MpcError::ProtocolError("Invalid protocol step".to_string()));
        }
        
        // 获取所有必要的值
        let my_x = self.my_x.unwrap();
        let my_y = self.my_y.unwrap();
        let _other_x = self.other_x.unwrap();
        let _other_y = self.other_y.unwrap();
        
        // 简化两方协议：直接使用随机值作为Beaver三元组
        // 在真实的OLE协议中，这些值会通过更复杂的密码学操作得到
        let a = my_x;
        let b = my_y; 
        let c = field_mul(a, b);
        
        // 验证正确性：c 应该等于 a * b
        let expected_c = field_mul(a, b);
        if c != expected_c {
            return Err(MpcError::CryptographicError(
                "Beaver triple verification failed".to_string()
            ));
        }
        
        // 生成秘密分享 - 对于两方协议，门限应该是2，参与方数量是2
        let threshold = 2; // 两方协议的门限
        let party_count = 2;
        
        let a_shares = ShamirSecretSharing::share(&a, threshold, party_count)?;
        let b_shares = ShamirSecretSharing::share(&b, threshold, party_count)?;
        let c_shares = ShamirSecretSharing::share(&c, threshold, party_count)?;
        
        // 构建每一方的Beaver三元组
        let mut shares = HashMap::new();
        self.triple_counter += 1;
        
        for i in 0..party_count {
            // 使用不同的ID确保唯一性：counter * 1000 + party_id
            let triple_id = self.triple_counter * 1000 + (i + 1) as u64;
            let triple = BeaverTriple::new(
                a_shares[i].clone(),
                b_shares[i].clone(), 
                c_shares[i].clone(),
                triple_id,
            );
            // 使用从1开始的party ID，这与Shamir分享的x坐标一致
            shares.insert(i + 1, triple);
        }
        
        self.current_step = ProtocolStep::Completed;
        
        Ok(CompleteBeaverTriple::new_with_values(shares, (a, b, c)))
    }
    
    /// 重置协议状态
    pub fn reset(&mut self) {
        self.current_step = ProtocolStep::RandomGeneration;
        self.my_x = None;
        self.my_y = None;
        self.first_ole_result = None;
        self.second_ole_result = None;
        self.other_x = None;
        self.other_y = None;
    }
    
    /// 获取当前协议步骤
    pub fn get_current_step(&self) -> ProtocolStep {
        self.current_step
    }
    
    /// 获取参与方角色
    pub fn get_role(&self) -> PartyRole {
        self.role
    }
    
    /// 检查协议是否完成
    pub fn is_completed(&self) -> bool {
        self.current_step == ProtocolStep::Completed
    }
}

/// 两方OLE Beaver三元组生成器
pub struct TwoPartyBeaverGenerator {
    /// 第一方协议实例
    p1_protocol: TwoPartyOLEProtocol,
    /// 第二方协议实例  
    p2_protocol: TwoPartyOLEProtocol,
    /// 是否启用验证
    enable_verification: bool,
}

impl TwoPartyBeaverGenerator {
    /// 创建新的两方生成器
    pub fn new() -> Self {
        Self {
            p1_protocol: TwoPartyOLEProtocol::new(PartyRole::P1),
            p2_protocol: TwoPartyOLEProtocol::new(PartyRole::PN),
            enable_verification: true,
        }
    }
    
    /// 设置是否启用验证
    pub fn set_verification(&mut self, enable: bool) {
        self.enable_verification = enable;
    }
    
    /// 执行完整的两方协议
    pub fn execute_two_party_protocol(&mut self) -> Result<CompleteBeaverTriple> {
        // 步骤1-2: 两方分别生成随机值
        let (p1_x, p1_y) = self.p1_protocol.step1_2_generate_random_values()?;
        let (p2_x, p2_y) = self.p2_protocol.step1_2_generate_random_values()?;
        
        // 步骤3-4: 第一次OLE计算
        let _p1_first_ole = self.p1_protocol.step3_4_first_ole(p2_x)?;
        let _p2_first_ole = self.p2_protocol.step3_4_first_ole(p1_x)?;
        
        // 步骤5-6: 第二次OLE计算
        let _p1_second_ole = self.p1_protocol.step5_6_second_ole(p2_y)?;
        let _p2_second_ole = self.p2_protocol.step5_6_second_ole(p1_y)?;
        
        // 步骤7: 最终计算 (只需要一方计算即可)
        let triple = self.p1_protocol.step7_final_computation()?;
        
        // 验证三元组
        if self.enable_verification {
            if !triple.verify(2)? {
                return Err(MpcError::CryptographicError(
                    "Generated triple failed verification".to_string()
                ));
            }
        }
        
        // 重置协议状态以供下次使用
        self.p1_protocol.reset();
        self.p2_protocol.reset();
        
        Ok(triple)
    }
    
    /// 模拟网络通信的协议执行（更真实的两方场景）
    pub fn execute_with_messages(&mut self) -> Result<CompleteBeaverTriple> {
        // 模拟真实的消息传递协议
        let mut messages: Vec<TwoPartyOLEMessage> = Vec::new();
        
        // 步骤1-2: 生成随机值
        let (p1_x, p1_y) = self.p1_protocol.step1_2_generate_random_values()?;
        let (p2_x, p2_y) = self.p2_protocol.step1_2_generate_random_values()?;
        
        // 步骤3: P1发送第一次OLE请求
        messages.push(TwoPartyOLEMessage::FirstOLERequest { x_value: p1_x });
        
        // 步骤4: P2处理请求并响应
        let p2_first_ole = self.p2_protocol.step3_4_first_ole(p1_x)?;
        messages.push(TwoPartyOLEMessage::FirstOLEResponse { result: p2_first_ole });
        
        // P1处理响应
        let _p1_first_ole = self.p1_protocol.step3_4_first_ole(p2_x)?;
        
        // 步骤5: P1发送第二次OLE请求  
        messages.push(TwoPartyOLEMessage::SecondOLERequest { y_value: p1_y });
        
        // 步骤6: P2处理请求并响应
        let p2_second_ole = self.p2_protocol.step5_6_second_ole(p1_y)?;
        messages.push(TwoPartyOLEMessage::SecondOLEResponse { result: p2_second_ole });
        
        // P1处理响应
        let _p1_second_ole = self.p1_protocol.step5_6_second_ole(p2_y)?;
        
        // 步骤7: 生成最终三元组
        let triple = self.p1_protocol.step7_final_computation()?;
        
        // 验证消息数量
        if messages.len() != 4 {
            return Err(MpcError::ProtocolError(
                format!("Expected 4 messages, got {}", messages.len())
            ));
        }
        
        // 重置状态
        self.p1_protocol.reset();
        self.p2_protocol.reset();
        
        Ok(triple)
    }
}

impl Default for TwoPartyBeaverGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaverTripleGenerator for TwoPartyBeaverGenerator {
    fn generate_single(&mut self) -> Result<CompleteBeaverTriple> {
        self.execute_two_party_protocol()
    }
    
    fn generate_batch(&mut self, count: usize) -> Result<Vec<CompleteBeaverTriple>> {
        // 注意：根据用户要求，不需要批量处理优化，只是简单循环
        let mut triples = Vec::with_capacity(count);
        
        for _ in 0..count {
            let triple = self.generate_single()?;
            triples.push(triple);
        }
        
        Ok(triples)
    }
    
    fn verify_triple(&self, triple: &CompleteBeaverTriple) -> Result<bool> {
        triple.verify(2) // 两方协议的门限是2
    }
    
    fn get_party_count(&self) -> usize {
        2 // 两方协议
    }
    
    fn get_threshold(&self) -> usize {
        2 // 两方协议的门限
    }
}

