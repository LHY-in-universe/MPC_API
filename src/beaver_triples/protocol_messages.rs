//! # BFV Beaver 三元组协议消息定义
//! 
//! 本模块定义了BFV同态加密Beaver三元组生成协议中
//! 各参与方之间交换的消息类型。

use crate::homomorphic_encryption::{BFVCiphertext, BFVPublicKey, BFVSecretKey};
use crate::{MpcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 参与方ID类型
pub type PartyId = usize;

/// 协议轮次标识
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolRound {
    /// 门限密钥生成轮次
    ThresholdKeyGen,
    /// 加密分享提交轮次
    EncryptedShares, 
    /// 同态聚合结果广播轮次
    HomomorphicAggregation,
    /// C分享计算轮次
    CShareComputation,
    /// 最终三元组重构轮次
    TripleReconstruction,
}

/// BFV Beaver协议消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BFVBeaverMessage {
    /// 门限密钥生成贡献
    KeyGenContribution {
        party_id: PartyId,
        public_contribution: Vec<u64>,
        proof: Vec<u8>, // 零知识证明
    },
    
    /// 生成的公钥广播
    PublicKeyBroadcast {
        public_key: BFVPublicKey,
        verification_data: Vec<u8>,
    },
    
    /// 加密的秘密分享
    EncryptedShares {
        party_id: PartyId,
        enc_a_i: BFVCiphertext,
        enc_b_i: BFVCiphertext,
        commitment: Vec<u8>, // 承诺值
    },
    
    /// 同态聚合结果 (由P1发送)
    AggregatedResult {
        enc_a: BFVCiphertext,  // Enc(Σa_i)
        enc_b: BFVCiphertext,  // Enc(Σb_i) 
        enc_ab: BFVCiphertext, // Enc(ab)
        proof_of_correctness: Vec<u8>,
    },
    
    /// C分享贡献 (前N-1方)
    CShareContribution {
        party_id: PartyId,
        c_i: u64,
        enc_c_i: BFVCiphertext,
    },
    
    /// 部分解密结果 (最后一方)
    PartialDecryption {
        party_id: PartyId,
        decryption_share: Vec<u64>,
        proof: Vec<u8>,
    },
    
    /// 协议完成通知
    ProtocolComplete {
        triple_id: u64,
        success: bool,
        error_message: Option<String>,
    },
    
    /// 协议中止请求
    ProtocolAbort {
        party_id: PartyId,
        reason: String,
        round: ProtocolRound,
    },
}

/// 协议执行状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProtocolState {
    /// 初始化状态
    Initialized,
    /// 密钥生成中
    KeyGeneration,
    /// 等待加密分享
    WaitingForShares,
    /// 执行同态聚合
    HomomorphicComputation,
    /// 计算C分享
    CShareGeneration,
    /// 最终解密中
    FinalDecryption,
    /// 协议完成
    Completed,
    /// 协议失败
    Failed(String),
}

/// 协议配置参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BFVBeaverConfig {
    /// 参与方数量
    pub party_count: usize,
    /// 门限值
    pub threshold: usize,
    /// BFV参数
    pub bfv_params: crate::beaver_triples::bfv_based::BFVParams,
    /// 安全参数
    pub security_level: u32,
    /// 超时设置（毫秒）
    pub timeout_ms: u64,
    /// 是否启用零知识证明
    pub enable_zk_proofs: bool,
}



impl Default for BFVBeaverConfig {
    fn default() -> Self {
        Self {
            party_count: 3,
            threshold: 2,
            bfv_params: crate::beaver_triples::bfv_based::BFVParams::default(),
            security_level: 128,
            timeout_ms: 30000, // 30秒
            enable_zk_proofs: true,
        }
    }
}

/// 协议执行上下文
#[derive(Debug)]
pub struct BFVBeaverProtocolContext {
    /// 配置参数
    pub config: BFVBeaverConfig,
    /// 当前方ID
    pub party_id: PartyId,
    /// 当前状态
    pub state: ProtocolState,
    /// 当前轮次
    pub current_round: ProtocolRound,
    /// 接收到的消息缓存
    pub received_messages: HashMap<(PartyId, ProtocolRound), BFVBeaverMessage>,
    /// 公钥
    pub public_key: Option<BFVPublicKey>,
    /// 私钥分享
    pub secret_key_share: Option<BFVSecretKey>,
    /// 本方的秘密分享
    pub my_shares: Option<(u64, u64)>, // (a_i, b_i)
    /// 聚合后的加密结果
    pub aggregated_enc: Option<(BFVCiphertext, BFVCiphertext, BFVCiphertext)>, // (Enc(a), Enc(b), Enc(ab))
    /// C分享
    pub c_shares: HashMap<PartyId, u64>,
    /// 生成的三元组ID
    pub triple_id: Option<u64>,
}

impl BFVBeaverProtocolContext {
    /// 创建新的协议上下文
    pub fn new(config: BFVBeaverConfig, party_id: PartyId) -> Self {
        Self {
            config,
            party_id,
            state: ProtocolState::Initialized,
            current_round: ProtocolRound::ThresholdKeyGen,
            received_messages: HashMap::new(),
            public_key: None,
            secret_key_share: None,
            my_shares: None,
            aggregated_enc: None,
            c_shares: HashMap::new(),
            triple_id: None,
        }
    }
    
    /// 更新协议状态
    pub fn update_state(&mut self, new_state: ProtocolState) {
        self.state = new_state;
    }
    
    /// 进入下一轮次
    pub fn advance_round(&mut self) -> Result<()> {
        self.current_round = match self.current_round {
            ProtocolRound::ThresholdKeyGen => ProtocolRound::EncryptedShares,
            ProtocolRound::EncryptedShares => ProtocolRound::HomomorphicAggregation,
            ProtocolRound::HomomorphicAggregation => ProtocolRound::CShareComputation,
            ProtocolRound::CShareComputation => ProtocolRound::TripleReconstruction,
            ProtocolRound::TripleReconstruction => {
                return Err(MpcError::ProtocolError("Protocol already completed".to_string()));
            }
        };
        Ok(())
    }
    
    /// 添加接收到的消息
    pub fn add_message(&mut self, from_party: PartyId, message: BFVBeaverMessage) {
        let round = self.current_round;
        self.received_messages.insert((from_party, round), message);
    }
    
    /// 检查是否收到了所有必需的消息
    pub fn has_required_messages(&self) -> bool {
        match self.current_round {
            ProtocolRound::ThresholdKeyGen => {
                // 需要收到所有其他方的密钥生成贡献
                (0..self.config.party_count).all(|id| {
                    id == self.party_id || 
                    self.received_messages.contains_key(&(id, self.current_round))
                })
            }
            ProtocolRound::EncryptedShares => {
                // 需要收到所有方的加密分享
                (0..self.config.party_count).all(|id| {
                    self.received_messages.contains_key(&(id, self.current_round))
                })
            }
            ProtocolRound::HomomorphicAggregation => {
                // 只需要收到P1的聚合结果
                self.received_messages.contains_key(&(0, self.current_round))
            }
            ProtocolRound::CShareComputation => {
                // 需要收到前N-1方的C分享贡献
                (0..self.config.party_count - 1).all(|id| {
                    self.received_messages.contains_key(&(id, self.current_round))
                })
            }
            ProtocolRound::TripleReconstruction => {
                // 需要收到最后一方的解密结果
                self.received_messages.contains_key(&(self.config.party_count - 1, self.current_round))
            }
        }
    }
    
    /// 重置协议状态（用于重新开始）
    pub fn reset(&mut self) {
        self.state = ProtocolState::Initialized;
        self.current_round = ProtocolRound::ThresholdKeyGen;
        self.received_messages.clear();
        self.public_key = None;
        self.secret_key_share = None;
        self.my_shares = None;
        self.aggregated_enc = None;
        self.c_shares.clear();
        self.triple_id = None;
    }
}

/// 消息验证trait
pub trait MessageValidator {
    /// 验证消息的格式和内容是否正确
    fn validate(&self) -> Result<()>;
    
    /// 验证消息是否来自指定的参与方
    fn verify_sender(&self, expected_party_id: PartyId) -> Result<()>;
}

impl MessageValidator for BFVBeaverMessage {
    fn validate(&self) -> Result<()> {
        match self {
            BFVBeaverMessage::KeyGenContribution { public_contribution, .. } => {
                if public_contribution.is_empty() {
                    return Err(MpcError::ProtocolError("Empty public contribution".to_string()));
                }
                Ok(())
            }
            BFVBeaverMessage::EncryptedShares { enc_a_i, enc_b_i, .. } => {
                if enc_a_i.c0.is_empty() || enc_a_i.c1.is_empty() || 
                   enc_b_i.c0.is_empty() || enc_b_i.c1.is_empty() {
                    return Err(MpcError::ProtocolError("Invalid ciphertext structure".to_string()));
                }
                Ok(())
            }
            BFVBeaverMessage::AggregatedResult { enc_a, enc_b, enc_ab, .. } => {
                if enc_a.c0.is_empty() || enc_b.c0.is_empty() || enc_ab.c0.is_empty() {
                    return Err(MpcError::ProtocolError("Invalid aggregated ciphertext".to_string()));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    
    fn verify_sender(&self, expected_party_id: PartyId) -> Result<()> {
        let actual_party_id = match self {
            BFVBeaverMessage::KeyGenContribution { party_id, .. } => *party_id,
            BFVBeaverMessage::EncryptedShares { party_id, .. } => *party_id,
            BFVBeaverMessage::CShareContribution { party_id, .. } => *party_id,
            BFVBeaverMessage::PartialDecryption { party_id, .. } => *party_id,
            BFVBeaverMessage::ProtocolAbort { party_id, .. } => *party_id,
            _ => return Ok(()), // 某些消息类型不需要验证发送方
        };
        
        if actual_party_id != expected_party_id {
            return Err(MpcError::ProtocolError(
                format!("Message sender mismatch: expected {}, got {}", expected_party_id, actual_party_id)
            ));
        }
        
        Ok(())
    }
}

