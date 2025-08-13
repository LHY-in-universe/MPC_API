//! # Beaver 三元组模块 (Beaver Triples Module)
//! 
//! Beaver 三元组是安全多方计算中用于实现安全乘法的核心工具。
//! 本模块提供了多种生成 Beaver 三元组的方法，包括：
//! 
//! 1. **OLE-based**: 基于不经意线性求值的方法
//! 2. **Homomorphic Encryption**: 基于同态加密 (BFV) 的方法  
//! 3. **Trusted Third Party**: 基于可信第三方的方法
//! 4. **BGW Protocol**: 基于 BGW 协议的信息论安全方法
//! 
//! ## Beaver 三元组定义
//! 
//! Beaver 三元组是满足以下条件的三元组 (a, b, c)：
//! - a, b 是随机值
//! - c = a * b (在有限域上)
//! - 每一方都持有 (a, b, c) 的秘密分享
//! 
//! ## 安全乘法协议
//! 
//! 使用 Beaver 三元组，两方可以安全地计算 x * y：
//! 1. 各方持有 [x], [y] (x, y 的分享) 和 ([a], [b], [c])
//! 2. 计算并公开 d = x - a, e = y - b  
//! 3. 计算 [z] = [c] + d·[b] + e·[a] + d·e
//! 4. 结果 [z] 是 x·y 的分享
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::beaver_triples::*;
//! use mpc_api::secret_sharing::*;
//! 
//! // 使用 OLE 生成 Beaver 三元组
//! let generator = OLEBeaverGenerator::new(3, 2)?; // 3方，门限2
//! let triples = generator.generate_batch(10)?;    // 生成10个三元组
//! 
//! // 使用 BFV 同态加密生成
//! let bfv_generator = BFVBeaverGenerator::new(3, 2)?;
//! let bfv_triples = bfv_generator.generate_batch(10)?;
//! 
//! // 安全乘法示例
//! let x_shares = ShamirSecretSharing::share(&15, 2, 3)?;
//! let y_shares = ShamirSecretSharing::share(&25, 2, 3)?;
//! let triple = &triples[0];
//! 
//! let product_shares = secure_multiply(&x_shares, &y_shares, triple)?;
//! let product = ShamirSecretSharing::reconstruct(&product_shares[0..2], 2)?;
//! assert_eq!(product, field_mul(15, 25));
//! ```

pub mod ole_based;
pub mod bfv_based;
pub mod trusted_party;

pub use ole_based::*;
pub use bfv_based::*;
pub use trusted_party::*;

use crate::{MpcError, Result};
use crate::secret_sharing::{Share, field_add, field_sub, field_mul, FIELD_PRIME};
use serde::{Deserialize, Serialize};
use rand::{Rng, thread_rng};
use std::collections::HashMap;

/// Beaver 三元组的分享表示
/// 每一方持有 (a, b, c) 三个值的分享，其中 c = a * b
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaverTriple {
    /// a 的分享
    pub a: Share,
    /// b 的分享  
    pub b: Share,
    /// c = a * b 的分享
    pub c: Share,
    /// 三元组的唯一标识符
    pub id: u64,
}

/// 完整的 Beaver 三元组，包含所有参与方的分享
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteBeaverTriple {
    /// 每一方的三元组分享
    pub shares: HashMap<usize, BeaverTriple>,
    /// 原始值 (仅用于验证，实际协议中不应该存在)
    pub original_values: Option<(u64, u64, u64)>,
}

/// Beaver 三元组生成器的通用特征
pub trait BeaverTripleGenerator {
    /// 生成单个 Beaver 三元组
    fn generate_single(&mut self) -> Result<CompleteBeaverTriple>;
    
    /// 批量生成 Beaver 三元组
    fn generate_batch(&mut self, count: usize) -> Result<Vec<CompleteBeaverTriple>>;
    
    /// 验证三元组的正确性
    fn verify_triple(&self, triple: &CompleteBeaverTriple) -> Result<bool>;
    
    /// 获取支持的参与方数量
    fn get_party_count(&self) -> usize;
    
    /// 获取门限值
    fn get_threshold(&self) -> usize;
}

impl BeaverTriple {
    /// 创建新的 Beaver 三元组分享
    pub fn new(a: Share, b: Share, c: Share, id: u64) -> Self {
        Self { a, b, c, id }
    }
    
    /// 验证三元组分享的一致性 (相同的 x 坐标)
    pub fn is_consistent(&self) -> bool {
        self.a.x == self.b.x && self.b.x == self.c.x
    }
    
    /// 获取参与方 ID
    pub fn get_party_id(&self) -> usize {
        self.a.x as usize
    }
}

impl CompleteBeaverTriple {
    /// 创建新的完整 Beaver 三元组
    pub fn new(shares: HashMap<usize, BeaverTriple>) -> Self {
        Self {
            shares,
            original_values: None,
        }
    }
    
    /// 创建带有原始值的 Beaver 三元组 (用于测试)
    pub fn new_with_values(
        shares: HashMap<usize, BeaverTriple>,
        original: (u64, u64, u64),
    ) -> Self {
        Self {
            shares,
            original_values: Some(original),
        }
    }
    
    /// 获取指定方的三元组分享
    pub fn get_share(&self, party_id: usize) -> Option<&BeaverTriple> {
        self.shares.get(&party_id)
    }
    
    /// 验证三元组的完整性
    pub fn verify(&self, threshold: usize) -> Result<bool> {
        if self.shares.len() < threshold {
            return Ok(false);
        }
        
        // 验证所有分享的一致性
        for triple in self.shares.values() {
            if !triple.is_consistent() {
                return Ok(false);
            }
        }
        
        // 如果有原始值，验证重构的正确性
        if let Some((a, b, c)) = self.original_values {
            let a_shares: Vec<_> = self.shares.values().map(|t| t.a.clone()).collect();
            let b_shares: Vec<_> = self.shares.values().map(|t| t.b.clone()).collect();
            let c_shares: Vec<_> = self.shares.values().map(|t| t.c.clone()).collect();
            
            use crate::secret_sharing::{ShamirSecretSharing, SecretSharing};
            
            let reconstructed_a = ShamirSecretSharing::reconstruct(&a_shares[0..threshold], threshold)?;
            let reconstructed_b = ShamirSecretSharing::reconstruct(&b_shares[0..threshold], threshold)?;
            let reconstructed_c = ShamirSecretSharing::reconstruct(&c_shares[0..threshold], threshold)?;
            
            return Ok(reconstructed_a == a && 
                     reconstructed_b == b && 
                     reconstructed_c == c &&
                     c == field_mul(a, b));
        }
        
        Ok(true)
    }
}

/// 使用 Beaver 三元组进行安全乘法
/// 
/// 实现标准的 Beaver 乘法协议：
/// 1. 计算 d = x - a, e = y - b (需要重构这些值)
/// 2. 计算 [z] = [c] + d·[b] + e·[a] + d·e
/// 3. 返回 z = x·y 的分享
pub fn secure_multiply(
    x_shares: &[Share],
    y_shares: &[Share], 
    beaver_triple: &CompleteBeaverTriple,
    threshold: usize,
) -> Result<Vec<Share>> {
    if x_shares.len() != y_shares.len() || x_shares.len() < threshold {
        return Err(MpcError::InvalidThreshold);
    }
    
    use crate::secret_sharing::{ShamirSecretSharing, SecretSharing};
    
    // 1. 重构 x, y, a, b
    let x = ShamirSecretSharing::reconstruct(&x_shares[0..threshold], threshold)?;
    let y = ShamirSecretSharing::reconstruct(&y_shares[0..threshold], threshold)?;
    
    let a_shares: Vec<_> = beaver_triple.shares.values().take(threshold)
        .map(|t| t.a.clone()).collect();
    let b_shares: Vec<_> = beaver_triple.shares.values().take(threshold)
        .map(|t| t.b.clone()).collect();
    
    let a = ShamirSecretSharing::reconstruct(&a_shares, threshold)?;
    let b = ShamirSecretSharing::reconstruct(&b_shares, threshold)?;
    
    // 2. 计算 d = x - a, e = y - b
    let d = field_sub(x, a);
    let e = field_sub(y, b);
    
    // 3. 计算每一方的 z 分享: [z] = [c] + d·[b] + e·[a] + d·e
    let mut z_shares = Vec::new();
    let de = field_mul(d, e);
    
    for (party_id, triple) in &beaver_triple.shares {
        if z_shares.len() >= x_shares.len() {
            break;
        }
        
        // [z_i] = [c_i] + d·[b_i] + e·[a_i] + d·e
        let term1 = triple.c.y;                    // [c_i]
        let term2 = field_mul(d, triple.b.y);     // d·[b_i]  
        let term3 = field_mul(e, triple.a.y);     // e·[a_i]
        let term4 = de;                            // d·e (只有第一方加这一项)
        
        let z_value = if *party_id == 1 {
            field_add(field_add(field_add(term1, term2), term3), term4)
        } else {
            field_add(field_add(term1, term2), term3)
        };
        
        z_shares.push(Share::new(*party_id as u64, z_value));
    }
    
    Ok(z_shares)
}

/// 批量安全乘法
/// 使用多个 Beaver 三元组同时计算多个乘法
pub fn batch_secure_multiply(
    x_shares_batch: &[Vec<Share>],
    y_shares_batch: &[Vec<Share>],
    beaver_triples: &[CompleteBeaverTriple],
    threshold: usize,
) -> Result<Vec<Vec<Share>>> {
    if x_shares_batch.len() != y_shares_batch.len() || 
       x_shares_batch.len() != beaver_triples.len() {
        return Err(MpcError::ProtocolError(
            "Batch arrays must have same length".to_string()
        ));
    }
    
    let mut results = Vec::new();
    
    for ((x_shares, y_shares), triple) in x_shares_batch.iter()
        .zip(y_shares_batch.iter())
        .zip(beaver_triples.iter()) {
        
        let product_shares = secure_multiply(x_shares, y_shares, triple, threshold)?;
        results.push(product_shares);
    }
    
    Ok(results)
}

/// 验证 Beaver 三元组的批次
pub fn verify_triple_batch(
    triples: &[CompleteBeaverTriple],
    threshold: usize,
) -> Result<bool> {
    for triple in triples {
        if !triple.verify(threshold)? {
            return Ok(false);
        }
    }
    Ok(true)
}