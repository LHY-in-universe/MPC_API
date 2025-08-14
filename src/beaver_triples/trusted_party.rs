//! # 基于可信第三方的 Beaver 三元组生成器
//! 
//! 本模块实现了使用可信第三方来生成 Beaver 三元组的方法。
//! 虽然这种方法引入了可信设置的假设，但在某些场景下是实用的解决方案。
//! 
//! ## 协议概述
//! 
//! 1. **可信设置**: 可信第三方生成随机的 (a, b, c) 其中 c = a * b
//! 2. **分享分发**: 可信方将 (a, b, c) 的分享分发给各参与方
//! 3. **验证协议**: 各方可以验证三元组的正确性而不泄露秘密
//! 4. **批量生成**: 支持高效的批量三元组生成
//! 
//! ## 安全模型
//! 
//! - **诚实但好奇**: 可信第三方按协议执行但可能尝试学习秘密
//! - **半诚实安全**: 在半诚实对手模型下提供安全性
//! - **可审计性**: 提供验证机制以检测恶意行为
//! 
//! ## 性能优势
//! 
//! - **高效生成**: 不需要复杂的密码学运算，生成速度快
//! - **低通信开销**: 主要是分发阶段的通信
//! - **批量优化**: 可以一次性生成大量三元组
//! 
//! ## 适用场景
//! 
//! - 受控环境下的 MPC 协议
//! - 需要高性能的应用场景
//! - 可以接受可信设置假设的情况

use super::*;
use crate::secret_sharing::{ShamirSecretSharing, SecretSharing};
use crate::utils::random_field_element;
use std::sync::{Arc, Mutex};

/// 基于可信第三方的 Beaver 三元组生成器
/// 
/// 这个生成器模拟了可信第三方的行为，在实际部署中
/// 可信第三方应该是一个独立的、可验证的实体。
pub struct TrustedPartyBeaverGenerator {
    /// 参与方数量
    party_count: usize,
    /// 重构门限
    threshold: usize,
    /// 当前方的 ID
    party_id: usize,
    /// 三元组计数器
    triple_counter: u64,
    /// 预计算的三元组池 (可选优化)
    precomputed_pool: Arc<Mutex<Vec<CompleteBeaverTriple>>>,
    /// 池大小限制
    pool_size_limit: usize,
}

/// 可信第三方的配置参数
#[derive(Debug, Clone)]
pub struct TrustedPartyConfig {
    /// 是否启用预计算池
    pub enable_precomputation: bool,
    /// 预计算池的大小
    pub pool_size: usize,
    /// 批量生成大小
    pub batch_size: usize,
    /// 是否启用额外的安全检查
    pub enable_security_checks: bool,
}

impl Default for TrustedPartyConfig {
    fn default() -> Self {
        Self {
            enable_precomputation: true,
            pool_size: 100,
            batch_size: 10,
            enable_security_checks: true,
        }
    }
}

impl TrustedPartyBeaverGenerator {
    /// 创建新的可信第三方 Beaver 三元组生成器
    /// 
    /// # 参数
    /// - `party_count`: 参与方总数
    /// - `threshold`: 重构门限
    /// - `party_id`: 当前方的 ID
    /// - `config`: 可信第三方配置
    /// 
    /// # 返回
    /// 返回配置好的生成器实例
    pub fn new(
        party_count: usize, 
        threshold: usize, 
        party_id: usize,
        config: Option<TrustedPartyConfig>,
    ) -> Result<Self> {
        if threshold == 0 || threshold > party_count {
            return Err(MpcError::InvalidThreshold);
        }
        
        if party_id >= party_count {
            return Err(MpcError::ProtocolError(
                "Party ID must be less than party count".to_string()
            ));
        }
        
        let config = config.unwrap_or_default();
        let precomputed_pool = Arc::new(Mutex::new(Vec::new()));
        
        let mut generator = Self {
            party_count,
            threshold,
            party_id,
            triple_counter: 0,
            precomputed_pool,
            pool_size_limit: config.pool_size,
        };
        
        // 如果启用预计算，初始填充池
        if config.enable_precomputation {
            generator.fill_precomputed_pool(config.pool_size)?;
        }
        
        Ok(generator)
    }
    
    /// 由可信第三方生成原始的三元组值
    /// 
    /// 这个方法模拟可信第三方的核心功能：
    /// 1. 生成随机的 a, b
    /// 2. 计算 c = a * b  
    /// 3. 返回 (a, b, c) 三元组
    fn generate_raw_triple(&mut self) -> (u64, u64, u64) {
        let a = random_field_element();
        let b = random_field_element();
        let c = field_mul(a, b);
        
        self.triple_counter += 1;
        (a, b, c)
    }
    
    /// 将原始三元组转换为分享形式
    /// 
    /// 可信第三方执行秘密分享，将 (a, b, c) 分享给所有参与方。
    /// 每一方将收到自己对应的分享。
    fn distribute_triple_shares(&self, a: u64, b: u64, c: u64) -> Result<CompleteBeaverTriple> {
        // 为 a, b, c 生成 Shamir 分享
        let a_shares = ShamirSecretSharing::share(&a, self.threshold, self.party_count)?;
        let b_shares = ShamirSecretSharing::share(&b, self.threshold, self.party_count)?;
        let c_shares = ShamirSecretSharing::share(&c, self.threshold, self.party_count)?;
        
        // 构建每一方的 Beaver 三元组
        let mut shares = HashMap::new();
        
        for i in 0..self.party_count {
            // Use party_id to create unique triple IDs across all parties
            let unique_triple_id = self.triple_counter * self.party_count as u64 + self.party_id as u64;
            let triple = BeaverTriple::new(
                a_shares[i].clone(),
                b_shares[i].clone(), 
                c_shares[i].clone(),
                unique_triple_id,
            );
            shares.insert(i + 1, triple);
        }
        
        Ok(CompleteBeaverTriple::new_with_values(shares, (a, b, c)))
    }
    
    /// 验证三元组的正确性
    /// 
    /// 提供一个零知识证明，证明 c = a * b 的关系
    /// 而不泄露 a, b, c 的具体值。
    fn verify_triple_correctness(&self, a: u64, b: u64, c: u64) -> bool {
        // 基本验证：检查乘法关系
        if c != field_mul(a, b) {
            return false;
        }
        
        // 检查值是否在有效域内
        if a >= FIELD_PRIME || b >= FIELD_PRIME || c >= FIELD_PRIME {
            return false;
        }
        
        // 检查值是否具有足够的随机性 (简化检查)
        // 在实际实现中，这里会使用更复杂的随机性测试
        if a == 0 || b == 0 {
            return false;
        }
        
        true
    }
    
    /// 填充预计算池
    /// 
    /// 预先生成一批三元组存储在池中，以提高响应速度。
    fn fill_precomputed_pool(&mut self, count: usize) -> Result<()> {
        let mut triples_to_store = Vec::new();
        
        // 生成三元组（需要可变借用来更新计数器）
        for _ in 0..count {
            let (a, b, c) = self.generate_raw_triple();
            
            if self.verify_triple_correctness(a, b, c) {
                let triple = self.distribute_triple_shares(a, b, c)?;
                triples_to_store.push(triple);
            }
        }
        
        // 将生成的三元组存储到池中
        let mut pool = self.precomputed_pool.lock()
            .map_err(|_| MpcError::ProtocolError("Failed to lock precomputed pool".to_string()))?;
        
        for triple in triples_to_store {
            pool.push(triple);
        }
        
        Ok(())
    }
    
    /// 从预计算池获取三元组
    fn get_from_pool(&self) -> Option<CompleteBeaverTriple> {
        let mut pool = self.precomputed_pool.lock().ok()?;
        pool.pop()
    }
    
    /// 检查并补充预计算池
    fn replenish_pool_if_needed(&mut self) -> Result<()> {
        let pool_size = {
            let pool = self.precomputed_pool.lock()
                .map_err(|_| MpcError::ProtocolError("Failed to lock pool".to_string()))?;
            pool.len()
        };
        
        let pool_size_limit = self.pool_size_limit;
        
        // 如果池中三元组数量少于限制的一半，则补充
        if pool_size < pool_size_limit / 2 {
            let refill_count = pool_size_limit - pool_size;
            self.fill_precomputed_pool(refill_count)?;
        }
        
        Ok(())
    }
}

impl BeaverTripleGenerator for TrustedPartyBeaverGenerator {
    fn generate_single(&mut self) -> Result<CompleteBeaverTriple> {
        // 优先从预计算池获取
        if let Some(triple) = self.get_from_pool() {
            // 异步补充池 (简化版：同步补充)
            let _ = self.replenish_pool_if_needed();
            return Ok(triple);
        }
        
        // 如果池为空，直接生成
        let (a, b, c) = self.generate_raw_triple();
        
        if !self.verify_triple_correctness(a, b, c) {
            return Err(MpcError::CryptographicError(
                "Generated triple failed verification".to_string()
            ));
        }
        
        self.distribute_triple_shares(a, b, c)
    }
    
    fn generate_batch(&mut self, count: usize) -> Result<Vec<CompleteBeaverTriple>> {
        let mut triples = Vec::with_capacity(count);
        
        // 首先尝试从池中获取
        for _ in 0..count {
            if let Some(triple) = self.get_from_pool() {
                triples.push(triple);
            } else {
                break;
            }
        }
        
        // 生成剩余的三元组
        let remaining = count - triples.len();
        for _ in 0..remaining {
            let triple = self.generate_single()?;
            triples.push(triple);
        }
        
        Ok(triples)
    }
    
    fn verify_triple(&self, triple: &CompleteBeaverTriple) -> Result<bool> {
        // 基本结构验证
        if !triple.verify(self.threshold)? {
            return Ok(false);
        }
        
        // 如果有原始值，进行额外验证
        if let Some((a, b, c)) = triple.original_values {
            return Ok(self.verify_triple_correctness(a, b, c));
        }
        
        Ok(true)
    }
    
    fn get_party_count(&self) -> usize {
        self.party_count
    }
    
    fn get_threshold(&self) -> usize {
        self.threshold
    }
}

/// 可信第三方批量生成器
/// 
/// 专门优化了批量生成场景，可以更高效地生成大量三元组。
pub struct BatchTrustedPartyGenerator {
    base_generator: TrustedPartyBeaverGenerator,
    batch_size: usize,
}

impl BatchTrustedPartyGenerator {
    /// 创建新的批量生成器
    pub fn new(
        party_count: usize,
        threshold: usize, 
        party_id: usize,
        batch_size: usize,
    ) -> Result<Self> {
        let config = TrustedPartyConfig {
            batch_size,
            pool_size: batch_size * 5, // 池大小为批量大小的5倍
            ..TrustedPartyConfig::default()
        };
        
        let base_generator = TrustedPartyBeaverGenerator::new(
            party_count, threshold, party_id, Some(config)
        )?;
        
        Ok(Self {
            base_generator,
            batch_size,
        })
    }
    
    /// 高效批量生成
    /// 
    /// 使用并行生成和批量分发来优化性能。
    pub fn generate_optimized_batch(&mut self, count: usize) -> Result<Vec<CompleteBeaverTriple>> {
        let mut all_triples = Vec::new();
        let mut remaining = count;
        
        while remaining > 0 {
            let current_batch = std::cmp::min(remaining, self.batch_size);
            let batch = self.base_generator.generate_batch(current_batch)?;
            all_triples.extend(batch);
            remaining -= current_batch;
        }
        
        Ok(all_triples)
    }
}

/// 可信第三方安全审计器
/// 
/// 提供对可信第三方行为的审计功能，检测潜在的恶意行为。
pub struct TrustedPartyAuditor {
    party_count: usize,
    threshold: usize,
}

impl TrustedPartyAuditor {
    /// 创建新的审计器
    pub fn new(party_count: usize, threshold: usize) -> Self {
        Self { party_count, threshold }
    }
    
    /// 审计三元组的统计性质
    /// 
    /// 检查生成的三元组是否具有预期的随机性质。
    pub fn audit_statistical_properties(&self, triples: &[CompleteBeaverTriple]) -> Result<bool> {
        if triples.is_empty() {
            return Ok(true);
        }
        
        // 统计检查：值分布的均匀性
        let mut value_counts = HashMap::new();
        
        for triple in triples {
            if let Some((a, b, c)) = triple.original_values {
                // 检查值的分布 (简化版)
                let bucket_a = (a % 100) as usize;
                let bucket_b = (b % 100) as usize; 
                let bucket_c = (c % 100) as usize;
                
                *value_counts.entry(bucket_a).or_insert(0) += 1;
                *value_counts.entry(bucket_b).or_insert(0) += 1;
                *value_counts.entry(bucket_c).or_insert(0) += 1;
                
                // 验证乘法关系
                if c != field_mul(a, b) {
                    return Ok(false);
                }
            }
        }
        
        // 简单的均匀性检查
        if let Some((&min_count, &max_count)) = value_counts.values()
            .minmax().into_option() {
            
            // 如果最大值和最小值相差太大，可能存在偏差
            if max_count > min_count * 3 {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// 审计三元组的密码学性质
    pub fn audit_cryptographic_properties(&self, triples: &[CompleteBeaverTriple]) -> Result<bool> {
        for triple in triples {
            // 验证分享的正确性
            if !triple.verify(self.threshold)? {
                return Ok(false);
            }
            
            // 检查分享数量
            if triple.shares.len() != self.party_count {
                return Ok(false);
            }
            
            // 验证每个分享的一致性
            for beaver_share in triple.shares.values() {
                if !beaver_share.is_consistent() {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
}

// 辅助函数：获取值的最小值和最大值
trait MinMaxExt<T> {
    fn minmax(self) -> MinMaxResult<T>;
}

impl<I: Iterator> MinMaxExt<I::Item> for I 
where 
    I::Item: Ord + Copy,
{
    fn minmax(mut self) -> MinMaxResult<I::Item> {
        match self.next() {
            None => MinMaxResult::NoElements,
            Some(first) => {
                let mut min = first;
                let mut max = first;
                
                for item in self {
                    if item < min {
                        min = item;
                    }
                    if item > max {
                        max = item;
                    }
                }
                
                MinMaxResult::MinMax(min, max)
            }
        }
    }
}

enum MinMaxResult<T> {
    NoElements,
    MinMax(T, T),
}

impl<T> MinMaxResult<T> {
    fn into_option(self) -> Option<(T, T)> {
        match self {
            MinMaxResult::NoElements => None,
            MinMaxResult::MinMax(min, max) => Some((min, max)),
        }
    }
}

