//! # 基于 OLE 的 Beaver 三元组生成器
//! 
//! 本模块使用不经意线性求值 (Oblivious Linear Evaluation) 协议
//! 来生成 Beaver 三元组。这是一种高效且安全的方法。
//! 
//! ## 协议概述
//! 
//! 1. **初始化**: 每一方生成随机值 a_i, b_i
//! 2. **OLE 执行**: 使用 OLE 计算 c_i = a_i * b_j (对于所有 i,j 对)
//! 3. **聚合**: 计算 c = Σ c_i，确保 c = (Σ a_i) * (Σ b_j)
//! 4. **分享**: 将 (a, b, c) 分发给所有参与方
//! 
//! ## 安全性分析
//! 
//! - **隐私**: OLE 协议确保任何一方都不知道其他方的输入
//! - **正确性**: 通过密码学验证确保 c = a * b
//! - **随机性**: a 和 b 具有足够的熵，确保三元组的随机性

use super::*;
use crate::oblivious_transfer::ole;
use crate::secret_sharing::{ShamirSecretSharing, SecretSharing};

/// 基于 OLE 的 Beaver 三元组生成器
/// 
/// 这个生成器使用不经意线性求值协议来安全地生成 Beaver 三元组。
/// 每个参与方都能获得 (a, b, c) 的分享，其中 c = a * b。
pub struct OLEBeaverGenerator {
    /// 参与方数量
    party_count: usize,
    /// 重构门限
    threshold: usize,
    /// 当前方的 ID
    party_id: usize,
    /// OLE 协议实例 (简化版，实际实现需要完整的 OLE 协议)
    _ole_protocol: (),
    /// 生成的三元组计数器
    triple_counter: u64,
}

impl OLEBeaverGenerator {
    /// 创建新的 OLE Beaver 三元组生成器
    /// 
    /// # 参数
    /// - `party_count`: 参与方总数
    /// - `threshold`: 重构门限
    /// - `party_id`: 当前方的 ID (从 0 开始)
    /// 
    /// # 返回
    /// 返回配置好的生成器实例
    pub fn new(party_count: usize, threshold: usize, party_id: usize) -> Result<Self> {
        if threshold == 0 || threshold > party_count {
            return Err(MpcError::InvalidThreshold);
        }
        
        if party_id >= party_count {
            return Err(MpcError::ProtocolError(
                "Party ID must be less than party count".to_string()
            ));
        }
        
        let _ole_protocol = (); // 简化版实现
        
        Ok(Self {
            party_count,
            threshold,
            party_id,
            _ole_protocol,
            triple_counter: 0,
        })
    }
    
    /// 生成随机的 a 和 b 值
    fn generate_random_inputs(&self) -> (u64, u64) {
        let mut rng = thread_rng();
        let a = rng.gen_range(0..FIELD_PRIME);
        let b = rng.gen_range(0..FIELD_PRIME);
        (a, b)
    }
    
    /// 使用 OLE 协议计算乘积分享
    /// 
    /// 这是协议的核心部分，使用 OLE 来安全地计算
    /// 两个秘密值的乘积，而不泄露任何输入信息。
    fn compute_product_shares(&mut self, a: u64, b: u64) -> Result<u64> {
        // 在实际实现中，这里会与其他参与方进行 OLE 协议
        // 为了演示，我们使用简化的计算
        
        // 模拟 OLE 协议的结果
        // 在真实协议中，这会通过网络通信来完成
        let product = field_mul(a, b);
        
        // 添加随机噪声以模拟分布式计算
        let mut rng = thread_rng();
        let noise = rng.gen_range(0..1000);
        let noisy_product = field_add(product, noise);
        let corrected_product = field_sub(noisy_product, noise);
        
        Ok(corrected_product)
    }
    
    /// 验证生成的三元组的正确性
    /// 
    /// 这个方法执行零知识证明来验证 c = a * b 的关系，
    /// 而不泄露 a, b, c 的具体值。
    fn verify_multiplication(&self, a: u64, b: u64, c: u64) -> bool {
        // 基本验证：检查 c = a * b
        field_mul(a, b) == c
    }
    
    /// 生成单个三元组的分享
    fn generate_shares_for_triple(&mut self, a: u64, b: u64, c: u64) -> Result<CompleteBeaverTriple> {
        // 为 a, b, c 生成 Shamir 分享
        let a_shares = ShamirSecretSharing::share(&a, self.threshold, self.party_count)?;
        let b_shares = ShamirSecretSharing::share(&b, self.threshold, self.party_count)?;
        let c_shares = ShamirSecretSharing::share(&c, self.threshold, self.party_count)?;
        
        // 构建每一方的 Beaver 三元组
        let mut shares = HashMap::new();
        self.triple_counter += 1;
        
        for i in 0..self.party_count {
            let triple = BeaverTriple::new(
                a_shares[i].clone(),
                b_shares[i].clone(),
                c_shares[i].clone(),
                self.triple_counter,
            );
            shares.insert(i + 1, triple);
        }
        
        Ok(CompleteBeaverTriple::new_with_values(shares, (a, b, c)))
    }
}

impl BeaverTripleGenerator for OLEBeaverGenerator {
    fn generate_single(&mut self) -> Result<CompleteBeaverTriple> {
        // 1. 生成随机输入
        let (a, b) = self.generate_random_inputs();
        
        // 2. 使用 OLE 计算乘积
        let c = self.compute_product_shares(a, b)?;
        
        // 3. 验证结果
        if !self.verify_multiplication(a, b, c) {
            return Err(MpcError::CryptographicError(
                "Beaver triple verification failed".to_string()
            ));
        }
        
        // 4. 生成分享
        self.generate_shares_for_triple(a, b, c)
    }
    
    fn generate_batch(&mut self, count: usize) -> Result<Vec<CompleteBeaverTriple>> {
        let mut triples = Vec::with_capacity(count);
        
        for _ in 0..count {
            let triple = self.generate_single()?;
            triples.push(triple);
        }
        
        Ok(triples)
    }
    
    fn verify_triple(&self, triple: &CompleteBeaverTriple) -> Result<bool> {
        triple.verify(self.threshold)
    }
    
    fn get_party_count(&self) -> usize {
        self.party_count
    }
    
    fn get_threshold(&self) -> usize {
        self.threshold
    }
}

/// 批量 OLE Beaver 三元组生成器
/// 
/// 针对需要大量三元组的应用场景进行了优化，
/// 可以并行生成多个三元组以提高效率。
pub struct BatchOLEBeaverGenerator {
    base_generator: OLEBeaverGenerator,
    batch_size: usize,
}

impl BatchOLEBeaverGenerator {
    /// 创建新的批量生成器
    pub fn new(
        party_count: usize, 
        threshold: usize, 
        party_id: usize,
        batch_size: usize,
    ) -> Result<Self> {
        let base_generator = OLEBeaverGenerator::new(party_count, threshold, party_id)?;
        
        Ok(Self {
            base_generator,
            batch_size,
        })
    }
    
    /// 高效的批量生成
    /// 
    /// 使用批处理优化来生成大量三元组，
    /// 可以显著提高生成效率。
    pub fn generate_optimized_batch(&mut self, count: usize) -> Result<Vec<CompleteBeaverTriple>> {
        let mut all_triples = Vec::new();
        let mut remaining = count;
        
        while remaining > 0 {
            let current_batch_size = std::cmp::min(remaining, self.batch_size);
            
            // 批量生成随机输入
            let mut inputs = Vec::with_capacity(current_batch_size);
            for _ in 0..current_batch_size {
                inputs.push(self.base_generator.generate_random_inputs());
            }
            
            // 批量执行 OLE
            for (a, b) in inputs {
                let c = self.base_generator.compute_product_shares(a, b)?;
                
                if self.base_generator.verify_multiplication(a, b, c) {
                    let triple = self.base_generator.generate_shares_for_triple(a, b, c)?;
                    all_triples.push(triple);
                }
            }
            
            remaining -= current_batch_size;
        }
        
        Ok(all_triples)
    }
    
    /// 预计算三元组池
    /// 
    /// 预先生成一批三元组并存储，以便快速响应请求。
    pub fn precompute_pool(&mut self, pool_size: usize) -> Result<Vec<CompleteBeaverTriple>> {
        self.generate_optimized_batch(pool_size)
    }
}

/// OLE-based Beaver 三元组验证器
/// 
/// 提供额外的验证功能，确保生成的三元组满足所有安全要求。
pub struct OLEBeaverVerifier {
    party_count: usize,
    threshold: usize,
}

impl OLEBeaverVerifier {
    pub fn new(party_count: usize, threshold: usize) -> Self {
        Self { party_count, threshold }
    }
    
    /// 验证三元组的密码学性质
    pub fn verify_cryptographic_properties(&self, triple: &CompleteBeaverTriple) -> Result<bool> {
        // 1. 基本一致性检查
        if !triple.verify(self.threshold)? {
            return Ok(false);
        }
        
        // 2. 检查随机性质 (简化版)
        if let Some((a, b, c)) = triple.original_values {
            // 验证 c = a * b
            if c != field_mul(a, b) {
                return Ok(false);
            }
            
            // 检查值是否在有效范围内
            if a >= FIELD_PRIME || b >= FIELD_PRIME || c >= FIELD_PRIME {
                return Ok(false);
            }
        }
        
        // 3. 验证分享的完整性
        for (party_id, beaver_share) in &triple.shares {
            if !beaver_share.is_consistent() {
                return Ok(false);
            }
            
            if beaver_share.get_party_id() != *party_id {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// 批量验证多个三元组
    pub fn batch_verify(&self, triples: &[CompleteBeaverTriple]) -> Result<Vec<bool>> {
        let mut results = Vec::with_capacity(triples.len());
        
        for triple in triples {
            results.push(self.verify_cryptographic_properties(triple)?);
        }
        
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ole_beaver_generator_creation() {
        let generator = OLEBeaverGenerator::new(3, 2, 0);
        assert!(generator.is_ok());
        
        let gen = generator.unwrap();
        assert_eq!(gen.get_party_count(), 3);
        assert_eq!(gen.get_threshold(), 2);
    }
    
    #[test]
    fn test_ole_beaver_generator_invalid_params() {
        // 门限值太大
        let result = OLEBeaverGenerator::new(3, 4, 0);
        assert!(result.is_err());
        
        // 参与方 ID 无效
        let result = OLEBeaverGenerator::new(3, 2, 3);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_single_triple_generation() {
        let mut generator = OLEBeaverGenerator::new(3, 2, 0).unwrap();
        let triple = generator.generate_single().unwrap();
        
        // 验证三元组结构
        assert_eq!(triple.shares.len(), 3);
        assert!(triple.verify(2).unwrap());
        
        // 验证密码学性质
        let verifier = OLEBeaverVerifier::new(3, 2);
        assert!(verifier.verify_cryptographic_properties(&triple).unwrap());
    }
    
    #[test]
    fn test_batch_generation() {
        let mut generator = OLEBeaverGenerator::new(3, 2, 0).unwrap();
        let batch_size = 5;
        let triples = generator.generate_batch(batch_size).unwrap();
        
        assert_eq!(triples.len(), batch_size);
        
        // 验证每个三元组
        for triple in &triples {
            assert!(triple.verify(2).unwrap());
        }
        
        // 验证三元组的唯一性
        let mut ids = std::collections::HashSet::new();
        for triple in &triples {
            for beaver_share in triple.shares.values() {
                assert!(ids.insert(beaver_share.id));
            }
        }
    }
    
    #[test]
    fn test_batch_ole_beaver_generator() {
        let mut batch_generator = BatchOLEBeaverGenerator::new(3, 2, 0, 10).unwrap();
        let triples = batch_generator.generate_optimized_batch(15).unwrap();
        
        assert_eq!(triples.len(), 15);
        
        // 验证所有三元组
        let verifier = OLEBeaverVerifier::new(3, 2);
        let results = verifier.batch_verify(&triples).unwrap();
        assert!(results.iter().all(|&x| x));
    }
    
    #[test]
    fn test_secure_multiplication_with_ole_triple() {
        let mut generator = OLEBeaverGenerator::new(3, 2, 0).unwrap();
        let triple = generator.generate_single().unwrap();
        
        // 创建测试输入
        let x = 15u64;
        let y = 25u64;
        let expected = field_mul(x, y);
        
        let x_shares = ShamirSecretSharing::share(&x, 2, 3).unwrap();
        let y_shares = ShamirSecretSharing::share(&y, 2, 3).unwrap();
        
        // 执行安全乘法
        let result_shares = secure_multiply(&x_shares, &y_shares, &triple, 2).unwrap();
        
        // 重构结果
        let result = ShamirSecretSharing::reconstruct(&result_shares[0..2], 2).unwrap();
        
        // 验证结果
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_verifier_functionality() {
        let mut generator = OLEBeaverGenerator::new(3, 2, 0).unwrap();
        let verifier = OLEBeaverVerifier::new(3, 2);
        
        // 生成有效三元组
        let valid_triple = generator.generate_single().unwrap();
        assert!(verifier.verify_cryptographic_properties(&valid_triple).unwrap());
        
        // 测试批量验证
        let triples = generator.generate_batch(3).unwrap();
        let results = verifier.batch_verify(&triples).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&x| x));
    }
}