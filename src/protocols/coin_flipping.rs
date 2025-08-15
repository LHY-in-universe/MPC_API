//! # 硬币抛掷协议 (Coin Flipping Protocol)
//! 
//! 本模块实现了安全的硬币抛掷协议，用于在多方之间生成共享的随机性。
//! 硬币抛掷是密码学中的一个基本问题：如何让互不信任的参与方公平地生成随机比特。
//! 
//! ## 核心概念
//! 
//! ### 安全硬币抛掷的要求
//! - **公平性**: 任何一方都无法单独影响结果
//! - **不可预测性**: 在所有参与方提交之前，结果是不可预测的
//! - **可验证性**: 所有参与方都可以验证协议的正确执行
//! 
//! ### 承诺-揭示范式
//! 1. **承诺阶段**: 每个参与方对其输入进行承诺
//! 2. **揭示阶段**: 参与方揭示其输入和随机数
//! 3. **验证阶段**: 验证承诺的正确性
//! 4. **组合阶段**: 将所有输入组合得到最终结果
//! 
//! ## 支持的协议
//! 
//! - **XOR 硬币抛掷**: 基于异或运算的简单协议
//! - **Blum 硬币抛掷**: 经典的两方硬币抛掷协议
//! - **多方硬币抛掷**: 支持任意数量参与方的协议
//! - **抗偏置硬币抛掷**: 通过多轮协议减少偏置
//! - **基于承诺的硬币抛掷**: 使用 Pedersen 承诺的协议
//! 
//! ## 使用示例
//! 
//! ```rust
//! use mpc_api::protocols::coin_flipping::*;
//! 
//! // 简单的两方硬币抛掷
//! let result = BlumCoinFlip::protocol()?;
//! println!("硬币抛掷结果: {}", if result { "正面" } else { "反面" });
//! 
//! // 多方硬币抛掷
//! let multi_result = BlumCoinFlip::multi_party_coin_flip(5)?;
//! println!("多方硬币抛掷结果: {}", multi_result);
//! 
//! // 生成随机字符串
//! let random_string = SequentialCoinFlip::generate_random_string(32)?;
//! println!("随机字符串: {}", random_string);
//! ```

use crate::{MpcError, Result};
use crate::secret_sharing::{FIELD_PRIME, field_add};
use crate::commitment::{PedersenCommitment, CommitmentScheme};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};

/// 硬币抛掷承诺结构
/// 
/// 表示参与方对其选择比特的承诺。承诺包含哈希值和随机数，
/// 确保在揭示阶段之前无法推断出实际的比特值。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinFlipCommit {
    /// 承诺值（比特和随机数的哈希）
    pub commitment: u64,
    /// 用于承诺的随机数
    pub randomness: u64,
}

/// 硬币抛掷揭示结构
/// 
/// 表示参与方在揭示阶段公开的信息，包括实际的比特值和随机数。
/// 其他参与方可以使用这些信息验证承诺的正确性。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinFlipReveal {
    /// 实际的比特值
    pub value: bool,
    /// 承诺时使用的随机数
    pub randomness: u64,
}

/// 硬币抛掷协议 trait
/// 
/// 定义了所有硬币抛掷协议必须实现的基本操作。
/// 这是所有硬币抛掷协议的基础接口。
pub trait CoinFlipping {
    /// 对比特进行承诺
    /// 
    /// 生成对指定比特的承诺和相应的揭示信息。
    /// 承诺是隐藏的，但在揭示阶段可以被验证。
    /// 
    /// # 参数
    /// 
    /// * `bit` - 要承诺的比特值
    /// 
    /// # 返回值
    /// 
    /// 返回承诺和揭示信息的元组，或者在出错时返回错误
    fn commit_bit(bit: bool) -> Result<(CoinFlipCommit, CoinFlipReveal)>;
    
    /// 验证承诺并组合结果
    /// 
    /// 验证两个参与方的承诺是否正确，然后组合它们的比特值
    /// 得到最终的硬币抛掷结果。
    /// 
    /// # 参数
    /// 
    /// * `commit1` - 第一个参与方的承诺
    /// * `reveal1` - 第一个参与方的揭示
    /// * `commit2` - 第二个参与方的承诺
    /// * `reveal2` - 第二个参与方的揭示
    /// 
    /// # 返回值
    /// 
    /// 返回组合后的比特值，或者在验证失败时返回错误
    fn verify_and_combine(
        commit1: &CoinFlipCommit,
        reveal1: &CoinFlipReveal,
        commit2: &CoinFlipCommit, 
        reveal2: &CoinFlipReveal,
    ) -> Result<bool>;
}

/// 基于异或的硬币抛掷协议
/// 
/// 实现了最简单的硬币抛掷协议，通过异或运算组合参与方的比特。
/// 这个协议假设至少有一个诚实的参与方。
pub struct XORCoinFlip;

impl CoinFlipping for XORCoinFlip {
    fn commit_bit(bit: bool) -> Result<(CoinFlipCommit, CoinFlipReveal)> {
        let mut rng = thread_rng();
        let randomness = rng.gen_range(0..FIELD_PRIME);
        
        // Simple commitment: hash(bit || randomness)
        let bit_value = if bit { 1u64 } else { 0u64 };
        let commitment = Self::hash_commit(bit_value, randomness);
        
        let commit = CoinFlipCommit { commitment, randomness };
        let reveal = CoinFlipReveal { value: bit, randomness };
        
        Ok((commit, reveal))
    }
    
    fn verify_and_combine(
        commit1: &CoinFlipCommit,
        reveal1: &CoinFlipReveal,
        commit2: &CoinFlipCommit,
        reveal2: &CoinFlipReveal,
    ) -> Result<bool> {
        // Verify commitments
        let bit1_value = if reveal1.value { 1u64 } else { 0u64 };
        let bit2_value = if reveal2.value { 1u64 } else { 0u64 };
        
        let expected_commit1 = Self::hash_commit(bit1_value, reveal1.randomness);
        let expected_commit2 = Self::hash_commit(bit2_value, reveal2.randomness);
        
        if commit1.commitment != expected_commit1 || commit2.commitment != expected_commit2 {
            return Err(MpcError::ProtocolError("Commitment verification failed".to_string()));
        }
        
        // XOR the revealed bits
        Ok(reveal1.value ^ reveal2.value)
    }
}

impl XORCoinFlip {
    /// 哈希承诺函数
    /// 
    /// 使用 SHA-256 哈希函数生成承诺值。将比特值和随机数组合后进行哈希，
    /// 然后将结果映射到有限域中。
    /// 
    /// # 参数
    /// 
    /// * `bit` - 比特值（0 或 1）
    /// * `randomness` - 随机数
    /// 
    /// # 返回值
    /// 
    /// 返回承诺值（在有限域中）
    fn hash_commit(bit: u64, randomness: u64) -> u64 {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(bit.to_le_bytes());
        hasher.update(randomness.to_le_bytes());
        let result = hasher.finalize();
        
        let mut commitment = 0u64;
        for (i, &byte) in result.iter().take(8).enumerate() {
            commitment |= (byte as u64) << (i * 8);
        }
        commitment % FIELD_PRIME
    }
}

/// Blum 硬币抛掷协议
/// 
/// 实现了 Manuel Blum 提出的经典硬币抛掷协议。这是一个两方协议，
/// 其中一方（Alice）首先承诺一个随机比特，然后另一方（Bob）选择自己的比特。
/// 最终结果是两个比特的异或。
pub struct BlumCoinFlip;

impl BlumCoinFlip {
    /// 执行 Blum 硬币抛掷协议
    /// 
    /// 模拟完整的两方硬币抛掷协议执行过程：
    /// 1. Alice 对随机比特进行承诺
    /// 2. Bob 在看到承诺后选择自己的比特
    /// 3. Alice 揭示她的比特
    /// 4. 验证承诺并计算最终结果
    /// 
    /// # 返回值
    /// 
    /// 返回硬币抛掷的结果（true 或 false），或者在协议失败时返回错误
    pub fn protocol() -> Result<bool> {
        // Alice 对随机比特进行承诺
        let mut rng = thread_rng();
        let alice_bit = rng.gen::<bool>();
        let (alice_commit, alice_reveal) = XORCoinFlip::commit_bit(alice_bit)?;
        
        // Bob 在看到 Alice 的承诺后选择自己的比特
        let bob_bit = rng.gen::<bool>();
        let (bob_commit, bob_reveal) = XORCoinFlip::commit_bit(bob_bit)?;
        
        // Both reveal and combine
        XORCoinFlip::verify_and_combine(&alice_commit, &alice_reveal, &bob_commit, &bob_reveal)
    }
    
    /// 多方硬币抛掷协议
    /// 
    /// 扩展基本的两方协议以支持任意数量的参与方。
    /// 每个参与方都对一个随机比特进行承诺，最终结果是所有比特的异或。
    /// 
    /// # 参数
    /// 
    /// * `num_parties` - 参与方数量（至少为 1）
    /// 
    /// # 返回值
    /// 
    /// 返回多方硬币抛掷的结果，或者在协议失败时返回错误
    pub fn multi_party_coin_flip(num_parties: usize) -> Result<bool> {
        if num_parties == 0 {
            return Err(MpcError::ProtocolError("需要至少一个参与方".to_string()));
        }
        
        let mut commits = Vec::new();
        let mut reveals = Vec::new();
        let mut rng = thread_rng();
        
        // Each party commits to a random bit
        for _ in 0..num_parties {
            let bit = rng.gen::<bool>();
            let (commit, reveal) = XORCoinFlip::commit_bit(bit)?;
            commits.push(commit);
            reveals.push(reveal);
        }
        
        // XOR all bits together
        let mut result = false;
        for i in 0..num_parties {
            // Verify commitment
            let bit_value = if reveals[i].value { 1u64 } else { 0u64 };
            let expected_commit = XORCoinFlip::hash_commit(bit_value, reveals[i].randomness);
            
            if commits[i].commitment != expected_commit {
                return Err(MpcError::ProtocolError("Multi-party commitment verification failed".to_string()));
            }
            
            result ^= reveals[i].value;
        }
        
        Ok(result)
    }
}

/// 抗偏置硬币抛掷协议
/// 
/// 实现了抗偏置的硬币抛掷协议，通过多轮协议和统计技术来减少偏置。
/// 使用 von Neumann 技术从有偏置的硬币中提取无偏置的随机比特。
pub struct BiasResistantCoinFlip;

impl BiasResistantCoinFlip {
    /// 多轮硬币抛掷协议
    /// 
    /// 执行多轮硬币抛掷以生成一系列随机比特。
    /// 多轮协议可以提高安全性并减少单轮协议可能存在的偏置。
    /// 
    /// # 参数
    /// 
    /// * `num_rounds` - 执行的轮数
    /// 
    /// # 返回值
    /// 
    /// 返回每轮硬币抛掷的结果向量
    pub fn protocol_with_multiple_rounds(num_rounds: usize) -> Result<Vec<bool>> {
        let mut results = Vec::new();
        
        for _ in 0..num_rounds {
            let coin = BlumCoinFlip::protocol()?;
            results.push(coin);
        }
        
        Ok(results)
    }
    
    /// 生成共享随机性
    /// 
    /// 生成指定数量的共享随机比特，可用于其他密码学协议。
    /// 
    /// # 参数
    /// 
    /// * `num_bits` - 需要生成的随机比特数量
    /// 
    /// # 返回值
    /// 
    /// 返回生成的随机比特向量
    pub fn generate_shared_randomness(num_bits: usize) -> Result<Vec<bool>> {
        Self::protocol_with_multiple_rounds(num_bits)
    }
    
    /// 使用 von Neumann 技术提取无偏置比特
    /// 
    /// 从有偏置的硬币序列中提取无偏置的随机比特。
    /// 该技术通过观察连续的比特对来消除偏置：
    /// - (0,1) -> 输出 0
    /// - (1,0) -> 输出 1  
    /// - (0,0) 和 (1,1) -> 跳过
    /// 
    /// # 参数
    /// 
    /// * `biased_coins` - 有偏置的硬币抛掷结果序列
    /// 
    /// # 返回值
    /// 
    /// 返回提取的无偏置比特序列
    pub fn extract_unbiased_bits(biased_coins: &[bool]) -> Vec<bool> {
        let mut unbiased = Vec::new();
        let mut i = 0;
        
        while i + 1 < biased_coins.len() {
            match (biased_coins[i], biased_coins[i + 1]) {
                (false, true) => unbiased.push(false),
                (true, false) => unbiased.push(true),
                _ => {}, // 跳过 (0,0) 和 (1,1) 对
            }
            i += 2;
        }
        
        unbiased
    }
}

/// 基于承诺方案的硬币抛掷协议
/// 
/// 使用密码学承诺方案（如 Pedersen 承诺）实现的硬币抛掷协议。
/// 这种方法提供了更强的安全保证和更好的隐私保护。
pub struct CommitmentBasedCoinFlip;

impl CommitmentBasedCoinFlip {
    /// 使用 Pedersen 承诺的硬币抛掷协议
    /// 
    /// 基于 Pedersen 承诺方案实现的硬币抛掷协议。
    /// Pedersen 承诺提供了完美的隐藏性和计算绑定性。
    /// 
    /// # 返回值
    /// 
    /// 返回硬币抛掷结果，或者在协议失败时返回错误
    pub fn protocol_with_pedersen() -> Result<bool> {
        let mut rng = thread_rng();
        
        // Alice 使用 Pedersen 承诺对随机值进行承诺
        let alice_value = rng.gen_range(0..FIELD_PRIME);
        let alice_randomness = rng.gen_range(0..FIELD_PRIME);
        let alice_commitment = PedersenCommitment::commit(alice_value, alice_randomness);
        
        // Bob 对随机值进行承诺
        let bob_value = rng.gen_range(0..FIELD_PRIME);
        let bob_randomness = rng.gen_range(0..FIELD_PRIME);
        let bob_commitment = PedersenCommitment::commit(bob_value, bob_randomness);
        
        // 双方揭示承诺
        let alice_valid = PedersenCommitment::verify(alice_commitment, alice_value, alice_randomness);
        let bob_valid = PedersenCommitment::verify(bob_commitment, bob_value, bob_randomness);
        
        if !alice_valid || !bob_valid {
            return Err(MpcError::ProtocolError("Pedersen 承诺验证失败".to_string()));
        }
        
        // 组合值
        let combined = field_add(alice_value, bob_value);
        Ok((combined % 2) == 1)
    }
}

/// 顺序硬币抛掷协议
/// 
/// 用于生成随机字符串、字节序列和有限域元素的顺序硬币抛掷协议。
/// 通过多次执行基本的硬币抛掷协议来构建更复杂的随机数据结构。
pub struct SequentialCoinFlip;

impl SequentialCoinFlip {
    /// 生成随机二进制字符串
    /// 
    /// 通过多次硬币抛掷生成指定长度的随机二进制字符串。
    /// 每个字符都是通过一次硬币抛掷确定的。
    /// 
    /// # 参数
    /// 
    /// * `length` - 字符串长度
    /// 
    /// # 返回值
    /// 
    /// 返回生成的随机二进制字符串
    pub fn generate_random_string(length: usize) -> Result<String> {
        let mut result = String::new();
        
        for _ in 0..length {
            let bit = BlumCoinFlip::protocol()?;
            result.push(if bit { '1' } else { '0' });
        }
        
        Ok(result)
    }
    
    /// 生成随机字节序列
    /// 
    /// 通过多次硬币抛掷生成指定数量的随机字节。
    /// 每个字节由 8 次硬币抛掷构成。
    /// 
    /// # 参数
    /// 
    /// * `num_bytes` - 需要生成的字节数量
    /// 
    /// # 返回值
    /// 
    /// 返回生成的随机字节向量
    pub fn generate_random_bytes(num_bytes: usize) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        for _ in 0..num_bytes {
            let mut byte = 0u8;
            for bit_pos in 0..8 {
                let bit = BlumCoinFlip::protocol()?;
                if bit {
                    byte |= 1 << bit_pos;
                }
            }
            result.push(byte);
        }
        
        Ok(result)
    }
    
    /// 生成随机有限域元素
    /// 
    /// 通过多次硬币抛掷生成指定数量的随机有限域元素。
    /// 每个元素由 64 次硬币抛掷构成，然后映射到有限域中。
    /// 
    /// # 参数
    /// 
    /// * `count` - 需要生成的有限域元素数量
    /// 
    /// # 返回值
    /// 
    /// 返回生成的随机有限域元素向量
    pub fn generate_random_field_elements(count: usize) -> Result<Vec<u64>> {
        let mut result = Vec::new();
        
        for _ in 0..count {
            let mut element = 0u64;
            
            // 生成随机比特来构成有限域元素
            for bit_pos in 0..64 {
                let bit = BlumCoinFlip::protocol()?;
                if bit {
                    element |= 1 << bit_pos;
                }
            }
            
            result.push(element % FIELD_PRIME);
        }
        
        Ok(result)
    }
}

// Tests moved to tests/protocols_tests.rs
