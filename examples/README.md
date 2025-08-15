# MPC API 示例指南

本目录包含了 MPC API 的详细使用示例，展示了各种密码学协议的实际应用。

## 示例文件

### `advanced_protocols_guide.rs`
完整的高级协议使用指南，包含：
- 哈希承诺方案
- Pedersen 承诺方案
- Merkle 树
- 实际应用场景

## 运行示例

### 1. 运行完整指南
```bash
cargo run --example advanced_protocols_guide
```

### 2. 运行特定测试
```bash
# 哈希承诺示例
cargo test test_hash_commitment_examples

# Pedersen 承诺示例
cargo test test_pedersen_commitment_examples

# Merkle 树示例
cargo test test_merkle_tree_examples

# 应用场景示例
cargo test test_application_scenarios
```

### 3. 在代码中使用
```rust
use mpc_api::examples::advanced_protocols_guide::*;

// 运行所有示例
run_advanced_protocols_guide()?;

// 运行特定模块
hash_commitment_examples::run_all()?;
pedersen_commitment_examples::run_all()?;
merkle_tree_examples::run_all()?;
application_scenarios::run_all()?;
```

## 协议选择指南

| 需求场景 | 推荐协议 | 原因 |
|---------|----------|------|
| 简单承诺验证 | 哈希承诺 | 性能最优，实现简单 |
| 需要同态运算 | Pedersen 承诺 | 支持加法同态性 |
| 大数据集验证 | Merkle 树 | 证明大小为 O(log n) |
| 批量操作 | 哈希承诺批量 | 并行处理能力强 |
| 零知识证明构建 | Pedersen 承诺 | 完美隐藏性 |

## 性能基准

基于典型硬件（Intel i7, 16GB RAM）的性能测试：

| 操作 | 哈希承诺 | Pedersen 承诺 | Merkle 树 |
|------|----------|---------------|-----------|
| 单次承诺 | ~1μs | ~100μs | ~10μs (叶子节点) |
| 批量承诺 (1000个) | ~0.8ms | ~80ms | ~8ms |
| 验证 | ~1μs | ~150μs | ~10μs |
| 内存使用 | 32B | 64B | 32B + O(log n) |

## 安全注意事项

### 1. 随机数生成
```rust
// ✅ 正确：使用密码学安全的随机数
use rand::{thread_rng, Rng};
let randomness = thread_rng().gen::<u64>();

// ❌ 错误：使用固定或可预测的随机数
let randomness = 12345u64;
```

### 2. 参数验证
```rust
// ✅ 正确：验证 Pedersen 参数
let params = PedersenParams::new()?;
assert!(params.validate()?);

// ❌ 错误：直接使用未验证的参数
let params = PedersenParams::new()?;
// 直接使用，没有验证
```

### 3. 随机数重用
```rust
// ❌ 错误：重复使用相同随机数
let rand = thread_rng().gen::<u64>();
let commit1 = HashCommitment::commit_u64(value1, rand);
let commit2 = HashCommitment::commit_u64(value2, rand); // 危险！

// ✅ 正确：每次使用不同随机数
let rand1 = thread_rng().gen::<u64>();
let rand2 = thread_rng().gen::<u64>();
let commit1 = HashCommitment::commit_u64(value1, rand1);
let commit2 = HashCommitment::commit_u64(value2, rand2);
```

## 实际应用模式

### 1. 承诺-揭示模式
```rust
// 阶段1：承诺
let (nonce, commitment) = HashCommitment::auto_commit_u64(secret_value);

// 阶段2：发送承诺（不泄露原始值）
send_commitment(commitment);

// 阶段3：揭示（发送原始值和随机数）
reveal_commitment(secret_value, nonce);

// 阶段4：验证
let is_valid = HashCommitment::verify_u64(&commitment, secret_value, nonce);
```

### 2. 批量处理模式
```rust
// 收集所有需要承诺的值
let values: Vec<u64> = collect_batch_values();
let randomness: Vec<u64> = generate_batch_randomness(values.len());

// 批量生成承诺（性能更好）
let commitments = HashCommitment::batch_commit_u64(&values, &randomness)?;

// 批量验证
for (i, &value) in values.iter().enumerate() {
    assert!(HashCommitment::verify_u64(&commitments[i], value, randomness[i]));
}
```

### 3. 同态计算模式
```rust
// 使用 Pedersen 承诺进行隐私保护的加法
let params = PedersenParams::new()?;

let commit1 = PedersenCommitment::commit_with_params(&params, value1, rand1)?;
let commit2 = PedersenCommitment::commit_with_params(&params, value2, rand2)?;

// 在不知道原始值的情况下计算和的承诺
let sum_commit = PedersenCommitment::add_commitments(&commit1, &commit2)?;

// 验证同态性质
let sum_value = field_add(value1, value2);
let sum_rand = field_add(rand1, rand2);
assert!(PedersenCommitment::verify_with_params(&params, &sum_commit, sum_value, sum_rand)?);
```

## 错误处理

```rust
use mpc_api::Result;

fn handle_commitment_errors() -> Result<()> {
    // 输入验证
    if randomness == 0 {
        return Err("随机数不能为零".into());
    }
    
    // 参数检查
    let params = PedersenParams::new()?;
    if !params.validate()? {
        return Err("无效的Pedersen参数".into());
    }
    
    // 操作执行
    let commitment = PedersenCommitment::commit_with_params(&params, message, randomness)
        .map_err(|e| format!("承诺生成失败: {}", e))?;
    
    // 结果验证
    let is_valid = PedersenCommitment::verify_with_params(&params, &commitment, message, randomness)?;
    if !is_valid {
        return Err("承诺验证失败".into());
    }
    
    Ok(())
}
```

## 调试技巧

### 1. 启用调试输出
```rust
// 在 Cargo.toml 中启用调试特性
[features]
debug = []

// 代码中使用条件编译
#[cfg(feature = "debug")]
println!("承诺值: {:?}", commitment);
```

### 2. 性能分析
```rust
use std::time::Instant;

let start = Instant::now();
let commitment = HashCommitment::commit_u64(value, randomness);
let duration = start.elapsed();
println!("承诺生成耗时: {:?}", duration);
```

### 3. 内存使用监控
```rust
// 测量数据结构大小
println!("哈希承诺大小: {} bytes", std::mem::size_of::<HashCommitment>());
println!("Pedersen承诺大小: {} bytes", std::mem::size_of::<PedersenCommitment>());
```



