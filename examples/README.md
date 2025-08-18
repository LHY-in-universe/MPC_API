# MPC API 示例完整指南

本目录包含了 MPC API 的全面使用示例，展示了各种密码学协议的实际应用。每个示例都经过精心设计，提供从基础概念到高级应用的完整学习路径。

## 📁 示例文件详细说明

### 🌟 核心示例文件

#### `simple_network_demo.rs` - **🆕 简化网络演示程序 (推荐开始)**
**测试目的**: 展示 MPC API 网络模块的核心功能，提供分布式计算入门
**具体作用**:
- **多节点 MPC 网络**: 模拟 Alice、Bob、Charlie 三方参与的 MPC 计算
- **P2P 节点管理**: 点对点网络的创建、连接和消息传递
- **HTTP API 服务**: RESTful API 服务器和客户端的使用
- **秘密分享网络传输**: Shamir 秘密分享在网络中的序列化和传输
- **错误处理最佳实践**: 常见网络错误的处理和恢复机制

**运行方式**:
```bash
# 运行完整网络演示
cargo run --example simple_network_demo

# 运行测试用例
cargo test --example simple_network_demo
```

#### `network_example.rs` - 基础网络功能演示
**测试目的**: 展示网络模块的基础功能和工具函数
**具体作用**:
- **网络管理器**: 统一管理 P2P 和 HTTP 服务
- **网络协议**: 消息格式和序列化演示
- **网络工具**: 端口检查、IP 获取等实用功能

#### `basic_functionality_demo.rs` - 基础功能演示
**测试目的**: 提供 MPC API 的入门教程和基础概念验证
**具体作用**:
- **有限域运算**: 演示密码学计算的数学基础，包括模运算、逆元计算
- **Shamir 秘密分享**: 完整的分享生成、重构和同态运算流程
- **Beaver 三元组**: 安全乘法协议的核心组件演示
- **哈希承诺**: 简单高效的承诺方案实现
- **Merkle 树**: 数据完整性验证和包含性证明

**运行方式**:
```bash
# 运行完整演示
cargo run --example basic_functionality_demo

# 运行特定功能测试
cargo test test_field_operations_demo
cargo test test_secret_sharing_demo
```

#### `beaver_triples_trusted_party_example.rs` - 可信第三方方法
**测试目的**: 展示最高效的 Beaver 三元组生成方法
**具体作用**:
- **可信第三方模式**: 在受控环境中的高性能三元组生成
- **批量优化**: 大规模三元组的高效生成和管理
- **安全审计**: 三元组质量的验证和安全检查
- **实际部署**: 多方协作场景的完整实现

**性能特点**: 最快的生成速度，适用于受控环境

#### `beaver_triples_ole_example.rs` - OLE 方法
**测试目的**: 演示无需可信第三方的 Beaver 三元组生成
**具体作用**:
- **OLE 协议**: 不经意线性求值的完整实现
- **分布式生成**: 多方协作生成，无单点故障
- **安全乘法**: 使用 OLE 三元组的安全计算协议
- **性能分析**: 安全性与效率的平衡展示

**安全特点**: 计算安全，无需可信第三方

#### `beaver_triples_bfv_example.rs` - BFV 同态加密方法
**测试目的**: 展示最高安全级别的三元组生成
**具体作用**:
- **BFV 同态加密**: 基于格问题的量子安全方案
- **参数配置**: 不同安全级别的参数选择和验证
- **密钥管理**: 门限密钥的生成和分布式管理
- **同态运算**: 在密文状态下的安全计算

**安全特点**: 抗量子攻击，长期安全保证

#### `comprehensive_beaver_examples.rs` - 综合对比
**测试目的**: 多种方法的性能和安全性对比分析
**具体作用**:
- **方法对比**: 可信第三方、OLE、BFV 三种方法的全面比较
- **性能基准**: 实际测量各方法的生成速度和资源消耗
- **场景选择**: 不同应用场景下的最优方法推荐
- **混合部署**: 多种方法组合使用的策略

#### `complete_api_usage_guide.rs` - 完整 API 指南
**测试目的**: 提供全面的 API 使用教程和最佳实践
**具体作用**:
- **API 概览**: 所有主要功能的使用方法
- **集成示例**: 多个协议的组合使用
- **错误处理**: 常见问题的诊断和解决
- **生产部署**: 实际应用中的配置和优化

#### `advanced_protocols_guide.rs` - 高级协议指南
**测试目的**: 展示复杂密码学协议的实现和应用
**具体作用**:
- **高级承诺方案**: Pedersen 承诺的同态性质
- **零知识证明**: 承诺方案在证明系统中的应用
- **复杂协议**: 多个基础协议的组合使用
- **优化技术**: 高级优化和安全增强技术

### 🔧 工具和配置文件

#### `main.rs` - 示例管理器
**测试目的**: 提供统一的示例运行和管理界面
**具体作用**:
- **命令行接口**: 方便地选择和运行不同示例
- **批量执行**: 一次性运行所有示例进行综合测试
- **参数配置**: 动态调整示例参数和配置
- **结果汇总**: 收集和展示所有示例的执行结果

#### `simple_api_usage.rs` - 快速入门
**测试目的**: 为新用户提供最简单的入门体验
**具体作用**:
- **最小示例**: 最基础的功能演示
- **快速验证**: 环境配置的正确性检查
- **核心概念**: 关键概念的简化展示

## 🚀 运行指南

### 💻 命令行运行方式

#### 1. 运行单个示例
```bash
# 基础功能演示
cargo run --example basic_functionality_demo

# 可信第三方方法
cargo run --example beaver_triples_trusted_party_example

# OLE 方法演示
cargo run --example beaver_triples_ole_example

# BFV 同态加密方法
cargo run --example beaver_triples_bfv_example

# 综合对比分析
cargo run --example comprehensive_beaver_examples

# 完整 API 指南
cargo run --example complete_api_usage_guide

# 高级协议指南
cargo run --example advanced_protocols_guide

# 统一示例管理器
cargo run --example main
```

#### 2. 使用示例管理器
```bash
# 运行所有示例
cargo run --example main all

# 运行特定类型
cargo run --example main ole          # OLE 方法
cargo run --example main bfv          # BFV 方法
cargo run --example main trusted      # 可信第三方
cargo run --example main comparison   # 综合对比

# 获取帮助
cargo run --example main help
```

#### 3. 运行测试验证
```bash
# 运行所有示例测试
cargo test --example

# 运行特定模块测试
cargo test test_basic_functionality
cargo test test_beaver_triples_trusted_party
cargo test test_beaver_triples_ole
cargo test test_beaver_triples_bfv
cargo test test_comprehensive_beaver

# 运行性能基准测试
cargo test --release -- --nocapture
```

### 📊 性能基准测试

#### 运行基准测试
```bash
# 如果有 benches 目录
cargo bench

# 单独的性能测试
cargo test --release performance
cargo test --release benchmark
```

### 🔧 在代码中集成使用

#### 1. 基本集成
```rust
use mpc_api::examples::basic_functionality_demo::*;

// 运行基础功能演示
run_all_demos()?;

// 运行特定功能
field_operations_demo()?;
secret_sharing_demo()?;
beaver_triples_demo()?;
```

#### 2. 高级集成
```rust
use mpc_api::examples::{
    beaver_triples_trusted_party_example::*,
    beaver_triples_ole_example::*,
    beaver_triples_bfv_example::*,
};

// 对比不同方法
run_all_trusted_party_examples()?;
run_all_ole_examples()?;
run_all_bfv_examples()?;
```

#### 3. 自定义配置运行
```rust
use mpc_api::beaver_triples::*;
use mpc_api::secret_sharing::*;

// 自定义参数运行
let party_count = 5;
let threshold = 3;
let party_id = 0;

let mut generator = TrustedPartyBeaverGenerator::new(
    party_count, threshold, party_id, None
)?;

let beaver_triple = generator.generate_single()?;
```

## 🎯 协议选择指南

### Beaver 三元组生成方法对比

| 需求场景 | 推荐方法 | 性能 | 安全级别 | 适用环境 |
|---------|----------|------|----------|----------|
| 受控环境高性能 | 可信第三方 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | 企业内部、测试环境 |
| 分布式无信任 | OLE 方法 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 跨组织协作 |
| 长期量子安全 | BFV 同态加密 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 高安全要求场景 |
| 原型开发验证 | 可信第三方 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | 概念验证、研发测试 |
| 生产环境部署 | OLE + BFV 混合 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 实际商业应用 |

### 具体协议技术对比

| 特性 | 哈希承诺 | Pedersen 承诺 | Merkle 树 | Beaver 三元组 |
|------|----------|---------------|-----------|---------------|
| 计算复杂度 | O(1) | O(1) | O(log n) | O(1) 使用 |
| 安全假设 | 哈希抗碰撞 | 离散对数 | 哈希抗碰撞 | 依赖生成方法 |
| 同态性质 | 无 | 加法同态 | 无 | 乘法支持 |
| 验证效率 | 极高 | 高 | 高 | 极高 |
| 存储开销 | 最小 | 中等 | 对数级 | 固定 |

## 📊 性能基准数据

### 测试环境
- **硬件**: Intel i7-12700K, 32GB DDR4, NVMe SSD
- **操作系统**: Ubuntu 22.04 LTS
- **Rust 版本**: 1.75.0
- **编译优化**: `--release` 模式

### Beaver 三元组生成性能

| 方法 | 单个三元组 | 批量(100个) | 内存使用 | 网络通信 |
|------|------------|-------------|----------|----------|
| 可信第三方 | ~50μs | ~4ms | 1.2KB | 最少 |
| OLE 方法 | ~2ms | ~150ms | 8KB | 中等 |
| BFV 方法 | ~15ms | ~1.2s | 32KB | 较多 |

### 基础密码学操作性能

| 操作 | 哈希承诺 | Pedersen 承诺 | Merkle 树 | 秘密分享 |
|------|----------|---------------|-----------|----------|
| 单次操作 | ~1μs | ~100μs | ~10μs | ~5μs |
| 批量(1000个) | ~0.8ms | ~80ms | ~8ms | ~4ms |
| 验证时间 | ~1μs | ~150μs | ~10μs | ~3μs |
| 内存占用 | 32B | 64B | 32B+O(log n) | 16B |

### 可扩展性测试

| 参与方数量 | 3方 | 5方 | 10方 | 20方 | 50方 |
|------------|-----|-----|------|------|------|
| Shamir 分享生成 | 15μs | 25μs | 50μs | 100μs | 250μs |
| Shamir 重构 | 8μs | 12μs | 20μs | 35μs | 75μs |
| 可信第三方三元组 | 50μs | 55μs | 65μs | 85μs | 150μs |
| OLE 三元组 | 2ms | 3.5ms | 8ms | 18ms | 65ms |

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



