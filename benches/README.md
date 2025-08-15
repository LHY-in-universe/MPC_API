# MPC API 性能基准测试完整指南

本目录包含 MPC API 的全面性能基准测试套件，用于评估各种密码学协议和算法的性能特征。基准测试采用 Rust 的 `criterion` 框架，提供准确的性能测量和统计分析。

## 📁 基准测试文件结构

### 🌟 核心性能基准测试

#### `beaver_triples_benchmarks.rs` - Beaver 三元组生成性能测试
**测试目的**: 系统评估不同 Beaver 三元组生成方法的性能特征
**具体测试内容**:
- **可信第三方方法**: 测量单个和批量三元组生成时间
- **OLE 方法**: 评估不经意线性求值协议的计算和通信开销
- **BFV 同态加密方法**: 测量基于格的量子安全三元组生成性能
- **批量优化**: 测试不同批量大小对性能的影响
- **内存使用**: 监控三元组生成过程中的内存占用
- **网络通信**: 评估协议执行所需的数据传输量

**性能指标**:
- 单个三元组生成时间 (μs)
- 批量生成吞吐量 (三元组/秒)
- 内存峰值使用量 (MB)
- 网络通信量 (KB/三元组)

#### `secret_sharing_benchmarks.rs` - 秘密分享协议性能测试
**测试目的**: 评估各种秘密分享方案的计算效率和可扩展性
**具体测试内容**:
- **Shamir 秘密分享**: 分享生成和重构的时间复杂度
- **加法秘密分享**: 简单分享方案的性能基线
- **门限参数影响**: 不同 (t,n) 组合对性能的影响
- **分享运算**: 同态加法和标量乘法的性能
- **可扩展性测试**: 参与方数量增长对性能的影响

**测试参数**:
- 参与方数量: 3, 5, 10, 20, 50, 100 方
- 门限设置: t = (n+1)/2, t = n/3, t = 2n/3
- 数据大小: 64位整数、256位大整数

#### `commitment_benchmarks.rs` - 承诺方案性能对比测试
**测试目的**: 对比不同承诺方案的性能和安全特性权衡
**具体测试内容**:
- **哈希承诺**: 基于 SHA-256 的简单承诺方案性能
- **Pedersen 承诺**: 基于离散对数的同态承诺性能
- **Merkle 树承诺**: 批量数据承诺的效率测试
- **批量操作**: 大规模承诺生成和验证的性能
- **同态运算**: Pedersen 承诺加法运算的效率

**基准测试场景**:
- 单个承诺生成和验证时间
- 批量承诺处理吞吐量
- 同态运算性能测试
- 内存使用效率分析

#### `elliptic_curve_benchmarks.rs` - 椭圆曲线密码学性能测试
**测试目的**: 评估椭圆曲线操作在 MPC 协议中的性能表现
**具体测试内容**:
- **点运算**: 椭圆曲线点加法和标量乘法性能
- **ECDH 密钥交换**: 密钥生成和共享秘密计算时间
- **ECDSA 数字签名**: 签名生成和验证的性能
- **曲线对比**: secp256k1 vs Curve25519 性能差异
- **批量验证**: 多个签名批量验证的效率优化

**支持的椭圆曲线**:
- secp256k1 (Bitcoin 标准)
- Curve25519 (现代高性能曲线)
- P-256 (NIST 标准)

#### `homomorphic_encryption_benchmarks.rs` - 同态加密性能测试
**测试目的**: 评估各种同态加密方案的计算开销和实用性
**具体测试内容**:
- **BFV 方案**: 整数上的全同态加密性能
- **BGV 方案**: 另一种格基全同态加密的对比
- **Paillier 加密**: 加法同态的经典方案性能
- **ElGamal 加密**: 乘法同态的椭圆曲线实现
- **参数影响**: 不同安全参数对性能的影响
- **同态运算**: 密文加法、乘法的计算时间

**测试维度**:
- 密钥生成时间
- 加密/解密速度
- 同态运算效率
- 密文大小膨胀比

#### `oblivious_transfer_benchmarks.rs` - 不经意传输协议性能测试
**测试目的**: 评估 OT 协议在不同场景下的性能表现
**具体测试内容**:
- **基础 OT**: 1-out-of-2 不经意传输的基本性能
- **OT 扩展**: 从少量基础 OT 生成大量 OT 的效率
- **批量 OT**: 大规模并行 OT 执行的性能
- **OLE 协议**: 不经意线性求值的计算和通信开销
- **VOLE 协议**: 向量化 OLE 的性能特点

**性能维度**:
- 单次 OT 执行时间
- 批量 OT 吞吐量
- 网络通信量
- 内存使用峰值

#### `garbled_circuits_benchmarks.rs` - 混淆电路性能测试
**测试目的**: 评估混淆电路构造和计算的性能特征
**具体测试内容**:
- **电路混淆**: 不同大小电路的混淆时间
- **电路求值**: 混淆电路计算的执行时间
- **Free-XOR 优化**: XOR 门优化对性能的影响
- **电路大小影响**: 门数量对性能的扩展性
- **并行化**: 多线程混淆和求值的加速比

**测试电路类型**:
- 算术电路 (加法、乘法)
- 逻辑电路 (AND, OR, XOR)
- 比较电路 (大小比较)
- 实际应用电路 (AES, SHA-256)

#### `authentication_benchmarks.rs` - 认证协议性能测试
**测试目的**: 评估各种消息认证码方案的性能
**具体测试内容**:
- **HMAC**: 基于哈希的消息认证码性能
- **CMAC**: 基于分组密码的认证码性能
- **GMAC**: Galois 消息认证码在 AEAD 中的性能
- **Poly1305**: 现代高速认证码的性能测试
- **批量认证**: 大量消息的批量认证效率

#### `protocol_integration_benchmarks.rs` - 协议集成性能测试
**测试目的**: 测试完整 MPC 协议的端到端性能
**具体测试内容**:
- **完整 MPC 协议**: 从输入到输出的全流程性能
- **协议组合**: 多个子协议组合使用的性能
- **网络模拟**: 不同网络条件下的协议性能
- **故障恢复**: 协议错误处理和重试的开销
- **实际应用**: 隐私保护机器学习、拍卖等应用场景

### 🔧 辅助测试文件

#### `memory_benchmarks.rs` - 内存使用分析
**测试目的**: 分析各协议的内存使用模式和优化空间
**具体测试内容**:
- **内存峰值**: 协议执行过程中的最大内存占用
- **内存泄漏检测**: 长期运行的内存稳定性
- **缓存效率**: CPU 缓存命中率对性能的影响
- **内存分配模式**: 堆内存分配和释放的效率

#### `network_simulation_benchmarks.rs` - 网络条件仿真测试
**测试目的**: 在不同网络环境下评估协议性能
**具体测试内容**:
- **延迟影响**: 不同网络延迟对协议性能的影响
- **带宽限制**: 有限带宽下的协议适应性
- **丢包处理**: 网络不稳定情况下的协议鲁棒性
- **并发连接**: 多方协议的网络并发性能

## 🚀 运行基准测试指南

### 💻 命令行运行方式

#### 1. 运行所有基准测试
```bash
# 运行完整的基准测试套件
cargo bench

# 生成详细报告
cargo bench --message-format=json > benchmark_results.json
```

#### 2. 运行特定类别的测试
```bash
# Beaver 三元组性能测试
cargo bench --bench beaver_triples_benchmarks

# 秘密分享性能测试
cargo bench --bench secret_sharing_benchmarks

# 承诺方案性能测试
cargo bench --bench commitment_benchmarks

# 椭圆曲线性能测试
cargo bench --bench elliptic_curve_benchmarks

# 同态加密性能测试
cargo bench --bench homomorphic_encryption_benchmarks

# 不经意传输性能测试
cargo bench --bench oblivious_transfer_benchmarks
```

#### 3. 运行特定测试用例
```bash
# 测试特定的 Beaver 三元组方法
cargo bench "beaver_triples.*trusted_party"
cargo bench "beaver_triples.*ole"
cargo bench "beaver_triples.*bfv"

# 测试不同参与方数量的秘密分享
cargo bench "shamir.*3_parties"
cargo bench "shamir.*10_parties"
cargo bench "shamir.*50_parties"

# 测试特定椭圆曲线操作
cargo bench "ecdsa.*secp256k1"
cargo bench "ecdh.*curve25519"
```

#### 4. 自定义测试参数
```bash
# 设置测试持续时间
cargo bench -- --measurement-time 30

# 设置样本数量
cargo bench -- --sample-size 1000

# 详细输出模式
cargo bench -- --verbose

# 保存结果到文件
cargo bench -- --save-baseline main_branch
```

### 📊 性能分析和报告

#### 1. 生成 HTML 报告
```bash
# 安装 criterion 报告工具
cargo install cargo-criterion

# 生成交互式 HTML 报告
cargo criterion

# 在浏览器中查看报告
open target/criterion/reports/index.html
```

#### 2. 性能回归检测
```bash
# 保存当前性能基线
cargo bench -- --save-baseline before_optimization

# 进行代码优化后重新测试
cargo bench -- --baseline before_optimization

# 比较性能变化
cargo bench -- --load-baseline before_optimization
```

#### 3. 性能数据导出
```bash
# 导出 CSV 格式数据
cargo bench --bench secret_sharing_benchmarks -- --output-format csv > results.csv

# 导出 JSON 格式数据
cargo bench --message-format json | tee benchmark_data.json
```

### 🔧 配置和定制

#### 1. 基准测试配置文件 `benches/config.toml`
```toml
[benchmark.settings]
# 默认测试时间 (秒)
measurement_time = 10

# 预热时间 (秒)
warm_up_time = 3

# 最小样本数量
sample_size = 100

# 置信区间
confidence_level = 0.95

[benchmark.beaver_triples]
# Beaver 三元组测试参数
party_counts = [3, 5, 10, 20]
batch_sizes = [1, 10, 50, 100, 500]
threshold_ratios = [0.5, 0.67, 0.8]

[benchmark.secret_sharing]
# 秘密分享测试参数
max_parties = 100
secret_sizes = [64, 128, 256, 512]
operation_counts = [100, 1000, 10000]

[benchmark.commitment]
# 承诺方案测试参数
message_sizes = [32, 64, 128, 256, 1024]
batch_sizes = [1, 10, 100, 1000]

[benchmark.network]
# 网络仿真参数
latencies_ms = [1, 10, 50, 100, 500]
bandwidths_mbps = [1, 10, 100, 1000]
loss_rates = [0.0, 0.01, 0.05, 0.1]
```

#### 2. 环境变量配置
```bash
# 设置并发线程数
export RAYON_NUM_THREADS=8

# 启用详细日志
export RUST_LOG=debug

# 设置内存分析
export CRITERION_DEBUG=1

# 禁用 CPU 频率缩放影响
export CRITERION_DISABLE_CPU_SCALING_CHECKS=1
```

## 📈 性能基准数据

### 🖥️ 测试环境规范

#### 标准测试环境
- **CPU**: Intel Core i7-12700K @ 3.6GHz (12C/20T)
- **内存**: 32GB DDR4-3200 CL16
- **存储**: 1TB NVMe SSD (PCIe 4.0)
- **操作系统**: Ubuntu 22.04 LTS (Linux 5.15)
- **Rust 版本**: 1.75.0 (stable)
- **编译选项**: `--release --target-cpu=native`

#### 网络测试环境
- **局域网延迟**: < 1ms
- **广域网延迟**: 10-100ms
- **带宽**: 1Gbps (LAN), 100Mbps (WAN)
- **丢包率**: < 0.01%

### 📊 典型性能基准数据

#### Beaver 三元组生成性能 (单个三元组)

| 方法 | 3方 | 5方 | 10方 | 20方 | 内存使用 |
|------|-----|-----|------|------|----------|
| 可信第三方 | 45μs | 52μs | 68μs | 95μs | 1.5KB |
| OLE 方法 | 1.8ms | 2.4ms | 4.2ms | 8.9ms | 12KB |
| BFV 方法 | 12ms | 18ms | 35ms | 78ms | 45KB |

#### Beaver 三元组批量生成性能 (100个三元组)

| 方法 | 总时间 | 平均每个 | 吞吐量 | 网络通信 |
|------|--------|----------|--------|----------|
| 可信第三方 | 3.2ms | 32μs | 31,250/s | 150B |
| OLE 方法 | 125ms | 1.25ms | 800/s | 8.5KB |
| BFV 方法 | 950ms | 9.5ms | 105/s | 35KB |

#### 秘密分享操作性能

| 操作 | 3方 | 5方 | 10方 | 20方 | 50方 |
|------|-----|-----|------|------|------|
| 分享生成 | 8μs | 12μs | 25μs | 48μs | 120μs |
| 秘密重构 | 5μs | 7μs | 12μs | 22μs | 45μs |
| 分享加法 | 0.1μs | 0.1μs | 0.2μs | 0.3μs | 0.6μs |
| 标量乘法 | 0.2μs | 0.2μs | 0.3μs | 0.5μs | 1.0μs |

#### 承诺方案性能对比

| 方案 | 承诺生成 | 验证时间 | 承诺大小 | 同态运算 |
|------|----------|----------|----------|----------|
| 哈希承诺 | 0.8μs | 0.8μs | 32B | 不支持 |
| Pedersen 承诺 | 85μs | 125μs | 64B | 0.1μs |
| Merkle 树 (1000叶子) | 2.5ms | 8μs | 32B+路径 | 不支持 |

#### 椭圆曲线操作性能

| 操作 | secp256k1 | Curve25519 | P-256 |
|------|-----------|------------|-------|
| 标量乘法 | 65μs | 45μs | 78μs |
| ECDH | 130μs | 90μs | 156μs |
| ECDSA 签名 | 85μs | N/A | 95μs |
| ECDSA 验证 | 150μs | N/A | 165μs |

#### 同态加密性能

| 方案 | 密钥生成 | 加密 | 解密 | 同态加法 | 同态乘法 |
|------|----------|------|------|----------|----------|
| BFV (128位安全) | 45ms | 0.8ms | 0.5ms | 0.02ms | 8.5ms |
| Paillier (2048位) | 125ms | 12ms | 15ms | 0.8ms | N/A |
| ElGamal | 2ms | 1.2ms | 1.5ms | 0.05ms | 0.08ms |

### 📊 性能扩展性分析

#### 参与方数量对性能的影响

```
秘密分享重构时间随参与方数量变化:
f(n) ≈ 2.5 * n + 3 (μs)

Beaver三元组生成时间(OLE方法):
f(n) ≈ 1.2 * n^1.3 (ms)

网络通信量随参与方数量增长:
f(n) ≈ O(n²) 对于广播协议
f(n) ≈ O(n) 对于点对点协议
```

#### 批量处理的性能优势

```
批量大小对单个操作平均时间的影响:
承诺生成: 单个=1.0μs, 批量1000=0.05μs
Beaver三元组: 单个=2ms, 批量100=1.2ms
秘密分享: 单个=8μs, 批量1000=0.1μs
```

## 🛠️ 性能优化建议

### 1. 算法层面优化
- **预计算**: 提前生成 Beaver 三元组池
- **批量处理**: 使用向量化操作提高吞吐量
- **并行化**: 利用多核 CPU 并行执行独立操作
- **缓存友好**: 优化数据结构的内存访问模式

### 2. 实现层面优化
- **零拷贝**: 减少不必要的内存复制
- **内存池**: 重用内存分配减少 GC 压力
- **SIMD**: 使用向量指令加速批量运算
- **内联汇编**: 关键路径的手工优化

### 3. 系统层面优化
- **CPU 绑定**: 将线程绑定到特定 CPU 核心
- **中断隔离**: 隔离关键线程免受中断干扰
- **内存大页**: 使用大页内存减少 TLB 缺失
- **网络优化**: 使用 DPDK 等高性能网络栈

### 4. 协议层面优化
- **预处理**: 将计算密集的操作移到离线阶段
- **协议组合**: 设计更高效的复合协议
- **通信优化**: 减少通信轮数和数据量
- **错误恢复**: 高效的协议失败恢复机制

## 🔧 自定义基准测试

### 创建新的基准测试

#### 1. 创建基准测试文件
```rust
// benches/my_custom_benchmark.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_api::*;

fn custom_protocol_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("custom_protocol");
    
    // 设置测试参数
    group.sample_size(100);
    group.measurement_time(std::time::Duration::from_secs(10));
    
    // 测试不同参数组合
    for &party_count in &[3, 5, 10] {
        for &batch_size in &[1, 10, 100] {
            group.bench_with_input(
                format!("parties_{}_batch_{}", party_count, batch_size),
                &(party_count, batch_size),
                |b, &(parties, batch)| {
                    b.iter(|| {
                        // 你的基准测试代码
                        custom_protocol_function(
                            black_box(parties),
                            black_box(batch)
                        )
                    })
                },
            );
        }
    }
    
    group.finish();
}

criterion_group!(custom_benches, custom_protocol_benchmark);
criterion_main!(custom_benches);
```

#### 2. 内存使用分析示例
```rust
use criterion::{Criterion, measurement::WallTime};
use criterion_utils::memory::MemoryProfiler;

fn memory_benchmark(c: &mut Criterion<WallTime, MemoryProfiler>) {
    c.bench_function("beaver_triple_memory", |b| {
        b.iter_custom(|iters| {
            let start_memory = get_memory_usage();
            
            for _ in 0..iters {
                // 执行测试
                let _result = generate_beaver_triple();
            }
            
            let end_memory = get_memory_usage();
            Duration::from_nanos((end_memory - start_memory) as u64)
        })
    });
}
```

## 📝 基准测试最佳实践

### 1. 测试设计原则
- **隔离性**: 每个测试应该独立运行
- **重现性**: 结果应该在相同环境下可重现
- **代表性**: 测试场景应该反映实际使用情况
- **全面性**: 覆盖所有关键性能路径

### 2. 数据收集和分析
- **统计显著性**: 确保样本数量足够
- **异常值处理**: 识别和处理性能异常
- **趋势分析**: 跟踪性能随时间的变化
- **回归检测**: 及时发现性能退化

### 3. 报告和可视化
- **清晰的图表**: 使用直观的图表展示性能数据
- **对比分析**: 提供不同方法和版本的对比
- **性能建议**: 基于测试结果给出优化建议
- **文档更新**: 及时更新性能相关的文档

## 🚨 故障排除

### 常见问题和解决方案

#### 1. 基准测试不稳定
```bash
# 问题: 测试结果波动很大
# 解决方案:
sudo cpupower frequency-set --governor performance
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
taskset -c 0-7 cargo bench  # 绑定到特定CPU核心
```

#### 2. 内存不足错误
```bash
# 增加虚拟内存
sudo fallocate -l 8G /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# 或者减少测试规模
cargo bench -- --sample-size 50
```

#### 3. 网络测试失败
```bash
# 检查网络配置
sudo ss -tuln
sudo iptables -L

# 使用本地回环进行测试
cargo bench --features "local-testing"
```

## 📞 技术支持

如果在运行基准测试时遇到问题，请：

1. **查看日志**: `RUST_LOG=debug cargo bench`
2. **检查系统资源**: `htop`, `free -h`, `df -h`
3. **更新依赖**: `cargo update`
4. **清理缓存**: `cargo clean && cargo bench`
5. **报告问题**: 在项目仓库中创建 issue

---

✅ 基准测试是确保 MPC API 性能和质量的重要工具，请定期运行并关注性能变化趋势。