# 秘密分享模块 API 文档

本模块实现了多种秘密分享方案，支持加法、减法、乘法以及 Beaver 乘法等运算。主要包括 Shamir 秘密分享和加法秘密分享两种方案。

## 快速开始

```rust
use mpc_api::secret_sharing::*;

// 基本使用示例
let secret = 42u64;
let threshold = 2;
let total_parties = 3;

// Shamir 秘密分享
let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
assert_eq!(reconstructed, secret);
```

## 核心概念

### 有限域运算
所有运算都在有限域 GF(p) 上进行，其中 p = 18446744069414584321。

### 支持的操作
- **加法 (+)**: 分享的同态加法
- **减法 (-)**: 分享的同态减法  
- **标量乘法**: 分享与标量的乘法
- **分享乘法**: 两个分享的乘积（度数会增加）
- **Beaver 乘法**: 使用 Beaver 三元组的安全乘法

## API 文档

### 1. Shamir 秘密分享

#### 基本操作

```rust
use mpc_api::secret_sharing::*;

// 创建分享
let secret = 100u64;
let shares = ShamirSecretSharing::share(&secret, 2, 3)?;

// 重构秘密
let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..2], 2)?;
```

#### 加法运算

```rust
// 分享两个秘密
let shares1 = ShamirSecretSharing::share(&10, 2, 3)?;
let shares2 = ShamirSecretSharing::share(&20, 2, 3)?;

// 计算和的分享
let sum_shares: Vec<Share> = shares1.iter()
    .zip(shares2.iter())
    .map(|(s1, s2)| ShamirSecretSharing::add_shares(s1, s2))
    .collect::<Result<Vec<_>>>()?;

// 重构和
let sum = ShamirSecretSharing::reconstruct(&sum_shares[0..2], 2)?;
// sum = 30
```

#### 减法运算

```rust
let shares1 = ShamirSecretSharing::share(&30, 2, 3)?;
let shares2 = ShamirSecretSharing::share(&10, 2, 3)?;

let diff_shares: Vec<Share> = shares1.iter()
    .zip(shares2.iter())
    .map(|(s1, s2)| ShamirSecretSharing::sub_shares(s1, s2))
    .collect::<Result<Vec<_>>>()?;

let diff = ShamirSecretSharing::reconstruct(&diff_shares[0..2], 2)?;
// diff = 20
```

#### 标量乘法

```rust
let shares = ShamirSecretSharing::share(&10, 2, 3)?;
let scalar = 5u64;

let scaled_shares: Vec<Share> = shares.iter()
    .map(|share| ShamirSecretSharing::scalar_mul(share, &scalar))
    .collect::<Result<Vec<_>>>()?;

let scaled = ShamirSecretSharing::reconstruct(&scaled_shares[0..2], 2)?;
// scaled = 50
```

#### 分享乘法

```rust
let shares1 = ShamirSecretSharing::share(&6, 2, 3)?;
let shares2 = ShamirSecretSharing::share(&7, 2, 3)?;

let product_shares: Vec<Share> = shares1.iter()
    .zip(shares2.iter())
    .map(|(s1, s2)| ShamirSecretSharing::mul_shares(s1, s2))
    .collect::<Result<Vec<_>>>()?;

// 注意：乘法后需要更多分享才能重构（2*threshold-1）
let product = ShamirSecretSharing::reconstruct(&product_shares, 3)?;
// product = 42
```

#### Beaver 乘法

```rust
// 生成 Beaver 三元组
let (shares_a, shares_b, shares_c) = ShamirSecretSharing::generate_beaver_triple(2, 3)?;

// 要相乘的秘密分享
let shares_x = ShamirSecretSharing::share(&6, 2, 3)?;
let shares_y = ShamirSecretSharing::share(&7, 2, 3)?;

// 计算 d = x - a, e = y - b（需要重构这些值）
let d_shares: Vec<Share> = shares_x.iter()
    .zip(shares_a.iter())
    .map(|(sx, sa)| ShamirSecretSharing::sub_shares(sx, sa))
    .collect::<Result<Vec<_>>>()?;
let d = ShamirSecretSharing::reconstruct(&d_shares[0..2], 2)?;

let e_shares: Vec<Share> = shares_y.iter()
    .zip(shares_b.iter())
    .map(|(sy, sb)| ShamirSecretSharing::sub_shares(sy, sb))
    .collect::<Result<Vec<_>>>()?;
let e = ShamirSecretSharing::reconstruct(&e_shares[0..2], 2)?;

// 执行 Beaver 乘法
let result_shares: Vec<Share> = (0..3).map(|i| {
    ShamirSecretSharing::beaver_mul(
        &shares_x[i], &shares_y[i],
        &shares_a[i], &shares_b[i], &shares_c[i],
        &d, &e
    )
}).collect::<Result<Vec<_>>>()?;

let result = ShamirSecretSharing::reconstruct(&result_shares[0..2], 2)?;
// result = 42
```

### 2. 加法秘密分享

#### 基本操作

```rust
use mpc_api::secret_sharing::*;

let scheme = AdditiveSecretSharingScheme::new();

// 创建分享（注意：加法分享需要所有分享才能重构）
let secret = 100u64;
let shares = scheme.share_additive(&secret, 3)?;

// 重构秘密
let reconstructed = scheme.reconstruct_additive(&shares)?;
```

#### 加法运算

```rust
let scheme = AdditiveSecretSharingScheme::new();

let shares1 = scheme.share_additive(&10, 3)?;
let shares2 = scheme.share_additive(&20, 3)?;

let sum_shares: Vec<AdditiveShare> = shares1.iter()
    .zip(shares2.iter())
    .map(|(s1, s2)| scheme.add_additive_shares(s1, s2))
    .collect::<Result<Vec<_>>>()?;

let sum = scheme.reconstruct_additive(&sum_shares)?;
// sum = 30
```

#### 减法运算

```rust
let shares1 = scheme.share_additive(&30, 3)?;
let shares2 = scheme.share_additive(&10, 3)?;

let diff_shares: Vec<AdditiveShare> = shares1.iter()
    .zip(shares2.iter())
    .map(|(s1, s2)| scheme.sub_additive_shares(s1, s2))
    .collect::<Result<Vec<_>>>()?;

let diff = scheme.reconstruct_additive(&diff_shares)?;
// diff = 20
```

#### 标量乘法

```rust
let shares = scheme.share_additive(&10, 3)?;
let scalar = 5u64;

let scaled_shares: Vec<AdditiveShare> = shares.iter()
    .map(|share| scheme.scalar_mul_additive(share, &scalar))
    .collect::<Result<Vec<_>>>()?;

let scaled = scheme.reconstruct_additive(&scaled_shares)?;
// scaled = 50
```

#### Beaver 乘法（推荐）

```rust
// 生成 Beaver 三元组
let (shares_a, shares_b, shares_c) = scheme.generate_beaver_triple_additive(3)?;

// 要相乘的秘密分享
let shares_x = scheme.share_additive(&6, 3)?;
let shares_y = scheme.share_additive(&7, 3)?;

// 计算 d = x - a, e = y - b
let d_shares: Vec<AdditiveShare> = shares_x.iter()
    .zip(shares_a.iter())
    .map(|(sx, sa)| scheme.sub_additive_shares(sx, sa))
    .collect::<Result<Vec<_>>>()?;
let d = scheme.reconstruct_additive(&d_shares)?;

let e_shares: Vec<AdditiveShare> = shares_y.iter()
    .zip(shares_b.iter())
    .map(|(sy, sb)| scheme.sub_additive_shares(sy, sb))
    .collect::<Result<Vec<_>>>()?;
let e = scheme.reconstruct_additive(&e_shares)?;

// 执行 Beaver 乘法
let result_shares: Vec<AdditiveShare> = (0..3).map(|i| {
    scheme.beaver_mul_additive(
        &shares_x[i], &shares_y[i],
        &shares_a[i], &shares_b[i], &shares_c[i],
        &d, &e
    )
}).collect::<Result<Vec<_>>>()?;

let result = scheme.reconstruct_additive(&result_shares)?;
// result = 42
```

## 安全性考虑

### Shamir 秘密分享
- **(t,n) 门限**: 任意 t 个分享可以重构秘密，t-1 个分享无法泄露任何信息
- **完美安全性**: 信息论安全，即使攻击者拥有无限计算能力也无法破解
- **乘法后度数增加**: 直接乘法会导致多项式度数翻倍，需要更多分享才能重构

### 加法秘密分享
- **完全门限**: 需要所有 n 个分享才能重构秘密
- **计算效率**: 分享和重构操作非常高效
- **乘法需要协议**: 不能直接进行乘法，必须使用 Beaver 三元组等协议

### Beaver 乘法
- **预处理需求**: 需要预先生成随机的 Beaver 三元组
- **通信需求**: 需要公开 d 和 e 的值
- **安全保证**: 在半诚实敌手模型下是安全的

## 错误处理

### 常见错误类型

```rust
use mpc_api::MpcError;

match result {
    Ok(value) => println!("成功: {}", value),
    Err(MpcError::InvalidThreshold) => println!("无效的门限值"),
    Err(MpcError::InsufficientShares) => println!("分享数量不足"),
    Err(MpcError::InvalidSecretShare) => println!("无效的秘密分享"),
    Err(e) => println!("其他错误: {}", e),
}
```

## 最佳实践

1. **选择合适的方案**:
   - Shamir: 适合需要门限特性的场景
   - 加法: 适合需要高效计算的场景

2. **乘法操作**:
   - 推荐使用 Beaver 乘法而不是直接乘法
   - 在预处理阶段生成足够的 Beaver 三元组

3. **错误处理**:
   - 始终检查分享的有效性
   - 确保有足够的分享进行重构

4. **性能优化**:
   - 批量处理多个操作
   - 重用 Beaver 三元组（注意安全性）

## 示例程序

```rust
use mpc_api::secret_sharing::*;

fn main() -> Result<()> {
    // 计算 (a + b) * c 的示例
    let a = 10u64;
    let b = 20u64;
    let c = 3u64;
    
    // 使用 Shamir 分享
    let shares_a = ShamirSecretSharing::share(&a, 2, 3)?;
    let shares_b = ShamirSecretSharing::share(&b, 2, 3)?;
    let shares_c = ShamirSecretSharing::share(&c, 2, 3)?;
    
    // 计算 a + b
    let sum_shares: Vec<Share> = shares_a.iter()
        .zip(shares_b.iter())
        .map(|(sa, sb)| ShamirSecretSharing::add_shares(sa, sb))
        .collect::<Result<Vec<_>>>()?;
    
    // 使用 Beaver 乘法计算 (a + b) * c
    let (beaver_a, beaver_b, beaver_c_triple) = 
        ShamirSecretSharing::generate_beaver_triple(2, 3)?;
    
    // ... 执行 Beaver 乘法协议 ...
    
    println!("计算完成！");
    Ok(())
}
```

更多示例和高级用法，请参考测试文件和模块文档。