# MPC API 项目文档清单

本文档提供了 MPC API 项目中所有模块的中文文档完成状态清单，方便检查和验证文档覆盖情况。

## 📋 API 分类清单

### 🔐 核心密码学模块 (Core Cryptographic Modules)

#### 1. 秘密分享 (Secret Sharing)
- [ ] **模块概述** - `secret_sharing/mod.rs`
  - [ ] Shamir 秘密分享方案
  - [ ] 加法秘密分享方案
  - [ ] 门限重构算法
  - [ ] 有限域运算支持
- [ ] **核心结构体**
  - [ ] `Share` - 秘密分享结构
  - [ ] `SecretSharing` trait - 分享接口
- [ ] **主要功能**
  - [ ] `share()` - 秘密分享生成
  - [ ] `reconstruct()` - 秘密重构
  - [ ] 拉格朗日插值算法

#### 2. Beaver 三元组 (Beaver Triples)
- [ ] **模块概述** - `beaver_triples/mod.rs`
  - [ ] OLE 基础方法
  - [ ] BFV 同态加密方法
  - [ ] 可信第三方方法
  - [ ] BGW 协议方法
- [ ] **核心结构体**
  - [ ] `BeaverTriple` - 三元组结构
  - [ ] `CompleteBeaverTriple` - 完整三元组
  - [ ] `BeaverTripleGenerator` trait - 生成器接口
- [ ] **实现方案**
  - [ ] `TrustedPartyBeaverGenerator` - 可信第三方生成器
  - [ ] `BFVBeaverGenerator` - BFV 同态加密生成器
  - [ ] `OLEBeaverGenerator` - OLE 基础生成器
- [ ] **协议消息** - `protocol_messages.rs`
  - [ ] BFV 协议消息定义
  - [ ] 门限密钥生成消息
  - [ ] 同态聚合消息

#### 3. 承诺方案 (Commitment Schemes)
- [ ] **模块概述** - `commitment/mod.rs`
  - [ ] Pedersen 承诺
  - [ ] 哈希承诺
  - [ ] Merkle 树承诺
- [ ] **核心接口**
  - [ ] `CommitmentScheme` trait - 承诺方案接口
  - [ ] `commit()` - 承诺生成
  - [ ] `reveal()` - 承诺揭示
  - [ ] `verify()` - 承诺验证
- [ ] **实现方案**
  - [ ] `HashCommitment` - 哈希承诺实现
  - [ ] `MerkleTree` - Merkle 树实现

#### 4. 椭圆曲线密码学 (Elliptic Curve Cryptography)
- [ ] **模块概述** - `elliptic_curve/mod.rs`
  - [ ] Curve25519 支持
  - [ ] secp256k1 支持
  - [ ] 椭圆曲线点运算
- [ ] **核心结构体**
  - [ ] `ECPoint` - 椭圆曲线点
  - [ ] `ECParams` - 椭圆曲线参数
- [ ] **核心接口**
  - [ ] `EllipticCurve` trait - 椭圆曲线接口
  - [ ] `ECDH` trait - 密钥交换接口
  - [ ] `ECDSA` trait - 数字签名接口
- [ ] **主要功能**
  - [ ] 点加法和点倍乘
  - [ ] 标量乘法
  - [ ] 密钥对生成
  - [ ] 共享密钥计算

#### 5. 混淆电路 (Garbled Circuits)
- [ ] **模块概述** - `garbled_circuits/mod.rs`
  - [ ] 布尔电路表示
  - [ ] 电路混淆算法
  - [ ] Free-XOR 优化
- [ ] **核心结构体**
  - [ ] `Circuit` - 电路结构
  - [ ] `Gate` - 门结构
  - [ ] `Garbler` - 混淆器
  - [ ] `Evaluator` - 求值器
- [ ] **门类型支持**
  - [ ] `GateType::And` - AND 门
  - [ ] `GateType::Or` - OR 门
  - [ ] `GateType::Xor` - XOR 门
  - [ ] `GateType::Not` - NOT 门

#### 6. 同态加密 (Homomorphic Encryption)
- [ ] **模块概述** - `homomorphic_encryption/mod.rs`
  - [ ] 部分同态加密方案
  - [ ] 全同态加密方案
- [ ] **支持方案**
  - [ ] **ElGamal** - 乘法同态
  - [ ] **RSA** - 乘法同态
  - [ ] **Paillier** - 加法同态
  - [ ] **BFV** - 全同态加密
  - [ ] **BGV** - 全同态加密
- [ ] **核心功能**
  - [ ] 密钥生成
  - [ ] 加密/解密
  - [ ] 同态运算

#### 7. 不经意传输 (Oblivious Transfer)
- [ ] **模块概述** - `oblivious_transfer/mod.rs`
  - [ ] 基本 1-out-of-2 OT
  - [ ] 相关不经意传输 (COT)
  - [ ] 随机不经意传输 (ROT)
  - [ ] OT 扩展协议
- [ ] **高级协议**
  - [ ] Naor-Pinkas OT
  - [ ] 向量不经意线性求值 (VOLE)
  - [ ] 不经意线性求值 (OLE)
- [ ] **安全性质**
  - [ ] 接收方隐私保护
  - [ ] 发送方隐私保护

### 🔧 支持模块 (Supporting Modules)

#### 8. 消息认证码 (Message Authentication Codes)
- [ ] **模块概述** - `authentication/mod.rs`
  - [ ] HMAC 实现
  - [ ] GMAC 实现
  - [ ] CMAC 实现
  - [ ] Poly1305 实现
- [ ] **核心接口**
  - [ ] `MessageAuthenticationCode` trait
  - [ ] `generate()` - MAC 生成
  - [ ] `verify()` - MAC 验证

#### 9. 高级协议 (Advanced Protocols)
- [ ] **模块概述** - `protocols/mod.rs`
  - [ ] 投币协议 (Coin Flipping)
  - [ ] 安全随机数生成
- [ ] **SPDZ 协议** - `spdz/mod.rs`
  - [ ] 认证秘密分享
  - [ ] MAC 验证机制
  - [ ] 批量验证优化

#### 10. 工具模块 (Utility Modules)
- [ ] **数学工具** - `utils/math.rs`
  - [ ] 有限域运算
  - [ ] 模运算优化
  - [ ] 扩展欧几里得算法
  - [ ] 中国剩余定理
- [ ] **随机数生成** - `utils/random.rs`
  - [ ] 密码学安全随机数
  - [ ] 有限域随机元素
  - [ ] 随机多项式生成
- [ ] **序列化工具** - `utils/serialization.rs`
  - [ ] 二进制序列化
  - [ ] JSON 序列化
  - [ ] 网络传输优化
- [ ] **安全内存管理** - `utils/memory.rs`
  - [ ] `SecureBuffer` - 安全缓冲区
  - [ ] `MemoryLock` - 内存锁定
  - [ ] `StackProtector` - 栈保护
  - [ ] 安全内存清零

### 📊 文档完成统计

| 模块类别 | 已完成 | 总数 | 完成率 |
|---------|--------|------|---------|
| 核心密码学模块 | 0 | 7 | 0% |
| 支持模块 | 0 | 3 | 0% |
| **总计** | **0** | **10** | **0%** |

## 📝 文档标准

所有模块文档均遵循以下标准：

- [ ] **模块级文档** (`//!`) - 包含模块概述、核心概念、使用示例
- [ ] **函数级文档** (`///`) - 包含参数说明、返回值、错误处理
- [ ] **中文技术注释** - 算法解释、安全性分析、性能考虑
- [ ] **代码示例** - 实际使用场景和最佳实践
- [ ] **安全警告** - 潜在风险和使用注意事项

**维护状态**: ⏳ 待完成

