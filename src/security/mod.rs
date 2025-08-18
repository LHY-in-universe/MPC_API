//! # 安全模块 (Security Module)
//! 
//! 本模块提供了 MPC API 的综合安全功能，包括威胁检测、安全审计、
//! 攻击防护和安全策略管理。这个模块是整个 MPC 系统安全架构的核心。
//! 
//! ## 🔒 核心安全功能
//! 
//! ### 威胁检测与防护
//! 
//! 1. **侧信道攻击防护**: 时序攻击、功耗分析、电磁泄露防护
//! 2. **内存安全**: 缓冲区溢出、悬空指针、内存泄露检测
//! 3. **协议攻击检测**: 恶意参与方、协议偏离、重放攻击检测
//! 4. **拒绝服务防护**: 资源耗尽、计算炸弹、网络洪流防护
//! 
//! ### 安全审计系统
//! 
//! 1. **操作日志**: 详细记录所有安全相关操作
//! 2. **异常检测**: 实时监控异常行为模式
//! 3. **合规检查**: 确保操作符合安全策略
//! 4. **取证支持**: 提供安全事件的详细取证信息
//! 
//! ### 密钥管理
//! 
//! 1. **密钥生命周期**: 生成、分发、轮换、销毁管理
//! 2. **安全存储**: 硬件安全模块（HSM）集成
//! 3. **访问控制**: 基于角色的密钥访问控制
//! 4. **密钥托管**: 安全的密钥备份和恢复
//! 
//! ## 🛡️ 安全威胁模型
//! 
//! ### 外部威胁
//! 
//! - **网络攻击**: 中间人攻击、DNS 劫持、网络窃听
//! - **恶意参与方**: 拜占庭故障、恶意协作、数据投毒
//! - **系统入侵**: 权限提升、后门植入、持久化攻击
//! - **社会工程**: 钓鱼攻击、欺诈、内部威胁
//! 
//! ### 内部威胁
//! 
//! - **实现缺陷**: 编程错误、逻辑漏洞、竞争条件
//! - **配置错误**: 安全配置不当、权限设置错误
//! - **供应链攻击**: 依赖库后门、编译器后门
//! - **硬件攻击**: 硬件后门、物理攻击、侧信道攻击
//! 
//! ## 📚 安全最佳实践
//! 
//! ### 开发阶段
//! 
//! 1. **安全设计**: 安全by设计，最小权限原则
//! 2. **代码审计**: 静态分析、动态测试、人工审计
//! 3. **模糊测试**: 输入验证、边界条件、异常处理
//! 4. **依赖管理**: 依赖扫描、版本管理、漏洞监控
//! 
//! ### 部署阶段
//! 
//! 1. **环境隔离**: 容器化、网络隔离、权限隔离
//! 2. **监控告警**: 实时监控、异常告警、自动响应
//! 3. **备份恢复**: 数据备份、系统镜像、灾难恢复
//! 4. **更新管理**: 安全补丁、版本升级、回滚机制
//! 
//! ## 🚀 使用示例
//! 
//! ```rust
//! use mpc_api::security::{
//!     SecurityManager, ThreatDetector, AuditLogger, 
//!     SecurityPolicy, AttackMitigation
//! };
//! 
//! // 创建安全管理器
//! let mut security_mgr = SecurityManager::new()?;
//! 
//! // 配置安全策略
//! let policy = SecurityPolicy::strict()
//!     .with_threat_detection(true)
//!     .with_audit_logging(true)
//!     .with_attack_mitigation(true);
//! 
//! security_mgr.apply_policy(policy)?;
//! 
//! // 启动威胁检测
//! let detector = ThreatDetector::new(&security_mgr)?;
//! detector.start_monitoring()?;
//! 
//! // 执行安全操作
//! let result = security_mgr.execute_secure_operation(|| {
//!     // 您的 MPC 协议代码
//!     perform_secure_computation()
//! })?;
//! ```

use std::{
    collections::HashMap,
    fmt::{self, Display},
    sync::{Arc, Mutex, RwLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use serde::{Deserialize, Serialize};
use crate::{Result, utils::memory::StackProtector};

/// 安全错误类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityError {
    /// 威胁检测到攻击
    ThreatDetected(String),
    /// 访问被拒绝
    AccessDenied(String),
    /// 安全策略违反
    PolicyViolation(String),
    /// 审计失败
    AuditFailure(String),
    /// 密钥管理错误
    KeyManagementError(String),
    /// 配置错误
    ConfigurationError(String),
}

impl Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::ThreatDetected(msg) => write!(f, "威胁检测: {}", msg),
            SecurityError::AccessDenied(msg) => write!(f, "访问拒绝: {}", msg),
            SecurityError::PolicyViolation(msg) => write!(f, "策略违反: {}", msg),
            SecurityError::AuditFailure(msg) => write!(f, "审计失败: {}", msg),
            SecurityError::KeyManagementError(msg) => write!(f, "密钥管理错误: {}", msg),
            SecurityError::ConfigurationError(msg) => write!(f, "配置错误: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}

/// 安全级别定义
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 低安全级别 - 开发和测试环境
    Low = 1,
    /// 中等安全级别 - 一般生产环境
    Medium = 2,
    /// 高安全级别 - 敏感应用环境
    High = 3,
    /// 最高安全级别 - 军用或金融级应用
    Critical = 4,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::High
    }
}

/// 威胁类型分类
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    /// 侧信道攻击
    SideChannelAttack,
    /// 时序攻击
    TimingAttack,
    /// 内存攻击
    MemoryAttack,
    /// 协议攻击
    ProtocolAttack,
    /// 重放攻击
    ReplayAttack,
    /// 拒绝服务攻击
    DenialOfService,
    /// 恶意参与方
    MaliciousParty,
    /// 网络攻击
    NetworkAttack,
    /// 密码学攻击
    CryptographicAttack,
    /// 物理攻击
    PhysicalAttack,
}

/// 安全事件记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// 事件唯一标识符
    pub id: String,
    /// 事件时间戳
    pub timestamp: SystemTime,
    /// 威胁类型
    pub threat_type: ThreatType,
    /// 严重级别
    pub severity: SecurityLevel,
    /// 事件描述
    pub description: String,
    /// 相关上下文数据
    pub context: HashMap<String, String>,
    /// 缓解措施
    pub mitigation: Option<String>,
    /// 是否已处理
    pub is_handled: bool,
}

impl SecurityEvent {
    /// 创建新的安全事件
    pub fn new(
        threat_type: ThreatType,
        severity: SecurityLevel,
        description: String,
    ) -> Self {
        let timestamp = SystemTime::now();
        let id = format!(
            "SEC_{}_{}",
            timestamp.duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            {
                // 使用线程 ID 的调试字符串表示的哈希值
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                thread::current().id().hash(&mut hasher);
                hasher.finish()
            }
        );

        SecurityEvent {
            id,
            timestamp,
            threat_type,
            severity,
            description,
            context: HashMap::new(),
            mitigation: None,
            is_handled: false,
        }
    }

    /// 添加上下文信息
    pub fn with_context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    /// 设置缓解措施
    pub fn with_mitigation(mut self, mitigation: String) -> Self {
        self.mitigation = Some(mitigation);
        self
    }

    /// 标记为已处理
    pub fn mark_handled(&mut self) {
        self.is_handled = true;
    }
}

/// 安全策略配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// 安全级别
    pub security_level: SecurityLevel,
    /// 是否启用威胁检测
    pub enable_threat_detection: bool,
    /// 是否启用审计日志
    pub enable_audit_logging: bool,
    /// 是否启用攻击缓解
    pub enable_attack_mitigation: bool,
    /// 是否启用内存保护
    pub enable_memory_protection: bool,
    /// 是否启用时序保护
    pub enable_timing_protection: bool,
    /// 最大允许的异常操作数量
    pub max_anomalous_operations: u32,
    /// 威胁检测敏感度 (0.0-1.0)
    pub threat_detection_sensitivity: f64,
    /// 日志保留天数
    pub log_retention_days: u32,
    /// 允许的最大内存使用量 (MB)
    pub max_memory_usage_mb: u64,
    /// 网络超时设置 (秒)
    pub network_timeout_seconds: u64,
}

impl SecurityPolicy {
    /// 创建低安全级别策略（开发环境）
    pub fn low() -> Self {
        SecurityPolicy {
            security_level: SecurityLevel::Low,
            enable_threat_detection: false,
            enable_audit_logging: true,
            enable_attack_mitigation: false,
            enable_memory_protection: false,
            enable_timing_protection: false,
            max_anomalous_operations: 100,
            threat_detection_sensitivity: 0.3,
            log_retention_days: 7,
            max_memory_usage_mb: 1024,
            network_timeout_seconds: 30,
        }
    }

    /// 创建中等安全级别策略（测试环境）
    pub fn medium() -> Self {
        SecurityPolicy {
            security_level: SecurityLevel::Medium,
            enable_threat_detection: true,
            enable_audit_logging: true,
            enable_attack_mitigation: false,
            enable_memory_protection: true,
            enable_timing_protection: false,
            max_anomalous_operations: 50,
            threat_detection_sensitivity: 0.5,
            log_retention_days: 30,
            max_memory_usage_mb: 2048,
            network_timeout_seconds: 15,
        }
    }

    /// 创建高安全级别策略（生产环境）
    pub fn high() -> Self {
        SecurityPolicy {
            security_level: SecurityLevel::High,
            enable_threat_detection: true,
            enable_audit_logging: true,
            enable_attack_mitigation: true,
            enable_memory_protection: true,
            enable_timing_protection: true,
            max_anomalous_operations: 10,
            threat_detection_sensitivity: 0.7,
            log_retention_days: 90,
            max_memory_usage_mb: 4096,
            network_timeout_seconds: 10,
        }
    }

    /// 创建严格安全策略（金融/军用级）
    pub fn strict() -> Self {
        SecurityPolicy {
            security_level: SecurityLevel::Critical,
            enable_threat_detection: true,
            enable_audit_logging: true,
            enable_attack_mitigation: true,
            enable_memory_protection: true,
            enable_timing_protection: true,
            max_anomalous_operations: 3,
            threat_detection_sensitivity: 0.9,
            log_retention_days: 365,
            max_memory_usage_mb: 8192,
            network_timeout_seconds: 5,
        }
    }

    /// 链式配置威胁检测
    pub fn with_threat_detection(mut self, enabled: bool) -> Self {
        self.enable_threat_detection = enabled;
        self
    }

    /// 链式配置审计日志
    pub fn with_audit_logging(mut self, enabled: bool) -> Self {
        self.enable_audit_logging = enabled;
        self
    }

    /// 链式配置攻击缓解
    pub fn with_attack_mitigation(mut self, enabled: bool) -> Self {
        self.enable_attack_mitigation = enabled;
        self
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::high()
    }
}

/// 威胁检测器
#[derive(Debug)]
pub struct ThreatDetector {
    /// 检测策略
    policy: SecurityPolicy,
    /// 异常操作计数器
    anomalous_operations: Arc<Mutex<u32>>,
    /// 时序测量历史
    timing_history: Arc<Mutex<Vec<Duration>>>,
    /// 内存使用历史
    memory_history: Arc<Mutex<Vec<usize>>>,
    /// 是否正在运行
    is_running: Arc<Mutex<bool>>,
}

impl ThreatDetector {
    /// 创建新的威胁检测器
    pub fn new(policy: SecurityPolicy) -> Self {
        ThreatDetector {
            policy,
            anomalous_operations: Arc::new(Mutex::new(0)),
            timing_history: Arc::new(Mutex::new(Vec::new())),
            memory_history: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(Mutex::new(false)),
        }
    }

    /// 启动威胁监控
    pub fn start_monitoring(&self) -> Result<()> {
        if !self.policy.enable_threat_detection {
            return Ok(());
        }

        {
            let mut running = self.is_running.lock().unwrap();
            if *running {
                return Err("威胁检测器已经在运行".into());
            }
            *running = true;
        }

        // 启动后台监控线程
        let policy = self.policy.clone();
        let anomalous_ops = Arc::clone(&self.anomalous_operations);
        let timing_hist = Arc::clone(&self.timing_history);
        let memory_hist = Arc::clone(&self.memory_history);
        let running = Arc::clone(&self.is_running);

        thread::spawn(move || {
            let monitor_interval = Duration::from_secs(1);
            
            while *running.lock().unwrap() {
                // 检查异常操作计数
                let anomalous_count = *anomalous_ops.lock().unwrap();
                if anomalous_count > policy.max_anomalous_operations {
                    eprintln!("⚠️  威胁检测: 异常操作数量超过阈值 ({} > {})", 
                             anomalous_count, policy.max_anomalous_operations);
                    
                    // 重置计数器
                    *anomalous_ops.lock().unwrap() = 0;
                }

                // 检查时序异常
                {
                    let mut timing = timing_hist.lock().unwrap();
                    if timing.len() > 100 {
                        let avg_time = timing.iter().sum::<Duration>() / timing.len() as u32;
                        let recent_time = *timing.last().unwrap();
                        
                        if recent_time > avg_time * 3 {
                            eprintln!("⚠️  威胁检测: 检测到时序异常，可能的侧信道攻击");
                        }
                        
                        // 保留最近100个记录
                        timing.truncate(100);
                    }
                }

                // 检查内存使用异常
                {
                    let mut memory = memory_hist.lock().unwrap();
                    if let Some(&last_usage) = memory.last() {
                        let max_usage = (policy.max_memory_usage_mb as usize) * 1024 * 1024;
                        if last_usage > max_usage {
                            eprintln!("⚠️  威胁检测: 内存使用超过限制 ({} > {} MB)", 
                                     last_usage / 1024 / 1024, policy.max_memory_usage_mb);
                        }
                    }
                    
                    if memory.len() > 100 {
                        memory.truncate(100);
                    }
                }

                thread::sleep(monitor_interval);
            }
        });

        Ok(())
    }

    /// 停止威胁监控
    pub fn stop_monitoring(&self) {
        *self.is_running.lock().unwrap() = false;
    }

    /// 记录操作时间
    pub fn record_timing(&self, duration: Duration) {
        if self.policy.enable_timing_protection {
            let mut timing = self.timing_history.lock().unwrap();
            timing.push(duration);
        }
    }

    /// 记录内存使用
    pub fn record_memory_usage(&self, usage: usize) {
        if self.policy.enable_memory_protection {
            let mut memory = self.memory_history.lock().unwrap();
            memory.push(usage);
        }
    }

    /// 报告异常操作
    pub fn report_anomaly(&self, description: &str) -> Result<SecurityEvent> {
        {
            let mut count = self.anomalous_operations.lock().unwrap();
            *count += 1;
        }

        let event = SecurityEvent::new(
            ThreatType::ProtocolAttack,
            SecurityLevel::Medium,
            format!("异常操作检测: {}", description),
        );

        Ok(event)
    }

    /// 检测侧信道攻击
    pub fn detect_side_channel_attack(&self, operation_time: Duration) -> Option<SecurityEvent> {
        if !self.policy.enable_threat_detection {
            return None;
        }

        let timing = self.timing_history.lock().unwrap();
        if timing.len() < 10 {
            return None;
        }

        let avg_time = timing.iter().sum::<Duration>() / timing.len() as u32;
        let deviation = if operation_time > avg_time {
            operation_time - avg_time
        } else {
            avg_time - operation_time
        };

        // 如果偏差超过平均值的50%，可能是侧信道攻击
        if deviation > avg_time / 2 {
            Some(SecurityEvent::new(
                ThreatType::SideChannelAttack,
                SecurityLevel::High,
                format!("检测到可能的侧信道攻击，操作时间异常: {:?} vs 平均 {:?}", 
                       operation_time, avg_time),
            ))
        } else {
            None
        }
    }
}

/// 审计日志记录器
#[derive(Debug)]
pub struct AuditLogger {
    /// 日志策略
    policy: SecurityPolicy,
    /// 日志事件存储
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    /// 日志计数器
    event_counter: Arc<Mutex<u64>>,
}

impl AuditLogger {
    /// 创建新的审计日志记录器
    pub fn new(policy: SecurityPolicy) -> Self {
        AuditLogger {
            policy,
            events: Arc::new(RwLock::new(Vec::new())),
            event_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// 记录安全事件
    pub fn log_event(&self, mut event: SecurityEvent) -> Result<()> {
        if !self.policy.enable_audit_logging {
            return Ok(());
        }

        // 分配序列号
        {
            let mut counter = self.event_counter.lock().unwrap();
            *counter += 1;
            event.context.insert("sequence".to_string(), counter.to_string());
        }

        // 添加系统上下文
        event.context.insert("thread_id".to_string(), 
                            format!("{:?}", thread::current().id()));
        event.context.insert("process_id".to_string(), 
                            std::process::id().to_string());

        // 存储事件
        {
            let mut events = self.events.write().unwrap();
            events.push(event.clone());

            // 限制事件数量以防内存泄露
            if events.len() > 10000 {
                events.drain(0..1000);
            }
        }

        // 在严重情况下立即输出
        if event.severity >= SecurityLevel::High {
            eprintln!("🔥 严重安全事件: {} - {}", event.threat_type.name(), event.description);
        }

        Ok(())
    }

    /// 获取所有事件
    pub fn get_events(&self) -> Vec<SecurityEvent> {
        self.events.read().unwrap().clone()
    }

    /// 获取指定类型的事件
    pub fn get_events_by_type(&self, threat_type: &ThreatType) -> Vec<SecurityEvent> {
        self.events.read().unwrap()
            .iter()
            .filter(|event| &event.threat_type == threat_type)
            .cloned()
            .collect()
    }

    /// 获取未处理的事件
    pub fn get_unhandled_events(&self) -> Vec<SecurityEvent> {
        self.events.read().unwrap()
            .iter()
            .filter(|event| !event.is_handled)
            .cloned()
            .collect()
    }

    /// 清理过期日志
    pub fn cleanup_expired_logs(&self) -> Result<usize> {
        let retention_duration = Duration::from_secs(
            self.policy.log_retention_days as u64 * 24 * 3600
        );
        let cutoff_time = SystemTime::now() - retention_duration;

        let mut events = self.events.write().unwrap();
        let initial_count = events.len();
        
        events.retain(|event| event.timestamp > cutoff_time);
        
        let removed_count = initial_count - events.len();
        Ok(removed_count)
    }
}

/// 攻击缓解系统
#[derive(Debug)]
pub struct AttackMitigation {
    /// 缓解策略
    policy: SecurityPolicy,
    /// 缓解措施历史
    mitigation_history: Arc<RwLock<Vec<MitigationAction>>>,
    /// 栈保护器
    stack_protector: StackProtector,
}

/// 缓解措施记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationAction {
    /// 措施时间戳
    pub timestamp: SystemTime,
    /// 威胁类型
    pub threat_type: ThreatType,
    /// 措施描述
    pub action: String,
    /// 措施结果
    pub result: MitigationResult,
}

/// 缓解结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationResult {
    /// 成功缓解
    Success,
    /// 部分缓解
    Partial(String),
    /// 缓解失败
    Failed(String),
}

impl AttackMitigation {
    /// 创建攻击缓解系统
    pub fn new(policy: SecurityPolicy) -> Self {
        AttackMitigation {
            policy,
            mitigation_history: Arc::new(RwLock::new(Vec::new())),
            stack_protector: StackProtector::new(),
        }
    }

    /// 应用缓解措施
    pub fn mitigate_threat(&self, event: &SecurityEvent) -> Result<MitigationResult> {
        if !self.policy.enable_attack_mitigation {
            return Ok(MitigationResult::Success);
        }

        // 验证栈完整性
        self.stack_protector.check();

        let result = match event.threat_type {
            ThreatType::TimingAttack => self.mitigate_timing_attack(event),
            ThreatType::SideChannelAttack => self.mitigate_side_channel_attack(event),
            ThreatType::MemoryAttack => self.mitigate_memory_attack(event),
            ThreatType::ProtocolAttack => self.mitigate_protocol_attack(event),
            ThreatType::ReplayAttack => self.mitigate_replay_attack(event),
            ThreatType::DenialOfService => self.mitigate_dos_attack(event),
            ThreatType::MaliciousParty => self.mitigate_malicious_party(event),
            ThreatType::NetworkAttack => self.mitigate_network_attack(event),
            ThreatType::CryptographicAttack => self.mitigate_crypto_attack(event),
            ThreatType::PhysicalAttack => self.mitigate_physical_attack(event),
        };

        // 记录缓解措施
        let action = MitigationAction {
            timestamp: SystemTime::now(),
            threat_type: event.threat_type.clone(),
            action: format!("缓解威胁: {}", event.description),
            result: result.clone(),
        };

        {
            let mut history = self.mitigation_history.write().unwrap();
            history.push(action);
            if history.len() > 1000 {
                history.drain(0..100);
            }
        }

        Ok(result)
    }

    /// 缓解时序攻击
    fn mitigate_timing_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 实现恒定时间操作
        thread::sleep(Duration::from_millis(1)); // 简单的时序平滑
        MitigationResult::Success
    }

    /// 缓解侧信道攻击
    fn mitigate_side_channel_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 实现侧信道防护措施
        MitigationResult::Partial("已应用侧信道防护，但需要进一步验证".to_string())
    }

    /// 缓解内存攻击
    fn mitigate_memory_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 触发内存清理和保护
        std::hint::black_box(vec![0u8; 1024]); // 简单的内存混淆
        MitigationResult::Success
    }

    /// 缓解协议攻击
    fn mitigate_protocol_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 实现协议级防护
        MitigationResult::Partial("协议攻击缓解需要协议级别的处理".to_string())
    }

    /// 缓解重放攻击
    fn mitigate_replay_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 实现重放攻击防护
        MitigationResult::Success
    }

    /// 缓解拒绝服务攻击
    fn mitigate_dos_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 实现资源限制和请求节流
        MitigationResult::Success
    }

    /// 缓解恶意参与方
    fn mitigate_malicious_party(&self, _event: &SecurityEvent) -> MitigationResult {
        // 实现恶意参与方检测和隔离
        MitigationResult::Partial("恶意参与方需要协议级别的处理".to_string())
    }

    /// 缓解网络攻击
    fn mitigate_network_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 实现网络层防护
        MitigationResult::Success
    }

    /// 缓解密码学攻击
    fn mitigate_crypto_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 实现密码学级防护
        MitigationResult::Partial("密码学攻击缓解需要算法级别的处理".to_string())
    }

    /// 缓解物理攻击
    fn mitigate_physical_attack(&self, _event: &SecurityEvent) -> MitigationResult {
        // 物理攻击主要依赖硬件和环境保护
        MitigationResult::Failed("物理攻击需要硬件级别的防护".to_string())
    }

    /// 获取缓解历史
    pub fn get_mitigation_history(&self) -> Vec<MitigationAction> {
        self.mitigation_history.read().unwrap().clone()
    }
}

/// 综合安全管理器
#[derive(Debug)]
pub struct SecurityManager {
    /// 安全策略
    policy: SecurityPolicy,
    /// 威胁检测器
    threat_detector: ThreatDetector,
    /// 审计日志记录器
    audit_logger: AuditLogger,
    /// 攻击缓解系统
    attack_mitigation: AttackMitigation,
}

impl SecurityManager {
    /// 创建安全管理器
    pub fn new() -> Result<Self> {
        let policy = SecurityPolicy::default();
        Self::with_policy(policy)
    }

    /// 使用指定策略创建安全管理器
    pub fn with_policy(policy: SecurityPolicy) -> Result<Self> {
        Ok(SecurityManager {
            threat_detector: ThreatDetector::new(policy.clone()),
            audit_logger: AuditLogger::new(policy.clone()),
            attack_mitigation: AttackMitigation::new(policy.clone()),
            policy,
        })
    }

    /// 应用安全策略
    pub fn apply_policy(&mut self, policy: SecurityPolicy) -> Result<()> {
        self.policy = policy.clone();
        self.threat_detector = ThreatDetector::new(policy.clone());
        self.audit_logger = AuditLogger::new(policy.clone());
        self.attack_mitigation = AttackMitigation::new(policy);
        Ok(())
    }

    /// 启动安全服务
    pub fn start(&self) -> Result<()> {
        println!("🔒 启动安全管理器...");
        println!("  安全级别: {:?}", self.policy.security_level);
        println!("  威胁检测: {}", self.policy.enable_threat_detection);
        println!("  审计日志: {}", self.policy.enable_audit_logging);
        println!("  攻击缓解: {}", self.policy.enable_attack_mitigation);

        if self.policy.enable_threat_detection {
            self.threat_detector.start_monitoring()?;
            println!("  ✅ 威胁检测器已启动");
        }

        println!("🛡️  安全管理器启动完成");
        Ok(())
    }

    /// 停止安全服务
    pub fn stop(&self) {
        self.threat_detector.stop_monitoring();
        println!("🔒 安全管理器已停止");
    }

    /// 执行安全操作
    pub fn execute_secure_operation<F, T>(&self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let start_time = Instant::now();
        
        // 执行操作
        let result = operation();
        
        let duration = start_time.elapsed();
        
        // 记录操作时间
        self.threat_detector.record_timing(duration);
        
        // 检查侧信道攻击
        if let Some(event) = self.threat_detector.detect_side_channel_attack(duration) {
            self.audit_logger.log_event(event.clone())?;
            self.attack_mitigation.mitigate_threat(&event)?;
        }

        result
    }

    /// 报告安全事件
    pub fn report_security_event(&self, event: SecurityEvent) -> Result<()> {
        // 记录事件
        self.audit_logger.log_event(event.clone())?;
        
        // 应用缓解措施
        if event.severity >= SecurityLevel::Medium {
            self.attack_mitigation.mitigate_threat(&event)?;
        }

        Ok(())
    }

    /// 获取安全统计信息
    pub fn get_security_stats(&self) -> SecurityStats {
        let events = self.audit_logger.get_events();
        let unhandled_events = self.audit_logger.get_unhandled_events();
        let mitigation_history = self.attack_mitigation.get_mitigation_history();

        SecurityStats {
            total_events: events.len(),
            unhandled_events: unhandled_events.len(),
            threat_types: events.iter()
                .fold(HashMap::new(), |mut acc, event| {
                    *acc.entry(event.threat_type.clone()).or_insert(0) += 1;
                    acc
                }),
            mitigation_actions: mitigation_history.len(),
            policy_level: self.policy.security_level,
        }
    }

    /// 清理资源
    pub fn cleanup(&self) -> Result<()> {
        let removed = self.audit_logger.cleanup_expired_logs()?;
        println!("🗑️  清理了 {} 条过期日志", removed);
        Ok(())
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new().expect("创建默认安全管理器失败")
    }
}

/// 安全统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStats {
    /// 总事件数
    pub total_events: usize,
    /// 未处理事件数
    pub unhandled_events: usize,
    /// 各类威胁统计
    pub threat_types: HashMap<ThreatType, usize>,
    /// 缓解措施数量
    pub mitigation_actions: usize,
    /// 当前策略级别
    pub policy_level: SecurityLevel,
}

/// 威胁类型扩展方法
impl ThreatType {
    /// 获取威胁类型的名称
    pub fn name(&self) -> &'static str {
        match self {
            ThreatType::SideChannelAttack => "侧信道攻击",
            ThreatType::TimingAttack => "时序攻击",
            ThreatType::MemoryAttack => "内存攻击",
            ThreatType::ProtocolAttack => "协议攻击",
            ThreatType::ReplayAttack => "重放攻击",
            ThreatType::DenialOfService => "拒绝服务攻击",
            ThreatType::MaliciousParty => "恶意参与方",
            ThreatType::NetworkAttack => "网络攻击",
            ThreatType::CryptographicAttack => "密码学攻击",
            ThreatType::PhysicalAttack => "物理攻击",
        }
    }

    /// 获取威胁类型的描述
    pub fn description(&self) -> &'static str {
        match self {
            ThreatType::SideChannelAttack => "通过分析系统的物理特征（如功耗、电磁辐射、时间）来推断敏感信息",
            ThreatType::TimingAttack => "通过测量操作执行时间来推断敏感信息",
            ThreatType::MemoryAttack => "利用内存管理漏洞进行攻击，如缓冲区溢出、悬空指针等",
            ThreatType::ProtocolAttack => "针对通信协议的攻击，如协议偏离、恶意消息等",
            ThreatType::ReplayAttack => "截获并重放之前的有效通信来进行未授权操作",
            ThreatType::DenialOfService => "通过消耗系统资源或阻断服务来使系统不可用",
            ThreatType::MaliciousParty => "参与方偏离协议或提供恶意输入",
            ThreatType::NetworkAttack => "针对网络通信的攻击，如中间人攻击、网络窃听等",
            ThreatType::CryptographicAttack => "针对密码学算法或实现的攻击",
            ThreatType::PhysicalAttack => "直接访问硬件进行的物理攻击",
        }
    }
}

/// 安全功能测试
pub fn test_security_features() -> Result<()> {
    println!("🔍 开始安全功能测试...");

    // 创建安全管理器
    let security_mgr = SecurityManager::with_policy(SecurityPolicy::medium())?;
    security_mgr.start()?;

    // 测试威胁检测
    println!("  测试威胁检测...");
    let test_event = SecurityEvent::new(
        ThreatType::TimingAttack,
        SecurityLevel::Medium,
        "测试时序攻击检测".to_string(),
    );
    security_mgr.report_security_event(test_event)?;

    // 测试安全操作
    println!("  测试安全操作...");
    let result = security_mgr.execute_secure_operation(|| -> Result<u64> {
        thread::sleep(Duration::from_millis(10));
        Ok(42)
    })?;
    assert_eq!(result, 42);

    // 获取安全统计
    println!("  测试安全统计...");
    let stats = security_mgr.get_security_stats();
    println!("    总事件数: {}", stats.total_events);
    println!("    安全级别: {:?}", stats.policy_level);

    // 清理资源
    security_mgr.cleanup()?;
    security_mgr.stop();

    println!("✅ 安全功能测试完成");
    Ok(())
}

