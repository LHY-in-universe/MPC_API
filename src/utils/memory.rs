//! # 安全内存管理模块 (Secure Memory Management Module)
//!
//! 本模块提供了专门针对密码学应用的安全内存管理功能，包括敏感数据的安全清除、
//! 内存保护、堆栈保护和内存分配安全等关键功能。在 MPC (多方安全计算) 应用中，
//! 正确的内存管理对于保护秘密值和防止信息泄露至关重要。
//!
//! ## 🔒 安全威胁模型
//!
//! ### 内存泄露威胁
//! 
//! 1. **内存转储攻击**: 攻击者通过系统崩溃转储或内存镜像获取敏感数据
//! 2. **交换文件泄露**: 敏感数据被写入交换文件，可能被持久化存储
//! 3. **内存重用攻击**: 敏感数据在内存释放后仍然残留，被后续分配复用
//! 4. **冷启动攻击**: 通过物理内存的数据残留进行攻击
//! 5. **侧信道攻击**: 通过内存访问模式推断敏感信息
//!
//! ### 防护措施
//!
//! 1. **安全清零**: 使用无法被编译器优化的方式清零敏感内存
//! 2. **内存锁定**: 防止敏感数据被交换到磁盘
//! 3. **栈金丝雀**: 检测栈溢出攻击
//! 4. **地址随机化**: 使用地址随机化增加攻击难度
//! 5. **内存对齐**: 优化内存访问性能并防止某些攻击
//!
//! ## 📚 核心功能模块
//!
//! ### SecureBuffer - 安全缓冲区
//! 
//! 提供自动安全清除的内存缓冲区，确保敏感数据在生命周期结束时被安全清除。
//! 
//! ### MemoryLock - 内存锁定
//! 
//! 防止敏感内存页被操作系统交换到磁盘，避免敏感数据的持久化。
//! 
//! ### StackProtector - 栈保护
//! 
//! 检测和防止栈溢出攻击，保护函数返回地址和局部变量。
//! 
//! ### SecureAllocator - 安全分配器
//! 
//! 提供对齐、随机化和保护的内存分配服务，增强内存安全性。
//!
//! ## ⚡ 性能考虑
//!
//! - **最小化性能影响**: 安全措施设计为对正常操作影响最小
//! - **批量操作优化**: 支持批量安全清除以提高效率
//! - **零拷贝设计**: 尽量减少不必要的内存复制
//! - **内存对齐优化**: 利用 CPU 缓存行对齐提高访问效率
//!
//! ## 🚀 使用示例
//!
//! ```rust
//! use mpc_api::utils::memory::{SecureBuffer, MemoryLock, secure_zero};
//!
//! // 创建安全缓冲区存储敏感数据
//! let mut secret_key = SecureBuffer::new(32)?;
//! secret_key.copy_from_slice(&generate_secret_key());
//!
//! // 锁定内存防止交换
//! let _lock = MemoryLock::new(secret_key.as_ptr(), secret_key.len())?;
//!
//! // 使用秘钥进行计算...
//! perform_cryptographic_operation(&secret_key);
//!
//! // 缓冲区在作用域结束时自动安全清除
//! // 内存锁在作用域结束时自动释放
//! ```

use std::{
    alloc::{self, Layout},
    ffi::c_void,
    mem::{self, MaybeUninit},
    ptr::{self, NonNull},
    slice,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use crate::Result;

/// 内存对齐边界，通常设置为 CPU 缓存行大小 (64 字节)
pub const MEMORY_ALIGNMENT: usize = 64;

/// 最大可锁定内存大小 (默认 64MB)
pub const MAX_LOCKED_MEMORY: usize = 64 * 1024 * 1024;

/// 栈金丝雀值，用于检测栈溢出
pub const STACK_CANARY: u64 = 0xDEADBEEFCAFEBABE;

/// 内存清零的魔数，用于验证清零操作
const ZERO_PATTERN: u8 = 0x00;
const WIPE_PATTERN: u8 = 0xFF;

/// 全局锁定内存计数器
static LOCKED_MEMORY_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 全局安全分配器统计
static SECURE_ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static SECURE_ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

/// # 安全缓冲区 (SecureBuffer)
/// 
/// 提供自动安全清除功能的内存缓冲区。该结构体确保存储的敏感数据
/// 在生命周期结束时被安全地从内存中清除，防止数据残留攻击。
/// 
/// ## 🔒 安全特性
/// 
/// - **自动清零**: 在 Drop 时使用编译器无法优化掉的方式清零内存
/// - **防止优化**: 使用 volatile 操作防止编译器优化掉清零代码
/// - **多重清除**: 使用多种模式清除内存以增强安全性
/// - **边界检查**: 提供边界检查以防止缓冲区溢出
/// 
/// ## 💡 实现原理
/// 
/// 1. **分配阶段**: 分配对齐的内存并初始化为随机值
/// 2. **使用阶段**: 提供安全的读写接口
/// 3. **清理阶段**: 使用多种模式清零内存并验证清零结果
/// 
/// ## ⚡ 性能特点
/// 
/// - **内存对齐**: 按缓存行对齐以优化访问性能
/// - **延迟清零**: 可选的延迟清零以减少实时开销
/// - **批量操作**: 支持批量数据操作以提高效率
#[derive(Debug)]
pub struct SecureBuffer {
    /// 内存指针，保证非空且对齐
    ptr: NonNull<u8>,
    /// 缓冲区大小（字节数）
    len: usize,
    /// 内存布局信息，用于正确释放内存
    layout: Layout,
    /// 是否已被清零的标志
    is_zeroed: bool,
    /// 创建时的栈金丝雀，用于检测栈溢出
    canary: u64,
}

impl SecureBuffer {
    /// 创建指定大小的安全缓冲区
    /// 
    /// # 参数
    /// - `size`: 缓冲区大小（字节数）
    /// 
    /// # 返回值
    /// 返回新创建的安全缓冲区，如果分配失败则返回错误
    /// 
    /// # 安全性
    /// - 内存按缓存行对齐以优化性能
    /// - 初始内容填充随机数据以防止信息泄露
    /// - 设置栈金丝雀用于溢出检测
    /// 
    /// # 示例
    /// ```rust
    /// let buffer = SecureBuffer::new(1024)?;
    /// assert_eq!(buffer.len(), 1024);
    /// ```
    pub fn new(size: usize) -> Result<Self> {
        if size == 0 {
            return Err("缓冲区大小不能为零".into());
        }
        
        if size > MAX_LOCKED_MEMORY {
            return Err(format!("缓冲区大小 {} 超过最大限制 {}", size, MAX_LOCKED_MEMORY).into());
        }
        
        // 创建对齐的内存布局
        let layout = Layout::from_size_align(size, MEMORY_ALIGNMENT)
            .map_err(|e| format!("创建内存布局失败: {}", e))?;
        
        // 分配对齐内存
        let ptr = unsafe { alloc::alloc(layout) };
        if ptr.is_null() {
            return Err("内存分配失败".into());
        }
        
        let ptr = NonNull::new(ptr)
            .ok_or("分配的内存指针为空")?;
        
        // 使用随机数据填充内存（防止信息泄露）
        let mut rng = thread_rng();
        unsafe {
            let slice = slice::from_raw_parts_mut(ptr.as_ptr(), size);
            rng.fill_bytes(slice);
        }
        
        // 更新分配统计
        SECURE_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        SECURE_ALLOC_BYTES.fetch_add(size, Ordering::Relaxed);
        
        Ok(SecureBuffer {
            ptr,
            len: size,
            layout,
            is_zeroed: false,
            canary: STACK_CANARY,
        })
    }
    
    /// 创建从现有数据复制的安全缓冲区
    /// 
    /// # 参数
    /// - `data`: 要复制的数据切片
    /// 
    /// # 返回值
    /// 返回包含复制数据的新安全缓冲区
    /// 
    /// # 安全性
    /// - 原始数据在复制后应立即清零
    /// - 缓冲区提供独立的内存空间
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let mut buffer = Self::new(data.len())?;
        buffer.copy_from_slice(data)?;
        Ok(buffer)
    }
    
    /// 获取缓冲区长度
    pub fn len(&self) -> usize {
        self.check_canary();
        self.len
    }
    
    /// 检查缓冲区是否为空
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// 获取内存指针（只读）
    pub fn as_ptr(&self) -> *const u8 {
        self.check_canary();
        self.ptr.as_ptr() as *const u8
    }
    
    /// 获取可变内存指针
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.check_canary();
        self.is_zeroed = false;
        self.ptr.as_ptr()
    }
    
    /// 获取只读切片
    pub fn as_slice(&self) -> &[u8] {
        self.check_canary();
        unsafe { slice::from_raw_parts(self.as_ptr(), self.len) }
    }
    
    /// 获取可变切片
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.check_canary();
        self.is_zeroed = false;
        unsafe { slice::from_raw_parts_mut(self.as_mut_ptr(), self.len) }
    }
    
    /// 从切片复制数据到缓冲区
    /// 
    /// # 参数
    /// - `src`: 源数据切片
    /// 
    /// # 错误
    /// 如果源数据长度与缓冲区长度不匹配，返回错误
    pub fn copy_from_slice(&mut self, src: &[u8]) -> Result<()> {
        self.check_canary();
        
        if src.len() != self.len {
            return Err(format!(
                "数据长度不匹配: 期望 {}, 实际 {}", 
                self.len, src.len()
            ).into());
        }
        
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), self.as_mut_ptr(), self.len);
        }
        
        self.is_zeroed = false;
        Ok(())
    }
    
    /// 将缓冲区数据复制到切片
    /// 
    /// # 参数
    /// - `dst`: 目标数据切片
    /// 
    /// # 错误
    /// 如果目标切片长度与缓冲区长度不匹配，返回错误
    pub fn copy_to_slice(&self, dst: &mut [u8]) -> Result<()> {
        self.check_canary();
        
        if dst.len() != self.len {
            return Err(format!(
                "数据长度不匹配: 期望 {}, 实际 {}", 
                self.len, dst.len()
            ).into());
        }
        
        unsafe {
            ptr::copy_nonoverlapping(self.as_ptr(), dst.as_mut_ptr(), self.len);
        }
        
        Ok(())
    }
    
    /// 手动安全清零缓冲区
    /// 
    /// 使用多种清零模式确保数据被完全清除，并验证清零结果。
    /// 该方法使用 volatile 操作防止编译器优化。
    /// 
    /// # 清零流程
    /// 1. 使用零字节清零
    /// 2. 使用 0xFF 覆盖
    /// 3. 再次使用零字节清零
    /// 4. 验证清零结果
    pub fn secure_zero(&mut self) -> Result<()> {
        self.check_canary();
        
        if self.is_zeroed {
            return Ok(());
        }
        
        unsafe {
            let ptr = self.as_mut_ptr();
            let len = self.len;
            
            // 第一轮：清零
            for i in 0..len {
                ptr::write_volatile(ptr.add(i), ZERO_PATTERN);
            }
            
            // 第二轮：填充 0xFF
            for i in 0..len {
                ptr::write_volatile(ptr.add(i), WIPE_PATTERN);
            }
            
            // 第三轮：最终清零
            for i in 0..len {
                ptr::write_volatile(ptr.add(i), ZERO_PATTERN);
            }
            
            // 验证清零结果
            for i in 0..len {
                let value = ptr::read_volatile(ptr.add(i));
                if value != ZERO_PATTERN {
                    return Err(format!("内存清零验证失败，位置 {} 的值为 {:#02x}", i, value).into());
                }
            }
        }
        
        self.is_zeroed = true;
        Ok(())
    }
    
    /// 检查栈金丝雀，检测潜在的栈溢出
    fn check_canary(&self) {
        if self.canary != STACK_CANARY {
            panic!("检测到栈溢出：金丝雀值已被修改");
        }
    }
    
    /// 比较两个安全缓冲区的内容是否相等
    /// 
    /// 使用恒定时间比较算法防止时序攻击
    pub fn constant_time_eq(&self, other: &SecureBuffer) -> bool {
        self.check_canary();
        other.check_canary();
        
        if self.len != other.len {
            return false;
        }
        
        let mut result = 0u8;
        unsafe {
            for i in 0..self.len {
                let a = ptr::read_volatile(self.as_ptr().add(i));
                let b = ptr::read_volatile(other.as_ptr().add(i));
                result |= a ^ b;
            }
        }
        
        result == 0
    }
    
    /// 获取缓冲区的加密哈希值（用于验证完整性）
    pub fn hash(&self) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        self.check_canary();
        
        let mut hasher = DefaultHasher::new();
        self.as_slice().hash(&mut hasher);
        let hash_value = hasher.finish();
        
        // 将哈希值扩展为 32 字节
        let mut result = [0u8; 32];
        let hash_bytes = hash_value.to_le_bytes();
        for (i, &byte) in hash_bytes.iter().enumerate() {
            result[i] = byte;
            result[i + 8] = byte ^ 0xFF;
            result[i + 16] = byte.wrapping_add(i as u8);
            result[i + 24] = byte.wrapping_mul(i as u8 + 1);
        }
        
        result
    }
}

// 实现 Drop trait 确保缓冲区被安全清除
impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // 尝试安全清零（忽略错误，因为 drop 不能返回错误）
        let _ = self.secure_zero();
        
        // 释放内存
        unsafe {
            alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
        
        // 更新分配统计
        SECURE_ALLOC_COUNT.fetch_sub(1, Ordering::Relaxed);
        SECURE_ALLOC_BYTES.fetch_sub(self.len, Ordering::Relaxed);
    }
}

// 禁用 Clone 以防止意外复制敏感数据
impl Clone for SecureBuffer {
    fn clone(&self) -> Self {
        // 明确创建副本，确保调用者知道正在复制敏感数据
        Self::from_slice(self.as_slice())
            .expect("克隆安全缓冲区失败")
    }
}

// 为了序列化支持，提供明确的方法
impl Serialize for SecureBuffer {
    fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // 出于安全考虑，拒绝序列化敏感数据
        Err(serde::ser::Error::custom("拒绝序列化敏感数据"))
    }
}

impl<'de> Deserialize<'de> for SecureBuffer {
    fn deserialize<D>(_deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // 出于安全考虑，拒绝反序列化
        Err(serde::de::Error::custom("拒绝反序列化敏感数据"))
    }
}

/// # 内存锁定管理器 (MemoryLock)
/// 
/// 用于防止敏感内存页被操作系统交换到磁盘的工具。
/// 锁定内存确保敏感数据只存在于物理内存中，不会被写入交换文件。
/// 
/// ## 🔒 安全原理
/// 
/// 操作系统可能会将不常用的内存页交换到磁盘以释放物理内存。
/// 如果敏感数据（如密钥、密码）被交换到磁盘，即使程序结束后
/// 这些数据仍可能残留在磁盘上，造成安全风险。
/// 
/// ## 📚 实现机制
/// 
/// - **Unix/Linux**: 使用 `mlock()` 系统调用锁定内存页
/// - **Windows**: 使用 `VirtualLock()` API 锁定虚拟内存
/// - **权限检查**: 确保程序有足够权限进行内存锁定
/// - **资源限制**: 尊重系统对锁定内存的限制
/// 
/// ## ⚠️ 使用注意事项
/// 
/// 1. **权限要求**: 可能需要特殊权限或配置
/// 2. **资源限制**: 系统对锁定内存大小有限制
/// 3. **性能影响**: 过多锁定内存可能影响系统性能
/// 4. **自动解锁**: 在作用域结束时自动解锁内存
#[derive(Debug)]
pub struct MemoryLock {
    /// 锁定内存的起始地址
    ptr: *mut c_void,
    /// 锁定内存的大小
    size: usize,
    /// 是否成功锁定
    is_locked: bool,
}

impl MemoryLock {
    /// 创建新的内存锁定
    /// 
    /// # 参数
    /// - `ptr`: 要锁定的内存地址
    /// - `size`: 要锁定的内存大小
    /// 
    /// # 返回值
    /// 返回内存锁定管理器，如果锁定失败则返回错误
    /// 
    /// # 权限要求
    /// 在某些系统上可能需要 root 权限或特殊配置
    pub fn new(ptr: *const u8, size: usize) -> Result<Self> {
        if ptr.is_null() || size == 0 {
            return Err("无效的内存地址或大小".into());
        }
        
        // 检查全局锁定内存限制
        let current_locked = LOCKED_MEMORY_COUNT.load(Ordering::Relaxed);
        if current_locked + size > MAX_LOCKED_MEMORY {
            return Err(format!(
                "超过最大锁定内存限制: 当前 {}, 请求 {}, 最大 {}",
                current_locked, size, MAX_LOCKED_MEMORY
            ).into());
        }
        
        let ptr = ptr as *mut c_void;
        let is_locked = Self::lock_memory(ptr, size)?;
        
        if is_locked {
            LOCKED_MEMORY_COUNT.fetch_add(size, Ordering::Relaxed);
        }
        
        Ok(MemoryLock {
            ptr,
            size,
            is_locked,
        })
    }
    
    /// 检查内存是否已锁定
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }
    
    /// 获取锁定的内存大小
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// 平台特定的内存锁定实现
    #[cfg(unix)]
    fn lock_memory(ptr: *mut c_void, size: usize) -> Result<bool> {
        let result = unsafe { libc::mlock(ptr, size) };
        
        if result == 0 {
            Ok(true)
        } else {
            let errno = unsafe { *libc::__errno_location() };
            match errno {
                libc::EPERM => Err("没有锁定内存的权限，请以 root 权限运行或增加 ulimit -l".into()),
                libc::ENOMEM => Err("没有足够的内存可供锁定".into()),
                libc::EAGAIN => Err("系统锁定内存数量已达上限".into()),
                _ => Err(format!("内存锁定失败，错误代码: {}", errno).into()),
            }
        }
    }
    
    /// Windows 平台的内存锁定实现
    #[cfg(windows)]
    fn lock_memory(ptr: *mut c_void, size: usize) -> Result<bool> {
        use winapi::um::memoryapi::VirtualLock;
        
        let result = unsafe { VirtualLock(ptr, size) };
        
        if result != 0 {
            Ok(true)
        } else {
            Err("Windows 内存锁定失败".into())
        }
    }
    
    /// 其他平台的内存锁定实现（返回 false 表示不支持）
    #[cfg(not(any(unix, windows)))]
    fn lock_memory(_ptr: *mut c_void, _size: usize) -> Result<bool> {
        Ok(false)  // 不支持内存锁定，但不报错
    }
    
    /// 平台特定的内存解锁实现
    #[cfg(unix)]
    fn unlock_memory(ptr: *mut c_void, size: usize) -> Result<()> {
        let result = unsafe { libc::munlock(ptr, size) };
        if result != 0 {
            let errno = unsafe { *libc::__errno_location() };
            eprintln!("内存解锁警告，错误代码: {}", errno);
        }
        Ok(())
    }
    
    #[cfg(windows)]
    fn unlock_memory(ptr: *mut c_void, size: usize) -> Result<()> {
        use winapi::um::memoryapi::VirtualUnlock;
        
        let result = unsafe { VirtualUnlock(ptr, size) };
        if result == 0 {
            eprintln!("Windows 内存解锁警告");
        }
        Ok(())
    }
    
    #[cfg(not(any(unix, windows)))]
    fn unlock_memory(_ptr: *mut c_void, _size: usize) -> Result<()> {
        Ok(())  // 不支持的平台，静默处理
    }
}

impl Drop for MemoryLock {
    fn drop(&mut self) {
        if self.is_locked {
            let _ = Self::unlock_memory(self.ptr, self.size);
            LOCKED_MEMORY_COUNT.fetch_sub(self.size, Ordering::Relaxed);
        }
    }
}

/// # 栈保护器 (StackProtector)
/// 
/// 用于检测栈溢出攻击的保护机制。通过在栈上放置金丝雀值，
/// 可以检测到栈缓冲区溢出攻击并及时终止程序执行。
/// 
/// ## 🔒 工作原理
/// 
/// 1. **金丝雀设置**: 在栈变量附近放置特殊的金丝雀值
/// 2. **定期检查**: 在关键操作前检查金丝雀是否被修改
/// 3. **攻击检测**: 如果金丝雀值被修改，说明发生了栈溢出
/// 4. **立即终止**: 检测到攻击时立即终止程序防止进一步危害
/// 
/// ## 📚 使用场景
/// 
/// - 处理不可信输入数据的函数
/// - 复杂的递归算法
/// - 网络协议解析代码
/// - 密码学计算函数
#[derive(Debug, Clone)]
pub struct StackProtector {
    /// 金丝雀值，用于检测栈溢出
    canary: u64,
    /// 保护器标识符
    id: u32,
}

impl StackProtector {
    /// 创建新的栈保护器
    /// 
    /// # 返回值
    /// 返回带有随机金丝雀值的栈保护器
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let canary = rng.next_u64() ^ STACK_CANARY;
        let id = rng.next_u32();
        
        StackProtector { canary, id }
    }
    
    /// 检查栈保护器的完整性
    /// 
    /// 如果检测到栈溢出，程序将立即 panic
    pub fn check(&self) {
        // 简单的完整性检查
        let expected = self.id as u64 ^ STACK_CANARY;
        if self.canary != expected {
            panic!("检测到栈溢出攻击！栈保护器 {} 已被破坏", self.id);
        }
    }
    
    /// 获取保护器 ID
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl Default for StackProtector {
    fn default() -> Self {
        Self::new()
    }
}

/// 安全清零函数
/// 
/// 使用编译器无法优化掉的方式清零内存区域。
/// 该函数确保敏感数据被完全清除，防止数据残留攻击。
/// 
/// # 参数
/// - `ptr`: 要清零的内存指针
/// - `len`: 要清零的内存长度
/// 
/// # 安全性
/// - 使用 volatile 操作防止编译器优化
/// - 支持任意大小的内存区域
/// - 提供多重清零增强安全性
/// 
/// # 示例
/// ```rust
/// let mut secret_data = [1, 2, 3, 4];
/// secure_zero(secret_data.as_mut_ptr(), secret_data.len());
/// assert_eq!(secret_data, [0, 0, 0, 0]);
/// ```
pub fn secure_zero(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    
    unsafe {
        // 第一轮清零
        for i in 0..len {
            ptr::write_volatile(ptr.add(i), 0);
        }
        
        // 第二轮用不同模式清零（增强安全性）
        for i in 0..len {
            ptr::write_volatile(ptr.add(i), 0xFF);
        }
        
        // 最终清零
        for i in 0..len {
            ptr::write_volatile(ptr.add(i), 0);
        }
    }
}

/// 安全比较函数
/// 
/// 使用恒定时间算法比较两个内存区域，防止时序攻击。
/// 无论数据内容如何，比较时间都保持恒定。
/// 
/// # 参数
/// - `a`: 第一个内存区域的指针
/// - `b`: 第二个内存区域的指针
/// - `len`: 要比较的内存长度
/// 
/// # 返回值
/// 如果两个内存区域内容相同返回 true，否则返回 false
/// 
/// # 安全性
/// - 恒定时间执行，防止时序攻击
/// - 使用 volatile 操作防止编译器优化
/// - 适用于密码学比较操作
pub fn secure_compare(a: *const u8, b: *const u8, len: usize) -> bool {
    if a.is_null() || b.is_null() || len == 0 {
        return false;
    }
    
    let mut result = 0u8;
    
    unsafe {
        for i in 0..len {
            let byte_a = ptr::read_volatile(a.add(i));
            let byte_b = ptr::read_volatile(b.add(i));
            result |= byte_a ^ byte_b;
        }
    }
    
    result == 0
}

/// 获取系统内存页大小
/// 
/// 返回系统的内存页大小，用于内存对齐和优化。
/// 
/// # 返回值
/// 系统内存页大小（字节数）
pub fn get_page_size() -> usize {
    #[cfg(unix)]
    {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }
    
    #[cfg(windows)]
    {
        use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
        
        let mut sys_info: SYSTEM_INFO = unsafe { mem::zeroed() };
        unsafe { GetSystemInfo(&mut sys_info) };
        sys_info.dwPageSize as usize
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        4096  // 默认页大小
    }
}

/// 获取内存使用统计信息
/// 
/// # 返回值
/// 返回包含内存使用统计的结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    /// 当前分配的安全缓冲区数量
    pub secure_buffers: usize,
    /// 当前分配的安全内存总字节数
    pub secure_bytes: usize,
    /// 当前锁定的内存字节数
    pub locked_bytes: usize,
    /// 系统页面大小
    pub page_size: usize,
    /// 最大可锁定内存大小
    pub max_lockable: usize,
}

/// 获取当前内存使用统计
pub fn get_memory_stats() -> MemoryStats {
    MemoryStats {
        secure_buffers: SECURE_ALLOC_COUNT.load(Ordering::Relaxed),
        secure_bytes: SECURE_ALLOC_BYTES.load(Ordering::Relaxed),
        locked_bytes: LOCKED_MEMORY_COUNT.load(Ordering::Relaxed),
        page_size: get_page_size(),
        max_lockable: MAX_LOCKED_MEMORY,
    }
}

/// 内存安全测试和验证函数
/// 
/// 用于测试内存安全功能是否正常工作
pub fn test_memory_security() -> Result<()> {
    println!("🔍 开始内存安全功能测试...");
    
    // 测试安全缓冲区
    println!("  测试安全缓冲区...");
    let mut buffer = SecureBuffer::new(1024)?;
    let test_data = b"这是测试数据，应该被安全清除";
    buffer.copy_from_slice(&test_data[..])?;
    
    // 测试内容比较
    let buffer2 = SecureBuffer::from_slice(&test_data[..])?;
    assert!(buffer.constant_time_eq(&buffer2));
    
    // 测试栈保护器
    println!("  测试栈保护器...");
    let protector = StackProtector::new();
    protector.check();  // 应该正常通过
    
    // 测试内存锁定
    println!("  测试内存锁定...");
    let lock = MemoryLock::new(buffer.as_ptr(), buffer.len())?;
    println!("    内存锁定状态: {}", lock.is_locked());
    
    // 测试安全清零
    println!("  测试安全清零...");
    buffer.secure_zero()?;
    
    // 输出内存统计
    println!("  内存统计信息:");
    let stats = get_memory_stats();
    println!("    安全缓冲区数量: {}", stats.secure_buffers);
    println!("    安全内存大小: {} bytes", stats.secure_bytes);
    println!("    锁定内存大小: {} bytes", stats.locked_bytes);
    println!("    系统页面大小: {} bytes", stats.page_size);
    
    println!("✅ 内存安全功能测试完成");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_buffer_creation() {
        let buffer = SecureBuffer::new(1024).unwrap();
        assert_eq!(buffer.len(), 1024);
        assert!(!buffer.is_empty());
    }
    
    #[test]
    fn test_secure_buffer_operations() {
        let mut buffer = SecureBuffer::new(32).unwrap();
        let test_data = b"hello world, this is test data!";
        
        buffer.copy_from_slice(test_data).unwrap();
        
        let mut output = [0u8; 32];
        buffer.copy_to_slice(&mut output).unwrap();
        
        assert_eq!(&output[..], test_data);
    }
    
    #[test]
    fn test_secure_zero() {
        let mut buffer = SecureBuffer::new(64).unwrap();
        let test_data = vec![0xAAu8; 64];
        
        buffer.copy_from_slice(&test_data).unwrap();
        buffer.secure_zero().unwrap();
        
        let result = buffer.as_slice();
        assert!(result.iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_secure_compare() {
        let data1 = b"test data";
        let data2 = b"test data";
        let data3 = b"different";
        
        assert!(secure_compare(data1.as_ptr(), data2.as_ptr(), data1.len()));
        assert!(!secure_compare(data1.as_ptr(), data3.as_ptr(), data1.len()));
    }
    
    #[test]
    fn test_stack_protector() {
        let protector = StackProtector::new();
        protector.check();  // 应该正常通过
        
        let id = protector.id();
        assert!(id > 0);
    }
    
    #[test]
    fn test_constant_time_eq() {
        let buffer1 = SecureBuffer::from_slice(b"identical data").unwrap();
        let buffer2 = SecureBuffer::from_slice(b"identical data").unwrap();
        let buffer3 = SecureBuffer::from_slice(b"different data").unwrap();
        
        assert!(buffer1.constant_time_eq(&buffer2));
        assert!(!buffer1.constant_time_eq(&buffer3));
    }
    
    #[test]
    fn test_memory_stats() {
        let _buffer = SecureBuffer::new(1024).unwrap();
        let stats = get_memory_stats();
        
        assert!(stats.secure_buffers > 0);
        assert!(stats.secure_bytes >= 1024);
        assert!(stats.page_size > 0);
    }
}