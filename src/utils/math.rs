//! # 数学工具函数 (Mathematical Utility Functions)
//! 
//! 本模块提供了 MPC 协议中常用的数学运算函数，包括：
//! - 基础数论函数（最大公约数、最小公倍数）
//! - 素数检测算法
//! - 有限域运算支持
//! 
//! 这些函数为密码学协议的数学基础提供支持。

// use crate::secret_sharing::FIELD_PRIME; // 未使用的导入

/// 计算两个数的最大公约数 (Greatest Common Divisor)
/// 
/// 使用欧几里得算法递归计算两个正整数的最大公约数。
/// 这是数论中的基础算法，在密码学中用于计算模逆等操作。
/// 
/// # 参数
/// * `a` - 第一个正整数
/// * `b` - 第二个正整数
/// 
/// # 返回值
/// 返回 a 和 b 的最大公约数
/// 
/// # 示例
/// ```rust
/// let result = gcd(48, 18); // 返回 6
/// ```
pub fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// 计算两个数的最小公倍数 (Least Common Multiple)
/// 
/// 基于最大公约数计算最小公倍数，使用公式：lcm(a,b) = (a*b)/gcd(a,b)
/// 
/// # 参数
/// * `a` - 第一个正整数
/// * `b` - 第二个正整数
/// 
/// # 返回值
/// 返回 a 和 b 的最小公倍数
/// 
/// # 示例
/// ```rust
/// let result = lcm(12, 18); // 返回 36
/// ```
pub fn lcm(a: u64, b: u64) -> u64 {
    (a * b) / gcd(a, b)
}

/// 素数检测函数
/// 
/// 使用试除法检测一个数是否为素数。算法优化：
/// - 特殊处理小于2的数（非素数）
/// - 特殊处理2（唯一的偶数素数）
/// - 排除所有偶数
/// - 只检测到平方根的奇数因子
/// 
/// # 参数
/// * `n` - 待检测的正整数
/// 
/// # 返回值
/// 如果 n 是素数返回 true，否则返回 false
/// 
/// # 示例
/// ```rust
/// assert!(is_prime(17));  // 17 是素数
/// assert!(!is_prime(15)); // 15 不是素数
/// ```
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    
    let sqrt_n = (n as f64).sqrt() as u64;
    for i in (3..=sqrt_n).step_by(2) {
        if n % i == 0 {
            return false;
        }
    }
    true
}