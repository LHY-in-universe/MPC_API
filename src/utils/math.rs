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

/// Miller-Rabin 素数检测算法
/// 
/// 这是一个概率性素数检测算法，比确定性试除法更高效。
/// 算法基于费马小定理的扩展，通过多轮测试来判断一个数是否为素数。
/// 
/// # 参数
/// * `n` - 待检测的奇数（大于2）
/// * `k` - 测试轮数，轮数越多准确率越高
/// 
/// # 返回值
/// 如果 n 很可能是素数返回 true，如果确定不是素数返回 false
/// 
/// # 准确率
/// 对于 k 轮测试，错误概率不超过 4^(-k)
/// - k=1: 错误率 ≤ 25%
/// - k=2: 错误率 ≤ 6.25%  
/// - k=3: 错误率 ≤ 1.56%
/// - k=10: 错误率 ≤ 0.0001%
/// 
/// # 示例
/// ```rust
/// assert!(miller_rabin_test(97, 10));    // 97 是素数
/// assert!(!miller_rabin_test(99, 10));   // 99 不是素数
/// ```
pub fn miller_rabin_test(n: u64, k: u32) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    
    // 将 n-1 写成 d * 2^r 的形式，其中 d 是奇数
    let mut d = n - 1;
    let mut r = 0;
    while d % 2 == 0 {
        d /= 2;
        r += 1;
    }
    
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    
    // 进行 k 轮测试
    for _ in 0..k {
        // 选择随机底数 a ∈ [2, n-2]
        let a = rng.gen_range(2..n-1);
        
        // 计算 a^d mod n
        let mut x = mod_pow(a, d, n);
        
        if x == 1 || x == n - 1 {
            continue;
        }
        
        let mut composite = true;
        for _ in 0..r-1 {
            x = mod_mul(x, x, n);
            if x == n - 1 {
                composite = false;
                break;
            }
        }
        
        if composite {
            return false;
        }
    }
    
    true
}

/// Solovay-Strassen 素数检测算法
/// 
/// 另一个概率性素数检测算法，基于二次剩余的雅可比符号。
/// 该算法与 Miller-Rabin 算法类似，但使用不同的数学原理。
/// 
/// # 参数
/// * `n` - 待检测的奇数（大于2）
/// * `k` - 测试轮数
/// 
/// # 返回值
/// 如果 n 很可能是素数返回 true，如果确定不是素数返回 false
/// 
/// # 示例
/// ```rust
/// assert!(solovay_strassen_test(97, 10));
/// assert!(!solovay_strassen_test(99, 10));
/// ```
pub fn solovay_strassen_test(n: u64, k: u32) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    
    for _ in 0..k {
        // 选择随机数 a ∈ [2, n-1]
        let a = rng.gen_range(2..n);
        
        // 计算 gcd(a, n)
        if gcd(a, n) != 1 {
            return false;
        }
        
        // 计算雅可比符号 (a/n)
        let jacobi = jacobi_symbol(a, n);
        
        // 计算 a^((n-1)/2) mod n
        let pow_result = mod_pow(a, (n - 1) / 2, n);
        
        // 检查 a^((n-1)/2) ≡ (a/n) (mod n)
        let jacobi_mod = if jacobi == -1 { n - 1 } else { jacobi as u64 };
        
        if pow_result != jacobi_mod {
            return false;
        }
    }
    
    true
}

/// AKS 素数检测算法的简化版本
/// 
/// 这是确定性的多项式时间素数检测算法，但实际实现复杂。
/// 此处提供一个基于多项式同余的简化检测方法。
/// 
/// # 参数
/// * `n` - 待检测的数
/// 
/// # 返回值
/// 如果 n 是素数返回 true，否则返回 false
/// 
/// # 注意
/// 这是 AKS 算法的高度简化版本，主要用于演示概念
pub fn aks_simplified_test(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    
    // 对于小数，使用确定性检测
    if n < 1000 {
        return is_prime(n);
    }
    
    // 检查是否为完全幂
    if is_perfect_power(n) {
        return false;
    }
    
    // 简化的 AKS 检测：检查多项式同余
    // (x + a)^n ≡ x^n + a (mod n) 对所有 a ∈ [1, √n] 成立
    let limit = ((n as f64).sqrt() as u64).min(100); // 限制计算量
    
    for a in 1..=limit {
        if !check_polynomial_congruence(n, a) {
            return false;
        }
    }
    
    true
}

/// 组合素数检测算法
/// 
/// 结合多种算法的优点，提供高效且准确的素数检测。
/// 算法策略：
/// 1. 小素数试除法（快速排除大部分合数）
/// 2. Miller-Rabin 测试（高效概率检测）
/// 3. 确定性验证（可选，用于关键应用）
/// 
/// # 参数
/// * `n` - 待检测的数
/// * `confidence_level` - 置信水平 (0.0-1.0)，越高越准确但越慢
/// 
/// # 返回值
/// 如果 n 是素数返回 true，否则返回 false
/// 
/// # 示例
/// ```rust
/// // 高置信度检测
/// assert!(combined_prime_test(18446744069414584321, 0.999));
/// 
/// // 快速检测
/// assert!(!combined_prime_test(18446744069414584320, 0.9));
/// ```
pub fn combined_prime_test(n: u64, confidence_level: f64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    
    // 阶段1: 小素数试除法（快速预筛选）
    let small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];
    
    for &p in &small_primes {
        if n == p {
            return true;
        }
        if n % p == 0 {
            return false;
        }
    }
    
    // 阶段2: 确定测试轮数
    let k = if confidence_level >= 0.999 {
        20  // 错误率 < 10^(-12)
    } else if confidence_level >= 0.99 {
        10  // 错误率 < 10^(-6)  
    } else if confidence_level >= 0.9 {
        5   // 错误率 < 0.003%
    } else {
        3   // 错误率 < 1.6%
    };
    
    // 阶段3: Miller-Rabin 测试
    if !miller_rabin_test(n, k) {
        return false;
    }
    
    // 阶段4: 高置信度情况下的额外验证
    if confidence_level >= 0.999 {
        // 使用 Solovay-Strassen 作为独立验证
        if !solovay_strassen_test(n, k / 2) {
            return false;
        }
        
        // 对于特别大的数，使用试除法验证更多因子
        if n > 1_000_000 {
            let limit = ((n as f64).sqrt() as u64).min(10000);
            for i in (101..limit).step_by(2) {
                if n % i == 0 {
                    return false;
                }
            }
        }
    }
    
    true
}

/// 检验指定素数的正确性
/// 
/// 专门用于验证 18446744069414584321 是否为素数
/// 
/// # 返回值
/// 如果该数是素数返回 true，否则返回 false
pub fn verify_field_prime() -> bool {
    const FIELD_PRIME: u64 = 18446744069414584321;
    
    println!("🔍 开始验证有限域素数: {}", FIELD_PRIME);
    
    // 使用多种方法验证
    println!("  方法1: 基础试除法");
    let basic_result = is_prime(FIELD_PRIME);
    println!("    结果: {}", if basic_result { "✅ 通过" } else { "❌ 失败" });
    
    println!("  方法2: Miller-Rabin 测试 (20轮)");
    let miller_rabin_result = miller_rabin_test(FIELD_PRIME, 20);
    println!("    结果: {}", if miller_rabin_result { "✅ 通过" } else { "❌ 失败" });
    
    println!("  方法3: Solovay-Strassen 测试 (10轮)");
    let solovay_result = solovay_strassen_test(FIELD_PRIME, 10);
    println!("    结果: {}", if solovay_result { "✅ 通过" } else { "❌ 失败" });
    
    println!("  方法4: 组合算法 (99.9% 置信度)");
    let combined_result = combined_prime_test(FIELD_PRIME, 0.999);
    println!("    结果: {}", if combined_result { "✅ 通过" } else { "❌ 失败" });
    
    let final_result = basic_result && miller_rabin_result && solovay_result && combined_result;
    
    println!("📋 素数验证总结:");
    println!("  待验证数: {}", FIELD_PRIME);
    println!("  基础试除法: {}", basic_result);
    println!("  Miller-Rabin: {}", miller_rabin_result);
    println!("  Solovay-Strassen: {}", solovay_result);
    println!("  组合算法: {}", combined_result);
    println!("  🎯 最终结果: {}", if final_result { 
        "✅ 确认为素数" 
    } else { 
        "❌ 不是素数或检测失败" 
    });
    
    final_result
}

// === 辅助函数 ===

/// 模指数运算：计算 (base^exp) mod m
/// 
/// 使用快速模指数算法，时间复杂度 O(log exp)
/// 
/// # 参数
/// * `base` - 底数
/// * `exp` - 指数
/// * `m` - 模数
/// 
/// # 返回值
/// 返回 (base^exp) mod m 的结果
fn mod_pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }
    
    let mut result = 1;
    base %= m;
    
    while exp > 0 {
        if exp % 2 == 1 {
            result = mod_mul(result, base, m);
        }
        exp >>= 1;
        base = mod_mul(base, base, m);
    }
    
    result
}

/// 模乘法：计算 (a * b) mod m，避免溢出
/// 
/// # 参数
/// * `a` - 第一个乘数
/// * `b` - 第二个乘数  
/// * `m` - 模数
/// 
/// # 返回值
/// 返回 (a * b) mod m 的结果
fn mod_mul(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

/// 雅可比符号计算
/// 
/// 计算雅可比符号 (a/n)，用于 Solovay-Strassen 算法
/// 
/// # 参数
/// * `a` - 分子
/// * `n` - 分母（奇数）
/// 
/// # 返回值
/// 返回雅可比符号的值：-1, 0, 或 1
fn jacobi_symbol(mut a: u64, mut n: u64) -> i32 {
    if gcd(a, n) != 1 {
        return 0;
    }
    
    let mut result = 1;
    
    while a != 0 {
        while a % 2 == 0 {
            a /= 2;
            if n % 8 == 3 || n % 8 == 5 {
                result = -result;
            }
        }
        
        std::mem::swap(&mut a, &mut n);
        
        if a % 4 == 3 && n % 4 == 3 {
            result = -result;
        }
        
        a %= n;
    }
    
    if n == 1 {
        result
    } else {
        0
    }
}

/// 检查一个数是否为完全幂
/// 
/// 检查 n 是否可以表示为 a^k 的形式，其中 k ≥ 2
/// 
/// # 参数
/// * `n` - 待检查的数
/// 
/// # 返回值
/// 如果 n 是完全幂返回 true，否则返回 false
fn is_perfect_power(n: u64) -> bool {
    if n <= 1 {
        return false;
    }
    
    // 检查 k = 2, 3, 4, ..., log2(n)
    let max_k = (n as f64).log2() as u32;
    
    for k in 2..=max_k {
        let root = (n as f64).powf(1.0 / k as f64).round() as u64;
        
        // 检查 root^k == n
        let mut power = 1u64;
        let temp_root = root;
        for _ in 0..k {
            if power > u64::MAX / temp_root {
                break; // 避免溢出
            }
            power *= temp_root;
        }
        
        if power == n {
            return true;
        }
    }
    
    false
}

/// 检查多项式同余（AKS 算法的简化版本）
/// 
/// 检查 (x + a)^n ≡ x^n + a (mod n) 是否成立
/// 
/// # 参数
/// * `n` - 模数
/// * `a` - 常数项
/// 
/// # 返回值
/// 如果同余成立返回 true，否则返回 false
fn check_polynomial_congruence(n: u64, _a: u64) -> bool {
    // 简化版本：只检查二项式系数
    // 在完整的 AKS 中，需要检查所有系数
    
    // 对于素数 n，二项式系数 C(n, k) ≡ 0 (mod n) 对所有 1 ≤ k ≤ n-1
    for k in 1..n.min(100) { // 限制计算量
        let binomial_coeff = binomial_coefficient(n, k);
        if binomial_coeff % n != 0 {
            return false;
        }
    }
    
    true
}

/// 计算二项式系数 C(n, k)
/// 
/// 使用递推关系计算，避免大数溢出
/// 
/// # 参数
/// * `n` - 上标
/// * `k` - 下标
/// 
/// # 返回值
/// 返回 C(n, k) 的值
fn binomial_coefficient(n: u64, k: u64) -> u64 {
    if k > n {
        return 0;
    }
    if k == 0 || k == n {
        return 1;
    }
    
    let k = k.min(n - k); // 利用对称性
    let mut result = 1u64;
    
    for i in 0..k {
        // 使用 result = result * (n - i) / (i + 1) 避免溢出
        result = result.saturating_mul(n - i) / (i + 1);
    }
    
    result
}

/// 生成指定范围内的所有素数（埃拉托斯特尼筛法）
/// 
/// 使用古典的筛法算法生成素数表
/// 
/// # 参数
/// * `limit` - 上限（不包含）
/// 
/// # 返回值
/// 返回所有小于 limit 的素数向量
/// 
/// # 示例
/// ```rust
/// let primes = sieve_of_eratosthenes(100);
/// assert!(primes.contains(&97));
/// assert!(!primes.contains(&100));
/// ```
pub fn sieve_of_eratosthenes(limit: usize) -> Vec<u64> {
    if limit < 2 {
        return vec![];
    }
    
    let mut is_prime = vec![true; limit];
    is_prime[0] = false;
    if limit > 1 {
        is_prime[1] = false;
    }
    
    for i in 2..((limit as f64).sqrt() as usize + 1) {
        if is_prime[i] {
            for j in ((i * i)..limit).step_by(i) {
                is_prime[j] = false;
            }
        }
    }
    
    is_prime.iter()
        .enumerate()
        .filter_map(|(i, &prime)| if prime { Some(i as u64) } else { None })
        .collect()
}

/// 下一个素数
/// 
/// 找到大于等于给定数的最小素数
/// 
/// # 参数
/// * `n` - 起始数
/// 
/// # 返回值
/// 返回大于等于 n 的最小素数
/// 
/// # 示例
/// ```rust
/// assert_eq!(next_prime(10), 11);
/// assert_eq!(next_prime(11), 11);
/// ```
pub fn next_prime(mut n: u64) -> u64 {
    if n < 2 {
        return 2;
    }
    
    // 确保是奇数
    if n % 2 == 0 {
        n += 1;
    }
    
    while !combined_prime_test(n, 0.999) {
        n += 2;
    }
    
    n
}

/// 上一个素数
/// 
/// 找到小于等于给定数的最大素数
/// 
/// # 参数
/// * `n` - 起始数
/// 
/// # 返回值
/// 返回小于等于 n 的最大素数，如果不存在则返回 0
pub fn prev_prime(mut n: u64) -> u64 {
    if n < 2 {
        return 0;
    }
    if n == 2 {
        return 2;
    }
    
    // 确保是奇数
    if n % 2 == 0 {
        n -= 1;
    }
    
    while n >= 3 && !combined_prime_test(n, 0.999) {
        n -= 2;
    }
    
    if n < 3 {
        2
    } else {
        n
    }
}