//! # MPC API Beaver 三元组示例程序入口
//! 
//! 这个程序演示了三种不同的 Beaver 三元组生成方法：
//! 1. OLE (不经意线性求值) 方法
//! 2. BFV (同态加密) 方法
//! 3. 可信第三方方法
//! 
//! 以及它们在实际多方计算场景中的应用。

use std::env;

mod beaver_triples_ole_example;
mod beaver_triples_bfv_example;
mod beaver_triples_trusted_party_example;
mod comprehensive_beaver_examples;

use mpc_api::Result;

fn print_usage() {
    println!("MPC API Beaver 三元组示例程序");
    println!();
    println!("用法: cargo run --example main [选项]");
    println!();
    println!("选项:");
    println!("  ole        - 运行 OLE 方法示例");
    println!("  bfv        - 运行 BFV 方法示例"); 
    println!("  trusted    - 运行可信第三方方法示例");
    println!("  comparison - 运行综合对比示例");
    println!("  all        - 运行所有示例 (默认)");
    println!("  help       - 显示帮助信息");
    println!();
    println!("示例:");
    println!("  cargo run --example main ole");
    println!("  cargo run --example main comparison");
    println!("  cargo run --example main");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    let command = if args.len() > 1 {
        args[1].as_str()
    } else {
        "all"
    };
    
    match command {
        "ole" => {
            println!("🚀 运行 OLE 方法示例...\n");
            beaver_triples_ole_example::run_all_ole_examples()?;
        },
        "bfv" => {
            println!("🚀 运行 BFV 方法示例...\n");
            beaver_triples_bfv_example::run_all_bfv_examples()?;
        },
        "trusted" => {
            println!("🚀 运行可信第三方方法示例...\n");
            beaver_triples_trusted_party_example::run_all_trusted_party_examples()?;
        },
        "comparison" => {
            println!("🚀 运行综合对比示例...\n");
            comprehensive_beaver_examples::run_all_comprehensive_examples()?;
        },
        "all" => {
            println!("🌟 === 运行所有 Beaver 三元组示例 ===\n");
            
            println!("步骤 1/4: OLE 方法示例");
            beaver_triples_ole_example::run_all_ole_examples()?;
            
            println!("\n{}\n", "=".repeat(80));
            
            println!("步骤 2/4: BFV 方法示例");
            beaver_triples_bfv_example::run_all_bfv_examples()?;
            
            println!("\n{}\n", "=".repeat(80));
            
            println!("步骤 3/4: 可信第三方方法示例");
            beaver_triples_trusted_party_example::run_all_trusted_party_examples()?;
            
            println!("\n{}\n", "=".repeat(80));
            
            println!("步骤 4/4: 综合对比示例");
            comprehensive_beaver_examples::run_all_comprehensive_examples()?;
            
            println!("\n🎉 === 所有示例运行完成！===");
            println!("📝 总结:");
            println!("• OLE 方法: 平衡的性能和安全性");
            println!("• BFV 方法: 最高安全级别，抗量子");
            println!("• 可信第三方: 最高性能，需要信任假设");
            println!("• 根据具体应用需求选择合适的方法");
        },
        "help" | "--help" | "-h" => {
            print_usage();
            return Ok(());
        },
        _ => {
            println!("❌ 未知选项: {}", command);
            print_usage();
            std::process::exit(1);
        }
    }
    
    Ok(())
}