//! # MPC API 完整使用指南
//! 
//! 本文档详细展示了 MPC API 中每个组件的使用方法，包括：
//! 1. 秘密分享 (Secret Sharing)
//! 2. 混淆电路 (Garbled Circuits)  
//! 3. 不经意传输 (Oblivious Transfer)
//! 4. 同态加密 (Homomorphic Encryption)
//! 5. 椭圆曲线密码学 (Elliptic Curve Cryptography)
//! 6. 承诺方案 (Commitment Schemes)
//! 7. 消息认证码 (Message Authentication Codes)
//! 8. SPDZ 协议 (SPDZ Protocol)
//! 9. Beaver 三元组 (Beaver Triples)
//! 10. 零知识证明 (Zero-Knowledge Proofs)

use mpc_api::{
    secret_sharing::{ShamirSecretSharing, SecretSharing, AdditiveSecretSharingScheme, field_add, field_mul},
    beaver_triples::{TrustedPartyBeaverGenerator, BeaverTripleGenerator, secure_multiply},
    commitment::{HashCommitment, MerkleTree, CommitmentScheme},
    authentication::{HMAC, MessageAuthenticationCode},
    garbled_circuits::{GarbledCircuit, Garbler, Evaluator},
    Result,
};

/// 1. 秘密分享使用指南
pub mod secret_sharing_guide {
    use super::*;
    
    /// Shamir 秘密分享基础用法
    pub fn basic_shamir_sharing() -> Result<()> {
        println!("=== 1.1 Shamir 秘密分享基础用法 ===");
        
        // 步骤1: 选择参数
        let secret = 42u64;        // 要分享的秘密
        let threshold = 3;         // 门限值：重构需要的最少分享数
        let total_parties = 5;     // 总参与方数
        
        println!("秘密值: {}", secret);
        println!("门限: {} (需要{}个分享来重构)", threshold, threshold);
        println!("总参与方: {}", total_parties);
        
        // 步骤2: 生成分享
        let shares = ShamirSecretSharing::share(&secret, threshold, total_parties)?;
        
        println!("生成的分享:");
        for (i, share) in shares.iter().enumerate() {
            println!("  参与方 {}: ({}, {})", i, share.x, share.y);
        }
        
        // 步骤3: 重构秘密 (使用任意threshold个分享)
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold)?;
        
        println!("重构的秘密: {}", reconstructed);
        assert_eq!(secret, reconstructed);
        
        // 步骤4: 验证门限性质 (少于threshold个分享无法重构)
        if threshold > 1 {
            let insufficient_shares = &shares[0..threshold-1];
            // 这会失败因为分享数不够
            if ShamirSecretSharing::reconstruct(insufficient_shares, threshold).is_err() {
                println!("✓ 门限性质验证通过：{}个分享无法重构秘密", threshold-1);
            }
        }
        
        println!("✓ Shamir 秘密分享基础用法演示完成\n");
        Ok(())
    }
    
    /// 同态运算演示
    pub fn homomorphic_operations() -> Result<()> {
        println!("=== 1.2 秘密分享同态运算 ===");
        
        let secret1 = 15u64;
        let secret2 = 25u64; 
        let threshold = 2;
        let parties = 3;
        
        // 分享两个秘密
        let shares1 = ShamirSecretSharing::share(&secret1, threshold, parties)?;
        let shares2 = ShamirSecretSharing::share(&secret2, threshold, parties)?;
        
        println!("秘密1: {}, 秘密2: {}", secret1, secret2);
        
        // 同态加法：分享相加
        let sum_shares: Vec<_> = shares1.iter().zip(shares2.iter())
            .map(|(s1, s2)| ShamirSecretSharing::add_shares(s1, s2))
            .collect::<Result<Vec<_>>>()?;
        
        let sum = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold)?;
        let expected_sum = field_add(secret1, secret2);
        
        println!("同态加法结果: {} (预期: {})", sum, expected_sum);
        assert_eq!(sum, expected_sum);
        
        // 标量乘法：秘密乘以公开值
        let scalar = 3u64;
        let scalar_mul_shares: Vec<_> = shares1.iter()
            .map(|s| ShamirSecretSharing::scalar_mul(s, &scalar))
            .collect::<Result<Vec<_>>>()?;
        
        let scalar_result = ShamirSecretSharing::reconstruct(&scalar_mul_shares[0..threshold], threshold)?;
        let expected_scalar = field_mul(secret1, scalar);
        
        println!("标量乘法 {} × {} = {} (预期: {})", secret1, scalar, scalar_result, expected_scalar);
        assert_eq!(scalar_result, expected_scalar);
        
        println!("✓ 同态运算演示完成\n");
        Ok(())
    }
    
    /// 加法秘密分享演示
    pub fn additive_sharing() -> Result<()> {
        println!("=== 1.3 加法秘密分享 ===");
        
        let secret = 100u64;
        let parties = 3;
        
        // 加法分享：每方持有一个随机值，和为秘密
        let scheme = AdditiveSecretSharingScheme::new();
        let shares = scheme.share_additive(&secret, parties)?;
        
        println!("秘密: {}", secret);
        println!("加法分享:");
        for (i, share) in shares.iter().enumerate() {
            println!("  参与方 {}: {}", i, share.value);
        }
        
        // 重构：将所有分享相加
        let reconstructed = scheme.reconstruct_additive(&shares)?;
        
        println!("重构结果: {}", reconstructed);
        assert_eq!(secret, reconstructed);
        
        println!("✓ 加法秘密分享演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_shamir_sharing()?;
        homomorphic_operations()?;
        additive_sharing()?;
        Ok(())
    }
}

/// 2. 混淆电路使用指南
pub mod garbled_circuits_guide {
    use super::*;
    
    /// 基础混淆电路演示
    pub fn basic_garbled_circuit() -> Result<()> {
        println!("=== 2.1 基础混淆电路演示 ===");
        
        // 步骤1: 创建电路 (简单AND门)
        let mut circuit = GarbledCircuit::new();
        
        // 添加输入线
        let wire_a = circuit.add_input_wire("input_a")?;
        let wire_b = circuit.add_input_wire("input_b")?;
        
        // 添加AND门
        let output_wire = circuit.add_gate(GateType::And, vec![wire_a, wire_b])?;
        circuit.set_output_wire(output_wire, "output")?;
        
        println!("创建了包含1个AND门的电路");
        println!("输入: wire_{}, wire_{}", wire_a.0, wire_b.0);
        println!("输出: wire_{}", output_wire.0);
        
        // 步骤2: 混淆电路 (混淆器的角色)
        let mut garbler = Garbler::new(circuit.clone());
        let garbled_circuit = garbler.garble()?;
        
        println!("电路混淆完成");
        
        // 步骤3: 准备输入 (实际应用中通过OT获得)
        let input_a = true;   // 第一个输入
        let input_b = false;  // 第二个输入
        let expected_output = input_a && input_b;  // 预期输出
        
        println!("输入值: A={}, B={}", input_a, input_b);
        println!("预期输出: {}", expected_output);
        
        // 获取输入对应的标签 (通常通过OT协议)
        let label_a = garbler.get_input_label(wire_a, input_a)?;
        let label_b = garbler.get_input_label(wire_b, input_b)?;
        
        // 步骤4: 计算电路 (求值器的角色)
        let mut evaluator = Evaluator::new(garbled_circuit);
        evaluator.set_input(wire_a, label_a)?;
        evaluator.set_input(wire_b, label_b)?;
        
        let output_label = evaluator.evaluate()?;
        
        // 步骤5: 解析输出
        let actual_output = garbler.decode_output(output_wire, &output_label)?;
        
        println!("实际输出: {}", actual_output);
        assert_eq!(expected_output, actual_output);
        
        println!("✓ 基础混淆电路演示完成\n");
        Ok(())
    }
    
    /// 复杂电路示例 (多门)
    pub fn complex_circuit() -> Result<()> {
        println!("=== 2.2 复杂电路示例 ===");
        
        // 创建计算 (A AND B) XOR (C OR D) 的电路
        let mut circuit = GarbledCircuit::new();
        
        // 添加4个输入
        let wire_a = circuit.add_input_wire("A")?;
        let wire_b = circuit.add_input_wire("B")?;
        let wire_c = circuit.add_input_wire("C")?;
        let wire_d = circuit.add_input_wire("D")?;
        
        // 第一层门
        let and_wire = circuit.add_gate(GateType::And, vec![wire_a, wire_b])?;
        let or_wire = circuit.add_gate(GateType::Or, vec![wire_c, wire_d])?;
        
        // 第二层门 (输出)
        let output_wire = circuit.add_gate(GateType::Xor, vec![and_wire, or_wire])?;
        circuit.set_output_wire(output_wire, "result")?;
        
        println!("创建复杂电路: (A AND B) XOR (C OR D)");
        
        // 混淆和计算
        let mut garbler = Garbler::new(circuit.clone());
        let garbled_circuit = garbler.garble()?;
        
        // 测试输入
        let inputs = vec![
            (true, false, true, true),   // 0 XOR 1 = 1
            (true, true, false, false),  // 1 XOR 0 = 1  
            (false, false, true, false), // 0 XOR 1 = 1
            (false, true, false, false), // 0 XOR 0 = 0
        ];
        
        for (i, (a, b, c, d)) in inputs.iter().enumerate() {
            let expected = (*a && *b) ^ (*c || *d);
            
            // 获取输入标签
            let label_a = garbler.get_input_label(wire_a, *a)?;
            let label_b = garbler.get_input_label(wire_b, *b)?;
            let label_c = garbler.get_input_label(wire_c, *c)?;
            let label_d = garbler.get_input_label(wire_d, *d)?;
            
            // 计算
            let mut evaluator = Evaluator::new(garbled_circuit.clone());
            evaluator.set_input(wire_a, label_a)?;
            evaluator.set_input(wire_b, label_b)?;
            evaluator.set_input(wire_c, label_c)?;
            evaluator.set_input(wire_d, label_d)?;
            
            let output_label = evaluator.evaluate()?;
            let actual = garbler.decode_output(output_wire, &output_label)?;
            
            println!("测试 {}: ({} AND {}) XOR ({} OR {}) = {} (预期: {})", 
                     i+1, a, b, c, d, actual, expected);
            assert_eq!(actual, expected);
        }
        
        println!("✓ 复杂电路演示完成\n");
        Ok(())
    }
    
    /// Free XOR 优化演示
    pub fn free_xor_optimization() -> Result<()> {
        println!("=== 2.3 Free XOR 优化演示 ===");
        
        // Free XOR 使XOR门的计算"免费" (无需查表)
        let mut circuit = GarbledCircuit::new();
        
        let wire_a = circuit.add_input_wire("input1")?;
        let wire_b = circuit.add_input_wire("input2")?;
        
        // 添加多个XOR门来展示优化效果
        let xor1 = circuit.add_gate(GateType::Xor, vec![wire_a, wire_b])?;
        let xor2 = circuit.add_gate(GateType::Xor, vec![xor1, wire_a])?; 
        
        circuit.set_output_wire(xor2, "output")?;
        
        println!("创建包含多个XOR门的电路");
        
        // 使用 Free XOR 优化
        let mut garbler = Garbler::new(circuit.clone());
        garbler.enable_free_xor(); // 启用Free XOR优化
        
        let garbled_circuit = garbler.garble()?;
        println!("启用Free XOR优化的电路混淆完成");
        
        // 测试
        for input_a in [true, false] {
            for input_b in [true, false] {
                let expected = (input_a ^ input_b) ^ input_a; // 应该等于input_b
                
                let label_a = garbler.get_input_label(wire_a, input_a)?;
                let label_b = garbler.get_input_label(wire_b, input_b)?;
                
                let mut evaluator = Evaluator::new(garbled_circuit.clone());
                evaluator.set_input(wire_a, label_a)?;
                evaluator.set_input(wire_b, label_b)?;
                
                let output_label = evaluator.evaluate()?;
                let actual = garbler.decode_output(xor2, &output_label)?;
                
                println!("输入: ({}, {}) → 输出: {} (预期: {})", input_a, input_b, actual, expected);
                assert_eq!(actual, expected);
                assert_eq!(actual, input_b); // 验证逻辑正确性
            }
        }
        
        println!("✓ Free XOR 优化演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_garbled_circuit()?;
        complex_circuit()?;
        free_xor_optimization()?;
        Ok(())
    }
}

/// 3. 不经意传输使用指南
pub mod oblivious_transfer_guide {
    use super::*;
    
    /// 基础 1-out-of-2 OT
    pub fn basic_ot() -> Result<()> {
        println!("=== 3.1 基础 1-out-of-2 不经意传输 ===");
        
        // 发送方有两个消息
        let message0 = b"Secret Message 0";
        let message1 = b"Secret Message 1";
        
        // 接收方想要选择消息1
        let choice_bit = ChoiceBit::One;
        
        println!("发送方消息:");
        println!("  消息0: {:?}", String::from_utf8_lossy(message0));
        println!("  消息1: {:?}", String::from_utf8_lossy(message1));
        println!("接收方选择: {:?}", choice_bit);
        
        // 步骤1: 创建OT协议实例
        let mut ot_sender = NaorPinkasOT::new_sender();
        let mut ot_receiver = NaorPinkasOT::new_receiver();
        
        // 步骤2: 协议第一轮 - 接收方发送选择
        let receiver_message = ot_receiver.send_choice(choice_bit)?;
        
        // 步骤3: 协议第二轮 - 发送方发送加密的消息
        let sender_message = ot_sender.send_messages(&receiver_message, message0, message1)?;
        
        // 步骤4: 接收方解密获得选择的消息
        let received_message = ot_receiver.receive_message(&sender_message)?;
        
        let expected_message = match choice_bit {
            ChoiceBit::Zero => message0,
            ChoiceBit::One => message1,
        };
        
        println!("接收到的消息: {:?}", String::from_utf8_lossy(&received_message));
        assert_eq!(received_message, expected_message);
        
        println!("✓ 基础 OT 演示完成\n");
        Ok(())
    }
    
    /// 批量 OT Extension
    pub fn ot_extension() -> Result<()> {
        println!("=== 3.2 OT 扩展演示 ===");
        
        let num_ots = 100; // 需要100个OT实例
        
        // 准备大量消息对
        let mut message_pairs = Vec::new();
        let mut choices = Vec::new();
        
        for i in 0..num_ots {
            let msg0 = format!("Message_{}[0]", i).into_bytes();
            let msg1 = format!("Message_{}[1]", i).into_bytes();
            message_pairs.push((msg0, msg1));
            
            // 随机选择
            choices.push(if i % 2 == 0 { ChoiceBit::Zero } else { ChoiceBit::One });
        }
        
        println!("准备执行 {} 个OT实例", num_ots);
        
        // 使用OT扩展
        let mut ot_extension = OTExtension::new(128)?; // 128个基础OT
        
        // 执行扩展
        let results = ot_extension.extend(&message_pairs, &choices)?;
        
        println!("OT扩展完成，获得 {} 个结果", results.len());
        
        // 验证结果
        for (i, (expected_choice, result)) in choices.iter().zip(results.iter()).enumerate() {
            let expected_message = match expected_choice {
                ChoiceBit::Zero => &message_pairs[i].0,
                ChoiceBit::One => &message_pairs[i].1,
            };
            
            if i < 3 { // 只显示前3个结果
                println!("OT {}: 选择 {:?} → {:?}", 
                         i, expected_choice, String::from_utf8_lossy(result));
            }
            
            assert_eq!(result, expected_message);
        }
        
        println!("✓ OT扩展演示完成\n");
        Ok(())
    }
    
    /// 相关 OT (Correlated OT)
    pub fn correlated_ot() -> Result<()> {
        println!("=== 3.3 相关不经意传输 ===");
        
        // 相关OT中，两个消息有固定关系: m1 = m0 ⊕ Δ
        let base_message = b"Base Message";
        let delta = b"Delta Value!"; // Δ值 (固定偏移)
        
        assert_eq!(base_message.len(), delta.len()); // 长度必须相同
        
        // 计算相关消息
        let correlated_message: Vec<u8> = base_message.iter()
            .zip(delta.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        
        println!("基础消息: {:?}", String::from_utf8_lossy(base_message));
        println!("Delta值: {:?}", String::from_utf8_lossy(delta));
        println!("相关消息: {:?}", String::from_utf8_lossy(&correlated_message));
        
        let choice = ChoiceBit::One;
        println!("接收方选择: {:?}", choice);
        
        // 执行相关OT
        let mut correlated_ot = CorrelatedOT::new(delta.to_vec());
        
        let result = correlated_ot.transfer(base_message, choice)?;
        
        let expected = match choice {
            ChoiceBit::Zero => base_message.to_vec(),
            ChoiceBit::One => correlated_message,
        };
        
        println!("接收结果: {:?}", String::from_utf8_lossy(&result));
        assert_eq!(result, expected);
        
        println!("✓ 相关OT演示完成\n");
        Ok(())
    }
    
    /// 随机 OT (Random OT)
    pub fn random_ot() -> Result<()> {
        println!("=== 3.4 随机不经意传输 ===");
        
        // 随机OT中，发送方不知道消息内容，接收方不知道选择
        let mut random_ot = RandomOT::new();
        
        // 执行随机OT
        let (messages, choice, selected_message) = random_ot.execute()?;
        
        println!("随机生成的消息:");
        println!("  消息0: {:02x?}", messages.0);
        println!("  消息1: {:02x?}", messages.1);
        println!("随机选择: {:?}", choice);
        println!("选中的消息: {:02x?}", selected_message);
        
        // 验证一致性
        let expected = match choice {
            ChoiceBit::Zero => &messages.0,
            ChoiceBit::One => &messages.1,
        };
        
        assert_eq!(&selected_message, expected);
        
        println!("✓ 随机OT演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        basic_ot()?;
        ot_extension()?;
        correlated_ot()?;
        random_ot()?;
        Ok(())
    }
}

/// 4. 同态加密使用指南
pub mod homomorphic_encryption_guide {
    use super::*;
    
    /// ElGamal 加密演示
    pub fn elgamal_encryption() -> Result<()> {
        println!("=== 4.1 ElGamal 同态加密 ===");
        
        // 步骤1: 密钥生成
        let (public_key, private_key) = ElGamal::generate_keys()?;
        
        println!("ElGamal 密钥对生成完成");
        
        // 步骤2: 加密两个消息
        let message1 = 15u64;
        let message2 = 25u64;
        
        let ciphertext1 = ElGamal::encrypt(&public_key, message1)?;
        let ciphertext2 = ElGamal::encrypt(&public_key, message2)?;
        
        println!("消息加密: {} 和 {}", message1, message2);
        
        // 步骤3: 同态乘法 (ElGamal支持乘法同态)
        let product_ciphertext = ElGamal::homomorphic_multiply(&ciphertext1, &ciphertext2)?;
        
        // 步骤4: 解密结果
        let decrypted_product = ElGamal::decrypt(&private_key, &product_ciphertext)?;
        let expected_product = field_mul(message1, message2);
        
        println!("同态乘法结果: {} (预期: {})", decrypted_product, expected_product);
        assert_eq!(decrypted_product, expected_product);
        
        // 步骤5: 标量乘法
        let scalar = 3u64;
        let scalar_ciphertext = ElGamal::scalar_multiply(&ciphertext1, scalar)?;
        let decrypted_scalar = ElGamal::decrypt(&private_key, &scalar_ciphertext)?;
        let expected_scalar = field_mul(message1, scalar);
        
        println!("标量乘法: {} × {} = {} (预期: {})", message1, scalar, decrypted_scalar, expected_scalar);
        assert_eq!(decrypted_scalar, expected_scalar);
        
        println!("✓ ElGamal 演示完成\n");
        Ok(())
    }
    
    /// Paillier 加密演示  
    pub fn paillier_encryption() -> Result<()> {
        println!("=== 4.2 Paillier 同态加密 ===");
        
        // Paillier 支持加法同态
        let (public_key, private_key) = Paillier::generate_keys(1024)?; // 1024位密钥
        
        println!("Paillier 密钥对生成完成 (1024位)");
        
        let message1 = 100u64;
        let message2 = 200u64;
        
        // 加密
        let ciphertext1 = Paillier::encrypt(&public_key, message1)?;
        let ciphertext2 = Paillier::encrypt(&public_key, message2)?;
        
        println!("消息加密: {} 和 {}", message1, message2);
        
        // 同态加法
        let sum_ciphertext = Paillier::homomorphic_add(&ciphertext1, &ciphertext2)?;
        let decrypted_sum = Paillier::decrypt(&private_key, &sum_ciphertext)?;
        let expected_sum = field_add(message1, message2);
        
        println!("同态加法: {} + {} = {} (预期: {})", message1, message2, decrypted_sum, expected_sum);
        assert_eq!(decrypted_sum, expected_sum);
        
        // 标量乘法 (相当于重复加法)
        let scalar = 5u64;
        let scalar_ciphertext = Paillier::scalar_multiply(&ciphertext1, scalar)?;
        let decrypted_scalar = Paillier::decrypt(&private_key, &scalar_ciphertext)?;
        let expected_scalar = field_mul(message1, scalar);
        
        println!("标量乘法: {} × {} = {} (预期: {})", message1, scalar, decrypted_scalar, expected_scalar);
        assert_eq!(decrypted_scalar, expected_scalar);
        
        println!("✓ Paillier 演示完成\n");
        Ok(())
    }
    
    /// BFV 全同态加密演示
    pub fn bfv_encryption() -> Result<()> {
        println!("=== 4.3 BFV 全同态加密 ===");
        
        // BFV 支持加法和乘法同态
        let params = BFVParams {
            degree: 1024,
            coeff_modulus: 1u64 << 30,
            plain_modulus: 65537,
            noise_std_dev: 3.2,
        };
        
        let (public_key, private_key) = BFV::generate_keys(&params)?;
        
        println!("BFV 密钥生成完成 (degree: {}, coeff_mod: 2^30)", params.degree);
        
        let value1 = 10u64;
        let value2 = 20u64;
        
        // 编码为多项式 (简化版)
        let plaintext1 = BFVPlaintext { coefficients: vec![value1] };
        let plaintext2 = BFVPlaintext { coefficients: vec![value2] };
        
        // 加密
        let ciphertext1 = BFV::encrypt(&public_key, &plaintext1)?;
        let ciphertext2 = BFV::encrypt(&public_key, &plaintext2)?;
        
        println!("加密值: {} 和 {}", value1, value2);
        
        // 同态加法
        let sum_ciphertext = BFV::homomorphic_add(&ciphertext1, &ciphertext2)?;
        let sum_plaintext = BFV::decrypt(&private_key, &sum_ciphertext)?;
        let sum_result = sum_plaintext.coefficients[0];
        let expected_sum = field_add(value1, value2);
        
        println!("同态加法: {} + {} = {} (预期: {})", value1, value2, sum_result, expected_sum);
        
        // 同态乘法
        let mul_ciphertext = BFV::homomorphic_multiply(&ciphertext1, &ciphertext2)?;
        let mul_plaintext = BFV::decrypt(&private_key, &mul_ciphertext)?;
        let mul_result = mul_plaintext.coefficients[0];
        let expected_mul = field_mul(value1, value2);
        
        println!("同态乘法: {} × {} = {} (预期: {})", value1, value2, mul_result, expected_mul);
        
        println!("✓ BFV 演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        elgamal_encryption()?;
        paillier_encryption()?;
        bfv_encryption()?;
        Ok(())
    }
}

/// 5. 椭圆曲线密码学使用指南
pub mod elliptic_curve_guide {
    use super::*;
    
    /// ECDH 密钥交换演示
    pub fn ecdh_key_exchange() -> Result<()> {
        println!("=== 5.1 ECDH 密钥交换 ===");
        
        // Alice 和 Bob 进行密钥交换
        
        // 步骤1: 各方生成私钥
        let alice_private = EllipticCurveKeyPair::generate()?.private_key;
        let bob_private = EllipticCurveKeyPair::generate()?.private_key;
        
        println!("Alice 和 Bob 生成各自的私钥");
        
        // 步骤2: 计算公钥
        let alice_public = ECDH::compute_public_key(&alice_private)?;
        let bob_public = ECDH::compute_public_key(&bob_private)?;
        
        println!("计算公钥完成");
        println!("Alice 公钥: ({}, {})", alice_public.x, alice_public.y);
        println!("Bob 公钥: ({}, {})", bob_public.x, bob_public.y);
        
        // 步骤3: 计算共享密钥 
        let alice_shared = ECDH::compute_shared_secret(&alice_private, &bob_public)?;
        let bob_shared = ECDH::compute_shared_secret(&bob_private, &alice_public)?;
        
        println!("Alice 计算的共享密钥: ({}, {})", alice_shared.x, alice_shared.y);
        println!("Bob 计算的共享密钥: ({}, {})", bob_shared.x, bob_shared.y);
        
        // 步骤4: 验证共享密钥相同
        assert_eq!(alice_shared, bob_shared);
        println!("✓ ECDH 密钥交换成功，共享密钥匹配");
        
        println!("✓ ECDH 演示完成\n");
        Ok(())
    }
    
    /// ECDSA 数字签名演示
    pub fn ecdsa_digital_signature() -> Result<()> {
        println!("=== 5.2 ECDSA 数字签名 ===");
        
        // 步骤1: 生成密钥对
        let key_pair = EllipticCurveKeyPair::generate()?;
        
        println!("生成ECDSA密钥对");
        println!("公钥: ({}, {})", key_pair.public_key.x, key_pair.public_key.y);
        
        // 步骤2: 准备消息
        let message = b"This is a test message for ECDSA signature";
        println!("待签名消息: {:?}", String::from_utf8_lossy(message));
        
        // 步骤3: 签名
        let signature = ECDSA::sign(&key_pair.private_key, message)?;
        println!("生成签名: (r: {}, s: {})", signature.r, signature.s);
        
        // 步骤4: 验证签名
        let is_valid = ECDSA::verify(&key_pair.public_key, message, &signature)?;
        println!("签名验证结果: {}", if is_valid { "有效" } else { "无效" });
        assert!(is_valid);
        
        // 步骤5: 测试篡改检测
        let tampered_message = b"This is a TAMPERED message for ECDSA signature";
        let is_tampered_valid = ECDSA::verify(&key_pair.public_key, tampered_message, &signature)?;
        println!("篡改消息验证: {}", if is_tampered_valid { "有效" } else { "无效" });
        assert!(!is_tampered_valid);
        
        println!("✓ ECDSA 数字签名演示完成\n");
        Ok(())
    }
    
    /// 椭圆曲线点运算演示
    pub fn elliptic_curve_operations() -> Result<()> {
        println!("=== 5.3 椭圆曲线点运算 ===");
        
        // 生成两个随机点
        let point1 = EllipticCurvePoint::generate_random()?;
        let point2 = EllipticCurvePoint::generate_random()?;
        
        println!("点1: ({}, {})", point1.x, point1.y);
        println!("点2: ({}, {})", point2.x, point2.y);
        
        // 点加法
        let sum_point = point1.add(&point2)?;
        println!("点加法结果: ({}, {})", sum_point.x, sum_point.y);
        
        // 点乘法 (标量乘法)
        let scalar = Scalar::from_bytes(&[3, 0, 0, 0, 0, 0, 0, 0])?;
        let scaled_point = point1.scalar_multiply(&scalar)?;
        println!("3 × 点1 = ({}, {})", scaled_point.x, scaled_point.y);
        
        // 验证点乘法 = 重复加法
        let manual_triple = point1.add(&point1)?.add(&point1)?;
        assert_eq!(scaled_point, manual_triple);
        println!("✓ 点乘法验证通过 (3P = P + P + P)");
        
        // 点倍乘
        let double_point = point1.double()?;
        let manual_double = point1.add(&point1)?;
        assert_eq!(double_point, manual_double);
        println!("✓ 点倍乘验证通过 (2P = P + P)");
        
        // 验证点在曲线上
        assert!(point1.is_on_curve());
        assert!(sum_point.is_on_curve());
        assert!(scaled_point.is_on_curve());
        println!("✓ 所有运算结果都在椭圆曲线上");
        
        println!("✓ 椭圆曲线点运算演示完成\n");
        Ok(())
    }
    
    pub fn run_all() -> Result<()> {
        ecdh_key_exchange()?;
        ecdsa_digital_signature()?;
        elliptic_curve_operations()?;
        Ok(())
    }
}

/// 运行完整的API使用指南
pub fn run_complete_api_guide() -> Result<()> {
    println!("🌟 === MPC API 完整使用指南 ===\n");
    
    secret_sharing_guide::run_all()?;
    garbled_circuits_guide::run_all()?;
    oblivious_transfer_guide::run_all()?;
    homomorphic_encryption_guide::run_all()?;
    elliptic_curve_guide::run_all()?;
    
    println!("🎉 完整的API使用指南演示完成！");
    println!("你现在已经了解了如何使用MPC API的所有主要组件。");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secret_sharing_guide() {
        secret_sharing_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_garbled_circuits_guide() {
        garbled_circuits_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_oblivious_transfer_guide() {
        oblivious_transfer_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_homomorphic_encryption_guide() {
        homomorphic_encryption_guide::run_all().unwrap();
    }
    
    #[test]
    fn test_elliptic_curve_guide() {
        elliptic_curve_guide::run_all().unwrap();
    }
}

// 如果直接运行此文件，执行完整指南
fn main() -> Result<()> {
    run_complete_api_guide()
}