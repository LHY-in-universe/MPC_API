use mpc_api::beaver_triples::threshold_keygen::*;
use mpc_api::beaver_triples::bfv_based::BFVParams;
use mpc_api::Result;

#[test]
fn test_threshold_keygen_creation() {
    let params = BFVParams::default();
    let keygen = ThresholdBFVKeyGen::new(3, 2, 0, params);
    assert!(keygen.is_ok());
}

#[test]
fn test_contribution_generation() {
    let params = BFVParams {
        degree: 8,
        coeff_modulus: 1024,
        plain_modulus: 16,
        noise_std_dev: 1.0,
    };
    
    let mut keygen = ThresholdBFVKeyGen::new(3, 2, 0, params).unwrap();
    let contribution = keygen.generate_contribution();
    
    assert!(contribution.is_ok());
    let contrib = contribution.unwrap();
    assert_eq!(contrib.party_id, 0);
    assert_eq!(contrib.public_polynomial.len(), 8);
    assert_eq!(contrib.commitments.len(), 2);
}

#[test]
fn test_full_keygen_protocol() {
    let params = BFVParams {
        degree: 4,
        coeff_modulus: 1024,
        plain_modulus: 16,
        noise_std_dev: 1.0,
    };
    
    let party_count = 3;
    let threshold = 2;
    
    // 模拟三方协议
    let mut keygens: Vec<ThresholdBFVKeyGen> = (0..party_count)
        .map(|i| ThresholdBFVKeyGen::new(party_count, threshold, i, params.clone()).unwrap())
        .collect();
    
    // 第一阶段：每方生成贡献
    let mut contributions = Vec::new();
    for keygen in &mut keygens {
        let contrib = keygen.generate_contribution().unwrap();
        contributions.push(contrib);
    }
    
    // 第二阶段：交换贡献
    for (i, keygen) in keygens.iter_mut().enumerate() {
        for (j, contrib) in contributions.iter().enumerate() {
            if i != j {
                keygen.add_contribution(contrib.clone()).unwrap();
            }
        }
    }
    
    // 第三阶段：生成密钥对
    let keypairs: Result<Vec<_>> = keygens.iter()
        .map(|keygen| keygen.generate_keypair())
        .collect();
    
    assert!(keypairs.is_ok());
    let kps = keypairs.unwrap();
    
    // 验证所有方生成了相同的公钥
    for i in 1..kps.len() {
        assert_eq!(kps[0].0.n, kps[i].0.n);
        assert_eq!(kps[0].0.q, kps[i].0.q);
        assert_eq!(kps[0].0.t, kps[i].0.t);
    }
}

#[test]
fn test_invalid_threshold() {
    let params = BFVParams::default();
    
    // 测试门限值为0
    let result = ThresholdBFVKeyGen::new(3, 0, 0, params.clone());
    assert!(result.is_err());
    
    // 测试门限值超过参与方数量
    let result = ThresholdBFVKeyGen::new(3, 4, 0, params);
    assert!(result.is_err());
}