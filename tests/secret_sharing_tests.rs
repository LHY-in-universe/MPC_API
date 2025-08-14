use mpc_api::secret_sharing::{ShamirSecretSharing, SecretSharing, AdditiveSecretSharing, AdditiveSecretSharingScheme, field_add, field_mul};

#[test]
fn test_shamir_secret_sharing() {
    let secret = 42u64;
    let threshold = 3;
    let total_parties = 5;
    
    let shares = ShamirSecretSharing::share(&secret, threshold, total_parties).unwrap();
    assert_eq!(shares.len(), total_parties);
    
    let reconstructed = ShamirSecretSharing::reconstruct(&shares[..threshold], threshold).unwrap();
    assert_eq!(secret, reconstructed);
}

#[test]
fn test_shamir_additive_operations() {
    let secret1 = 1000u64;
    let secret2 = 2000u64;
    let threshold = 2;
    let total_parties = 3;
    
    let shares1 = ShamirSecretSharing::share(&secret1, threshold, total_parties).unwrap();
    let shares2 = ShamirSecretSharing::share(&secret2, threshold, total_parties).unwrap();
    
    // Test addition
    let mut sum_shares = Vec::new();
    for i in 0..threshold {
        let sum_share = ShamirSecretSharing::add_shares(&shares1[i], &shares2[i]).unwrap();
        sum_shares.push(sum_share);
    }
    
    let sum_result = ShamirSecretSharing::reconstruct(&sum_shares, threshold).unwrap();
    assert_eq!(sum_result, field_add(secret1, secret2));
    
    // Test scalar multiplication
    let scalar = 3u64;
    let mut scaled_shares = Vec::new();
    for i in 0..threshold {
        let scaled_share = ShamirSecretSharing::scalar_mul(&shares1[i], &scalar).unwrap();
        scaled_shares.push(scaled_share);
    }
    
    let scaled_result = ShamirSecretSharing::reconstruct(&scaled_shares, threshold).unwrap();
    assert_eq!(scaled_result, field_mul(secret1, scalar));
}

#[test]
fn test_additive_secret_sharing() {
    let scheme = AdditiveSecretSharingScheme::new();
    let secret = 1000u64;
    let num_parties = 5;
    
    let shares = scheme.share_additive(&secret, num_parties).unwrap();
    assert_eq!(shares.len(), num_parties);
    
    let reconstructed = scheme.reconstruct_additive(&shares).unwrap();
    assert_eq!(secret, reconstructed);
}

#[test]
fn test_additive_operations() {
    let scheme = AdditiveSecretSharingScheme::new();
    let secret1 = 100u64;
    let secret2 = 200u64;
    let num_parties = 3;
    
    let shares1 = scheme.share_additive(&secret1, num_parties).unwrap();
    let shares2 = scheme.share_additive(&secret2, num_parties).unwrap();
    
    // Test addition
    let mut sum_shares = Vec::new();
    for i in 0..num_parties {
        let sum_share = scheme.add_additive_shares(&shares1[i], &shares2[i]).unwrap();
        sum_shares.push(sum_share);
    }
    
    let sum_result = scheme.reconstruct_additive(&sum_shares).unwrap();
    assert_eq!(sum_result, field_add(secret1, secret2));
    
    // Test scalar multiplication
    let scalar = 3u64;
    let mut scaled_shares = Vec::new();
    for share in &shares1 {
        let scaled_share = scheme.scalar_mul_additive(share, &scalar).unwrap();
        scaled_shares.push(scaled_share);
    }
    
    let scaled_result = scheme.reconstruct_additive(&scaled_shares).unwrap();
    assert_eq!(scaled_result, field_mul(secret1, scalar));
}