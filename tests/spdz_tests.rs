use mpc_api::spdz::{share::*, SPDZParams};
use mpc_api::secret_sharing::{field_add, field_sub, field_mul, FIELD_PRIME};

#[test]
fn test_spdz_share_creation() {
    let share = SPDZShare::new(42, 123, 0, 1);
    assert_eq!(share.value, 42);
    assert_eq!(share.mac, 123);
    assert_eq!(share.party_id, 0);
    assert_eq!(share.share_id, 1);
}

#[test]
fn test_spdz_share_addition() {
    let share1 = SPDZShare::new(10, 20, 0, 1);
    let share2 = SPDZShare::new(15, 25, 0, 2);
    
    let result = share1.add(&share2).unwrap();
    assert_eq!(result.value, field_add(10, 15));
    assert_eq!(result.mac, field_add(20, 25));
}

#[test]
fn test_spdz_share_subtraction() {
    let share1 = SPDZShare::new(20, 30, 0, 1);
    let share2 = SPDZShare::new(5, 10, 0, 2);
    
    let result = share1.sub(&share2).unwrap();
    assert_eq!(result.value, field_sub(20, 5));
    assert_eq!(result.mac, field_sub(30, 10));
}

#[test]
fn test_authenticated_share() {
    let mut auth_share = AuthenticatedShare::new();
    let share = SPDZShare::new(42, 123, 0, 1);
    
    auth_share.add_share(0, share.clone());
    
    let retrieved = auth_share.get_share(0).unwrap();
    assert_eq!(retrieved.value, share.value);
    assert_eq!(retrieved.mac, share.mac);
}

#[test]
fn test_spdz_protocol_creation() {
    let params = SPDZParams::new(3, 0, 2);
    let protocol = SPDZShareProtocol::new(params);
    assert!(protocol.is_ok());
}

#[test]
fn test_secret_sharing() {
    let params = SPDZParams::new(3, 0, 2);
    let protocol = SPDZShareProtocol::new(params).unwrap();
    
    let secret = 42u64;
    let shares = protocol.share_secret(secret).unwrap();
    
    assert_eq!(shares.len(), 3);
    for share in &shares {
        assert!(share.value < FIELD_PRIME);
    }
}

#[test]
fn test_input_and_reconstruction() {
    let params = SPDZParams::new(3, 0, 2);
    let protocol = SPDZShareProtocol::new(params).unwrap();
    
    let secret = 42u64;
    let auth_share = protocol.input(secret).unwrap();
    
    // In a real scenario, MAC verification would be done
    // For this test, we'll skip it
    let reconstructed = auth_share.reconstruct(2).unwrap();
    // Check that reconstruction works - the value might be equivalent in the field
    assert!(reconstructed == secret || reconstructed == field_add(secret, 0));
}

#[test]
fn test_share_operations() {
    let params = SPDZParams::new(3, 0, 2);
    let protocol = SPDZShareProtocol::new(params).unwrap();
    
    let share_a = protocol.input(10).unwrap();
    let share_b = protocol.input(20).unwrap();
    
    let sum = protocol.add(&share_a, &share_b).unwrap();
    let diff = protocol.sub(&share_a, &share_b).unwrap();
    let scaled = protocol.mul_public(&share_a, 5);
    
    // Verify operations (in practice, these would be verified with MACs)
    assert_eq!(sum.reconstruct(2).unwrap(), field_add(10, 20));
    assert_eq!(diff.reconstruct(2).unwrap(), field_sub(10, 20));
    assert_eq!(scaled.reconstruct(2).unwrap(), field_mul(10, 5));
}

#[test]
fn test_batch_operations() {
    let params = SPDZParams::new(3, 0, 2);
    let protocol = SPDZShareProtocol::new(params).unwrap();
    
    let shares_a = vec![
        protocol.input(10).unwrap(),
        protocol.input(20).unwrap(),
    ];
    let shares_b = vec![
        protocol.input(5).unwrap(),
        protocol.input(15).unwrap(),
    ];
    
    let sums = protocol.add_batch(&shares_a, &shares_b).unwrap();
    
    assert_eq!(sums.len(), 2);
    assert_eq!(sums[0].reconstruct(2).unwrap(), field_add(10, 5));
    assert_eq!(sums[1].reconstruct(2).unwrap(), field_add(20, 15));
}

#[test]
fn test_linear_combination() {
    let params = SPDZParams::new(3, 0, 2);
    let protocol = SPDZShareProtocol::new(params).unwrap();
    
    let shares = vec![
        protocol.input(10).unwrap(),
        protocol.input(20).unwrap(),
        protocol.input(30).unwrap(),
    ];
    let coefficients = vec![1, 2, 3];
    
    let result = protocol.linear_combination(&shares, &coefficients).unwrap();
    
    // Expected: 1*10 + 2*20 + 3*30 = 10 + 40 + 90 = 140
    let expected = field_add(
        field_add(
            field_mul(1, 10), 
            field_mul(2, 20)
        ), 
        field_mul(3, 30)
    );
    assert_eq!(result.reconstruct(2).unwrap(), expected);
}

#[test]
fn test_random_generation() {
    let params = SPDZParams::new(3, 0, 2);
    let protocol = SPDZShareProtocol::new(params).unwrap();
    
    let random_share = protocol.random().unwrap();
    let value = random_share.reconstruct(2).unwrap();
    
    assert!(value < FIELD_PRIME);
}