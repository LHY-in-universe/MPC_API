//! 椭圆曲线密码学测试
//! 
//! 包含 ECDH, ECDSA, 椭圆曲线点操作等测试

use mpc_api::elliptic_curve::{ECPoint, ECDH, ECDSA, EllipticCurve};
use mpc_api::elliptic_curve::ecdh::*;
use mpc_api::elliptic_curve::ecdsa::*;
use mpc_api::elliptic_curve::point::*;
use mpc_api::secret_sharing::{field_sub, FIELD_PRIME};
use rand::{thread_rng, Rng};

// ===== ECDH Tests =====

#[test]
fn test_ecdh_keypair_generation() {
    let result = ECDiffieHellman::generate_keypair();
    assert!(result.is_ok());
    
    let (private_key, public_key) = result.unwrap();
    assert!(private_key > 0);
    assert!(!public_key.is_infinity());
}

#[test]
fn test_ecdh_shared_secret() {
    // Generate keypairs for Alice and Bob
    let (alice_private, alice_public) = ECDiffieHellman::generate_keypair().unwrap();
    let (bob_private, bob_public) = ECDiffieHellman::generate_keypair().unwrap();
    
    // Compute shared secrets
    let alice_shared = ECDiffieHellman::compute_shared_secret(alice_private, &bob_public).unwrap();
    let bob_shared = ECDiffieHellman::compute_shared_secret(bob_private, &alice_public).unwrap();
    
    // Shared secrets should be equal
    assert_eq!(alice_shared, bob_shared);
}

#[test]
fn test_ecdh_key_exchange() {
    let mut rng = thread_rng();
    let alice_private = rng.gen_range(1..1000);
    let bob_private = rng.gen_range(1..1000);
    
    let result = ECDiffieHellman::perform_key_exchange(alice_private, bob_private);
    assert!(result.is_ok());
    
    let (alice_public, bob_public, shared_secret) = result.unwrap();
    
    assert!(!alice_public.is_infinity());
    assert!(!bob_public.is_infinity());
    assert!(!shared_secret.is_infinity());
}

#[test]
fn test_key_derivation() {
    let shared_point = ECPoint::new(123, 456);
    let key = ECDiffieHellman::derive_key_from_shared_secret(&shared_point);
    assert!(key.is_ok());
    
    let derived_key = key.unwrap();
    assert_eq!(derived_key.len(), 32);
    
    // Same input should produce same key
    let key2 = ECDiffieHellman::derive_key_from_shared_secret(&shared_point).unwrap();
    assert_eq!(derived_key, key2);
}

#[test]
fn test_key_agreement_protocol() {
    let result = ECDiffieHellman::key_agreement_protocol();
    assert!(result.is_ok());
    
    let (alice_key, bob_key) = result.unwrap();
    assert_eq!(alice_key.len(), 32);
    assert_eq!(bob_key.len(), 32);
    assert_eq!(alice_key, bob_key); // Keys should be the same
}

#[test]
fn test_curve25519_keypair() {
    let result = Curve25519ECDH::generate_keypair_curve25519();
    assert!(result.is_ok());
    
    let (private_key, public_key) = result.unwrap();
    assert!(private_key > 0);
    assert!(public_key > 0);
}

#[test]
fn test_curve25519_shared_secret() {
    let (alice_private, alice_public) = Curve25519ECDH::generate_keypair_curve25519().unwrap();
    let (bob_private, bob_public) = Curve25519ECDH::generate_keypair_curve25519().unwrap();
    
    let alice_shared = Curve25519ECDH::compute_shared_secret_curve25519(alice_private, bob_public).unwrap();
    let bob_shared = Curve25519ECDH::compute_shared_secret_curve25519(bob_private, alice_public).unwrap();
    
    assert_eq!(alice_shared, bob_shared);
}

// ===== ECDSA Tests =====

#[test]
fn test_ecdsa_signature_creation() {
    let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
    let message_hash = 12345u64;
    
    let signature = ECDigitalSignature::sign(private_key, message_hash).unwrap();
    
    assert!(signature.r > 0);
    assert!(signature.s > 0);
    
    let verification = ECDigitalSignature::verify(&public_key, message_hash, &signature).unwrap();
    assert!(verification);
}

#[test]
fn test_ecdsa_message_signing() {
    let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
    let message = b"Hello, ECDSA!";
    
    let signature = ECDigitalSignature::sign_message(message, private_key).unwrap();
    let verification = ECDigitalSignature::verify_message(message, &public_key, &signature).unwrap();
    
    assert!(verification);
}

#[test]
fn test_ecdsa_invalid_signature() {
    let (_, public_key) = ECDigitalSignature::generate_keypair().unwrap();
    let message_hash = 12345u64;
    
    // Create invalid signature
    let invalid_signature = ECDSASignature { r: 1, s: 1 };
    
    let verification = ECDigitalSignature::verify(&public_key, message_hash, &invalid_signature).unwrap();
    assert!(!verification);
}

#[test]
fn test_ecdsa_different_message() {
    let (private_key, public_key) = ECDigitalSignature::generate_keypair().unwrap();
    let message1 = b"Message 1";
    let message2 = b"Message 2";
    
    let signature1 = ECDigitalSignature::sign_message(message1, private_key).unwrap();
    
    // Signature for message1 should not verify for message2
    let verification = ECDigitalSignature::verify_message(message2, &public_key, &signature1).unwrap();
    assert!(!verification);
    
    // But should verify for message1
    let verification = ECDigitalSignature::verify_message(message1, &public_key, &signature1).unwrap();
    assert!(verification);
}

#[test]
fn test_ecdsa_wrong_public_key() {
    let (private_key1, _) = ECDigitalSignature::generate_keypair().unwrap();
    let (_, public_key2) = ECDigitalSignature::generate_keypair().unwrap();
    let message_hash = 12345u64;
    
    let signature = ECDigitalSignature::sign(private_key1, message_hash).unwrap();
    
    // Signature from private_key1 should not verify with public_key2
    let verification = ECDigitalSignature::verify(&public_key2, message_hash, &signature).unwrap();
    assert!(!verification);
}

// ===== EC Point Tests =====

#[test]
fn test_point_infinity() {
    let inf = ECPoint::infinity();
    assert!(inf.is_infinity());
    
    let p = ECPoint::new(1, 2);
    assert!(!p.is_infinity());
}

#[test]
fn test_point_negate() {
    let p = ECPoint::new(5, 10);
    let neg_p = p.negate();
    
    assert_eq!(neg_p.x, p.x);
    assert_eq!(neg_p.y, field_sub(0, p.y));
}

#[test]
fn test_point_addition_with_infinity() {
    let p = ECPoint::new(3, 4);
    let inf = ECPoint::infinity();
    
    let result1 = SimpleEC::point_add(&p, &inf).unwrap();
    let result2 = SimpleEC::point_add(&inf, &p).unwrap();
    
    assert_eq!(result1, p);
    assert_eq!(result2, p);
}

#[test]
fn test_scalar_multiplication() {
    let p = ECPoint::new(2, 3);
    
    // 0 * P = O (point at infinity)
    let result = SimpleEC::scalar_multiply(0, &p).unwrap();
    assert!(result.is_infinity());
    
    // 1 * P = P
    let result = SimpleEC::scalar_multiply(1, &p).unwrap();
    assert_eq!(result, p);
    
    // 2 * P = P + P
    let doubled = SimpleEC::point_double(&p).unwrap();
    let result = SimpleEC::scalar_multiply(2, &p).unwrap();
    assert_eq!(result, doubled);
}

#[test]
fn test_ec_params() {
    let params = SimpleEC::params();
    
    // Test that we can access the parameters
    assert_eq!(params.p, FIELD_PRIME);
    // A and B are private constants, so we just test they're accessible through params
    assert!(params.a >= 0);
    assert!(params.b >= 0);
}

#[test]
fn test_point_doubling() {
    let p = ECPoint::new(2, 3);
    
    // Verify that 2P = P + P
    let doubled = SimpleEC::point_double(&p).unwrap();
    let added = SimpleEC::point_add(&p, &p).unwrap();
    
    assert_eq!(doubled, added);
}