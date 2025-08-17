//! Simple benchmarks for MPC API core operations
//! 
//! Demonstrates basic performance testing for key MPC operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_api::*;

/// Benchmark basic secret sharing operations
fn bench_basic_secret_sharing(c: &mut Criterion) {
    let secret = 12345u64;
    let threshold = 3;
    let parties = 5;
    
    c.bench_function("secret_sharing_share", |b| {
        b.iter(|| {
            let shares = ShamirSecretSharing::share(
                black_box(&secret), 
                black_box(threshold), 
                black_box(parties)
            );
            black_box(shares)
        });
    });
    
    // Benchmark reconstruction
    let shares = ShamirSecretSharing::share(&secret, threshold, parties).unwrap();
    c.bench_function("secret_sharing_reconstruct", |b| {
        b.iter(|| {
            let result = ShamirSecretSharing::reconstruct(
                black_box(&shares[0..threshold]), 
                black_box(threshold)
            );
            black_box(result)
        });
    });
}

/// Benchmark field arithmetic
fn bench_field_arithmetic(c: &mut Criterion) {
    let a = 1234567890u64;
    let b = 9876543210u64;
    
    c.bench_function("field_add", |bench| {
        bench.iter(|| {
            let result = field_add(black_box(a), black_box(b));
            black_box(result)
        });
    });
    
    c.bench_function("field_mul", |bench| {
        bench.iter(|| {
            let result = field_mul(black_box(a), black_box(b));
            black_box(result)
        });
    });
}

/// Benchmark basic commitments
fn bench_basic_commitments(c: &mut Criterion) {
    let value = 12345u64;
    let randomness = 67890u64;
    
    c.bench_function("hash_commit", |bench| {
        bench.iter(|| {
            let commitment = HashCommitment::commit_u64(
                black_box(value), 
                black_box(randomness)
            );
            black_box(commitment)
        });
    });
    
    let commitment = HashCommitment::commit_u64(value, randomness);
    c.bench_function("hash_verify", |bench| {
        bench.iter(|| {
            let result = HashCommitment::verify_u64(
                black_box(&commitment), 
                black_box(value), 
                black_box(randomness)
            );
            black_box(result)
        });
    });
}

/// Benchmark Beaver triple generation
fn bench_beaver_triple(c: &mut Criterion) {
    c.bench_function("beaver_triple_generate", |b| {
        b.iter(|| {
            let mut generator = TrustedPartyBeaverGenerator::new(5, 3, 0, None).unwrap();
            let triple = generator.generate_single();
            black_box(triple)
        });
    });
}

/// Benchmark a simple MPC workflow
fn bench_simple_mpc_workflow(c: &mut Criterion) {
    c.bench_function("mpc_sum_3_values", |b| {
        let values = vec![100u64, 200u64, 300u64];
        let threshold = 2;
        let parties = 3;
        
        b.iter(|| {
            // Share all values
            let mut all_shares = Vec::new();
            for &value in &values {
                let shares = ShamirSecretSharing::share(&value, threshold, parties).unwrap();
                all_shares.push(shares);
            }
            
            // Compute sum
            let mut sum_shares = all_shares[0].clone();
            for shares in &all_shares[1..] {
                for (i, share) in shares.iter().enumerate() {
                    sum_shares[i] = ShamirSecretSharing::add_shares(&sum_shares[i], share).unwrap();
                }
            }
            
            // Reconstruct
            let result = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold);
            black_box(result)
        });
    });
}

criterion_group!(
    benches,
    bench_basic_secret_sharing,
    bench_field_arithmetic,
    bench_basic_commitments,
    bench_beaver_triple,
    bench_simple_mpc_workflow
);

criterion_main!(benches);