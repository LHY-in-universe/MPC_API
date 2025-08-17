//! Performance benchmarks for MPC API components
//! 
//! This benchmark suite measures the performance of key MPC operations
//! to help optimize the library and provide performance baselines.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use mpc_api::*;

/// Benchmark Shamir secret sharing operations
fn bench_secret_sharing(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_sharing");
    
    // Test different threshold and party configurations
    let configs = vec![
        (2, 3),   // (threshold, parties)
        (3, 5),
        (5, 10),
        (10, 20),
    ];
    
    for (threshold, parties) in configs {
        // Benchmark sharing
        group.bench_with_input(
            BenchmarkId::new("share", format!("t{}_n{}", threshold, parties)),
            &(threshold, parties),
            |b, &(t, n)| {
                let secret = 12345u64;
                b.iter(|| {
                    let shares = ShamirSecretSharing::share(black_box(&secret), black_box(t), black_box(n));
                    black_box(shares)
                });
            },
        );
        
        // Benchmark reconstruction
        let secret = 12345u64;
        let shares = ShamirSecretSharing::share(&secret, threshold, parties).unwrap();
        group.bench_with_input(
            BenchmarkId::new("reconstruct", format!("t{}_n{}", threshold, parties)),
            &(threshold, parties),
            |b, &(t, _n)| {
                b.iter(|| {
                    let result = ShamirSecretSharing::reconstruct(
                        black_box(&shares[0..t]), 
                        black_box(t)
                    );
                    black_box(result)
                });
            },
        );
        
        // Benchmark share addition
        let secret2 = 67890u64;
        let shares2 = ShamirSecretSharing::share(&secret2, threshold, parties).unwrap();
        group.bench_with_input(
            BenchmarkId::new("add_shares", format!("t{}_n{}", threshold, parties)),
            &(threshold, parties),
            |b, &(_t, n)| {
                b.iter(|| {
                    let mut results = Vec::new();
                    for i in 0..n {
                        let result = ShamirSecretSharing::add_shares(
                            black_box(&shares[i]), 
                            black_box(&shares2[i])
                        );
                        results.push(result);
                    }
                    black_box(results)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark Beaver triple generation
fn bench_beaver_triples(c: &mut Criterion) {
    let mut group = c.benchmark_group("beaver_triples");
    
    let configs = vec![
        (2, 3),   // (threshold, parties)
        (3, 5),
        (5, 7),
    ];
    
    for (threshold, parties) in configs {
        group.bench_with_input(
            BenchmarkId::new("generate_single", format!("t{}_n{}", threshold, parties)),
            &(threshold, parties),
            |b, &(t, n)| {
                b.iter(|| {
                    let mut generator = TrustedPartyBeaverGenerator::new(n, t, 0, None).unwrap();
                    let triple = generator.generate_single();
                    black_box(triple)
                });
            },
        );
        
        // Benchmark batch generation
        group.bench_with_input(
            BenchmarkId::new("generate_batch_10", format!("t{}_n{}", threshold, parties)),
            &(threshold, parties),
            |b, &(t, n)| {
                b.iter(|| {
                    let mut generator = TrustedPartyBeaverGenerator::new(n, t, 0, None).unwrap();
                    let triples = generator.generate_batch(black_box(10));
                    black_box(triples)
                });
            },
        );
        
        // Benchmark triple verification
        let mut generator = TrustedPartyBeaverGenerator::new(parties, threshold, 0, None).unwrap();
        let triple = generator.generate_single().unwrap();
        group.bench_with_input(
            BenchmarkId::new("verify", format!("t{}_n{}", threshold, parties)),
            &(threshold, parties),
            |b, &(t, _n)| {
                b.iter(|| {
                    let result = triple.verify(black_box(t));
                    black_box(result)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark commitment schemes
fn bench_commitments(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitments");
    
    // Benchmark hash commitments
    group.bench_function("hash_commit", |b| {
        let value = 12345u64;
        let randomness = 67890u64;
        b.iter(|| {
            let commitment = HashCommitment::commit_u64(black_box(value), black_box(randomness));
            black_box(commitment)
        });
    });
    
    group.bench_function("hash_verify", |b| {
        let value = 12345u64;
        let randomness = 67890u64;
        let commitment = HashCommitment::commit_u64(value, randomness);
        b.iter(|| {
            let result = HashCommitment::verify_u64(
                black_box(&commitment), 
                black_box(value), 
                black_box(randomness)
            );
            black_box(result)
        });
    });
    
    // Benchmark Pedersen commitments  
    group.bench_function("pedersen_commit", |b| {
        let value = 12345u64;
        let randomness = 67890u64;
        b.iter(|| {
            let commitment = PedersenCommitment::commit(black_box(value), black_box(randomness));
            black_box(commitment)
        });
    });
    
    group.bench_function("pedersen_verify", |b| {
        let value = 12345u64;
        let randomness = 67890u64;
        let commitment = PedersenCommitment::commit(value, randomness);
        b.iter(|| {
            let result = PedersenCommitment::verify(
                black_box(commitment.clone()), 
                black_box(value), 
                black_box(randomness)
            );
            black_box(result)
        });
    });
    
    // Benchmark batch commitments
    let values = vec![1u64, 2u64, 3u64, 4u64, 5u64, 6u64, 7u64, 8u64, 9u64, 10u64];
    let randomness = vec![11u64, 12u64, 13u64, 14u64, 15u64, 16u64, 17u64, 18u64, 19u64, 20u64];
    
    group.bench_function("hash_batch_commit_10", |b| {
        b.iter(|| {
            let result = HashCommitment::batch_commit_u64(black_box(&values), black_box(&randomness));
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark authentication schemes
fn bench_authentication(c: &mut Criterion) {
    let mut group = c.benchmark_group("authentication");
    
    // Test different message sizes
    let message_sizes = vec![64, 256, 1024, 4096, 16384]; // bytes
    
    for size in message_sizes {
        let message = vec![0u8; size];
        let key = HMAC::generate_key();
        
        group.bench_with_input(
            BenchmarkId::new("hmac_authenticate", format!("{}B", size)),
            &size,
            |b, &_size| {
                b.iter(|| {
                    let tag = HMAC::authenticate(black_box(&key), black_box(&message));
                    black_box(tag)
                });
            },
        );
        
        let tag = HMAC::authenticate(&key, &message);
        group.bench_with_input(
            BenchmarkId::new("hmac_verify", format!("{}B", size)),
            &size,
            |b, &_size| {
                b.iter(|| {
                    let result = HMAC::verify(black_box(&key), black_box(&message), black_box(&tag));
                    black_box(result)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark field arithmetic operations
fn bench_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_operations");
    
    let a = 1234567890123456789u64;
    let b = 9876543210987654321u64;
    
    group.bench_function("field_add", |bench| {
        bench.iter(|| {
            let result = field_add(black_box(a), black_box(b));
            black_box(result)
        });
    });
    
    group.bench_function("field_sub", |bench| {
        bench.iter(|| {
            let result = field_sub(black_box(a), black_box(b));
            black_box(result)
        });
    });
    
    group.bench_function("field_mul", |bench| {
        bench.iter(|| {
            let result = field_mul(black_box(a), black_box(b));
            black_box(result)
        });
    });
    
    // Benchmark batch operations
    let values_a = vec![a; 1000];
    let values_b = vec![b; 1000];
    
    group.bench_function("field_add_batch_1000", |b| {
        b.iter(|| {
            let results: Vec<_> = values_a.iter().zip(values_b.iter())
                .map(|(&x, &y)| field_add(x, y))
                .collect();
            black_box(results)
        });
    });
    
    group.bench_function("field_mul_batch_1000", |b| {
        b.iter(|| {
            let results: Vec<_> = values_a.iter().zip(values_b.iter())
                .map(|(&x, &y)| field_mul(x, y))
                .collect();
            black_box(results)
        });
    });
    
    group.finish();
}

/// Benchmark oblivious transfer operations
fn bench_oblivious_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("oblivious_transfer");
    
    let msg0 = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let msg1 = vec![9u8, 10, 11, 12, 13, 14, 15, 16];
    let choice = true;
    
    group.bench_function("ot_setup", |b| {
        b.iter(|| {
            let ot = BasicOT::new();
            black_box(ot)
        });
    });
    
    group.bench_function("ot_sender_phase1", |b| {
        b.iter(|| {
            let mut ot = BasicOT::new();
            let result = ot.sender_phase1(black_box(msg0.clone()), black_box(msg1.clone()));
            black_box(result)
        });
    });
    
    group.bench_function("ot_receiver_phase1", |b| {
        let mut ot = BasicOT::new();
        let sender_public = ot.sender_phase1(msg0.clone(), msg1.clone()).unwrap();
        
        b.iter(|| {
            let mut ot = BasicOT::new();
            let result = ot.receiver_phase1(black_box(choice), black_box(sender_public));
            black_box(result)
        });
    });
    
    group.finish();
}

/// Benchmark complete MPC workflows
fn bench_mpc_workflows(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpc_workflows");
    group.sample_size(10); // Reduce sample size for complex workflows
    
    // Benchmark secure sum computation
    group.bench_function("secure_sum_5_parties", |b| {
        let values = vec![100u64, 200u64, 300u64, 400u64, 500u64];
        let threshold = 3;
        let parties = 5;
        
        b.iter(|| {
            // Share all values
            let mut all_shares = Vec::new();
            for &value in &values {
                let shares = ShamirSecretSharing::share(&value, threshold, parties).unwrap();
                all_shares.push(shares);
            }
            
            // Compute sum using homomorphic addition
            let mut sum_shares = all_shares[0].clone();
            for shares in &all_shares[1..] {
                for (i, share) in shares.iter().enumerate() {
                    sum_shares[i] = ShamirSecretSharing::add_shares(&sum_shares[i], share).unwrap();
                }
            }
            
            // Reconstruct result
            let result = ShamirSecretSharing::reconstruct(&sum_shares[0..threshold], threshold);
            black_box(result)
        });
    });
    
    // Benchmark secure auction
    group.bench_function("secure_auction_10_bidders", |b| {
        let bids = vec![1000u64, 1500u64, 1200u64, 1800u64, 1100u64, 1600u64, 1300u64, 1700u64, 1400u64, 1900u64];
        
        b.iter(|| {
            // Commit to all bids
            let mut commitments = Vec::new();
            let mut randomness_values = Vec::new();
            
            for (i, &bid) in bids.iter().enumerate() {
                let randomness = 12345u64 + i as u64;
                let commitment = HashCommitment::commit_u64(bid, randomness);
                commitments.push(commitment);
                randomness_values.push(randomness);
            }
            
            // Find maximum (simplified)
            let mut max_bid = 0u64;
            for (i, &bid) in bids.iter().enumerate() {
                let is_valid = HashCommitment::verify_u64(&commitments[i], bid, randomness_values[i]);
                if is_valid && bid > max_bid {
                    max_bid = bid;
                }
            }
            
            black_box(max_bid)
        });
    });
    
    group.finish();
}

/// Benchmark memory usage and allocation patterns
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    
    // Benchmark memory allocation for different data structures
    group.bench_function("share_vector_allocation_1000", |b| {
        b.iter(|| {
            let shares: Vec<Share> = (0..1000)
                .map(|i| Share::new(i as u64, (i * 2) as u64))
                .collect();
            black_box(shares)
        });
    });
    
    group.bench_function("beaver_triple_allocation_100", |b| {
        b.iter(|| {
            let mut generator = TrustedPartyBeaverGenerator::new(5, 3, 0, None).unwrap();
            let triples: Result<Vec<_>> = (0..100)
                .map(|_| generator.generate_single())
                .collect();
            black_box(triples)
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_secret_sharing,
    bench_beaver_triples,
    bench_commitments,
    bench_authentication,
    bench_field_operations,
    bench_oblivious_transfer,
    bench_mpc_workflows,
    bench_memory_usage
);

criterion_main!(benches);