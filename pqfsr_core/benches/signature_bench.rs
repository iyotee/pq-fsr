/// SIGNATURE PERFORMANCE BENCHMARKS
/// =================================
/// Measures Dilithium signature generation and verification performance

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqfsr_core::signatures;

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("dilithium_key_generation", |b| {
        b.iter(|| {
            let (pk, sk) = signatures::generate_key_pair();
            black_box((pk, sk))
        });
    });
}

fn bench_sign_small(c: &mut Criterion) {
    let (_, sk) = signatures::generate_key_pair();
    let message = vec![0u8; 64];
    
    c.bench_function("dilithium_sign_64b", |b| {
        b.iter(|| {
            let signature = signatures::sign_message(&message, &sk).unwrap();
            black_box(signature)
        });
    });
}

fn bench_sign_medium(c: &mut Criterion) {
    let (_, sk) = signatures::generate_key_pair();
    let message = vec![0u8; 1024];
    
    c.bench_function("dilithium_sign_1kb", |b| {
        b.iter(|| {
            let signature = signatures::sign_message(&message, &sk).unwrap();
            black_box(signature)
        });
    });
}

fn bench_verify_small(c: &mut Criterion) {
    let (pk, sk) = signatures::generate_key_pair();
    let message = vec![0u8; 64];
    let signature = signatures::sign_message(&message, &sk).unwrap();
    
    c.bench_function("dilithium_verify_64b", |b| {
        b.iter(|| {
            let valid = signatures::verify_signature(&message, &signature, &pk).unwrap();
            black_box(valid)
        });
    });
}

fn bench_verify_medium(c: &mut Criterion) {
    let (pk, sk) = signatures::generate_key_pair();
    let message = vec![0u8; 1024];
    let signature = signatures::sign_message(&message, &sk).unwrap();
    
    c.bench_function("dilithium_verify_1kb", |b| {
        b.iter(|| {
            let valid = signatures::verify_signature(&message, &signature, &pk).unwrap();
            black_box(valid)
        });
    });
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_sign_small,
    bench_sign_medium,
    bench_verify_small,
    bench_verify_medium
);
criterion_main!(benches);

