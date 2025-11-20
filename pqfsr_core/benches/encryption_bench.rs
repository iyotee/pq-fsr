/// ENCRYPTION/DECRYPTION LATENCY BENCHMARKS
/// =========================================
/// Measures encryption and decryption performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use pqfsr_core::RatchetSession;

fn setup_session_pair() -> (RatchetSession, RatchetSession) {
    let mut alice = RatchetSession::create_initiator(b"alice_bench".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_bench".to_vec(), 50);
    
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    (alice, bob)
}

fn bench_encrypt_small(c: &mut Criterion) {
    let (mut alice, _) = setup_session_pair();
    let message = vec![0u8; 64]; // 64 bytes
    
    c.bench_function("encrypt_64_bytes", |b| {
        b.iter(|| {
            let packet = alice.encrypt(black_box(&message), black_box(b"")).unwrap();
            black_box(packet)
        });
    });
}

fn bench_encrypt_medium(c: &mut Criterion) {
    let (mut alice, _) = setup_session_pair();
    let message = vec![0u8; 1024]; // 1 KB
    
    c.bench_function("encrypt_1kb", |b| {
        b.iter(|| {
            let packet = alice.encrypt(black_box(&message), black_box(b"")).unwrap();
            black_box(packet)
        });
    });
}

fn bench_encrypt_large(c: &mut Criterion) {
    let (mut alice, _) = setup_session_pair();
    let message = vec![0u8; 64 * 1024]; // 64 KB
    
    c.bench_function("encrypt_64kb", |b| {
        b.iter(|| {
            let packet = alice.encrypt(black_box(&message), black_box(b"")).unwrap();
            black_box(packet)
        });
    });
}

fn bench_decrypt_small(c: &mut Criterion) {
    let (mut alice, mut bob) = setup_session_pair();
    let message = vec![0u8; 64];
    let packet = alice.encrypt(&message, b"").unwrap();
    
    c.bench_function("decrypt_64_bytes", |b| {
        b.iter(|| {
            let decrypted = bob.decrypt(black_box(&packet), black_box(b"")).unwrap();
            black_box(decrypted)
        });
    });
}

fn bench_decrypt_medium(c: &mut Criterion) {
    let (mut alice, mut bob) = setup_session_pair();
    let message = vec![0u8; 1024];
    let packet = alice.encrypt(&message, b"").unwrap();
    
    c.bench_function("decrypt_1kb", |b| {
        b.iter(|| {
            let decrypted = bob.decrypt(black_box(&packet), black_box(b"")).unwrap();
            black_box(decrypted)
        });
    });
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");
    
    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            format!("roundtrip_{}b", size),
            size,
            |b, &size| {
                let (mut alice, mut bob) = setup_session_pair();
                let message = vec![0u8; size];
                
                b.iter(|| {
                    let packet = alice.encrypt(black_box(&message), black_box(b"")).unwrap();
                    let decrypted = bob.decrypt(black_box(&packet), black_box(b"")).unwrap();
                    black_box(decrypted)
                });
            },
        );
    }
    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    
    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            format!("encrypt_throughput_{}b", size),
            size,
            |b, &size| {
                let (mut alice, _) = setup_session_pair();
                let message = vec![0u8; size];
                
                b.iter(|| {
                    let packet = alice.encrypt(black_box(&message), black_box(b"")).unwrap();
                    black_box(packet)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt_small,
    bench_encrypt_medium,
    bench_encrypt_large,
    bench_decrypt_small,
    bench_decrypt_medium,
    bench_roundtrip,
    bench_throughput
);
criterion_main!(benches);

