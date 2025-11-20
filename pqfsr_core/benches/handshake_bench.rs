/// HANDSHAKE LATENCY BENCHMARKS
/// =============================
/// Measures handshake performance (request, accept, finalize)

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqfsr_core::RatchetSession;

fn bench_handshake_complete(c: &mut Criterion) {
    c.bench_function("handshake_complete", |b| {
        b.iter(|| {
            let mut alice = RatchetSession::create_initiator(
                black_box(b"alice_bench".to_vec()),
                50,
            );
            let mut bob = RatchetSession::create_responder(
                black_box(b"bob_bench".to_vec()),
                50,
            );
            
            let request = alice.create_handshake_request().unwrap();
            let response = bob.accept_handshake(&request).unwrap();
            alice.finalize_handshake(&response).unwrap();
            
            black_box((alice, bob))
        });
    });
}

fn bench_handshake_request(c: &mut Criterion) {
    c.bench_function("handshake_request", |b| {
        b.iter(|| {
            let mut alice = RatchetSession::create_initiator(
                black_box(b"alice_bench".to_vec()),
                50,
            );
            let request = alice.create_handshake_request().unwrap();
            black_box(request)
        });
    });
}

fn bench_handshake_accept(c: &mut Criterion) {
    c.bench_function("handshake_accept", |b| {
        let mut alice = RatchetSession::create_initiator(
            b"alice_bench".to_vec(),
            50,
        );
        let request = alice.create_handshake_request().unwrap();
        
        b.iter(|| {
            let mut bob = RatchetSession::create_responder(
                black_box(b"bob_bench".to_vec()),
                50,
            );
            let response = bob.accept_handshake(&request).unwrap();
            black_box(response)
        });
    });
}

fn bench_handshake_finalize(c: &mut Criterion) {
    c.bench_function("handshake_finalize", |b| {
        let mut alice = RatchetSession::create_initiator(
            b"alice_bench".to_vec(),
            50,
        );
        let mut bob = RatchetSession::create_responder(
            b"bob_bench".to_vec(),
            50,
        );
        let request = alice.create_handshake_request().unwrap();
        let response = bob.accept_handshake(&request).unwrap();
        
        b.iter(|| {
            let mut alice_clone = RatchetSession::create_initiator(
                b"alice_bench".to_vec(),
                50,
            );
            let request_clone = alice_clone.create_handshake_request().unwrap();
            let response_clone = bob.accept_handshake(&request_clone).unwrap();
            alice_clone.finalize_handshake(&response_clone).unwrap();
            black_box(alice_clone)
        });
    });
}

criterion_group!(benches, bench_handshake_complete, bench_handshake_request, bench_handshake_accept, bench_handshake_finalize);
criterion_main!(benches);

