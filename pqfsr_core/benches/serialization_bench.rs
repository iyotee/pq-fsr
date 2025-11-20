/// SERIALIZATION PERFORMANCE BENCHMARKS
/// =====================================
/// Measures state serialization/deserialization performance

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqfsr_core::{RatchetSession, serialization};

fn setup_session() -> RatchetSession {
    let mut alice = RatchetSession::create_initiator(b"alice_bench".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_bench".to_vec(), 50);
    
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    // Send some messages to populate state
    for _ in 0..10 {
        let packet = alice.encrypt(b"test message", b"").unwrap();
        bob.decrypt(&packet, b"").unwrap();
    }
    
    alice
}

fn bench_serialize_cbor(c: &mut Criterion) {
    let alice = setup_session();
    let state = alice.get_state().unwrap();
    let semantic_hint = alice.semantic_hint();
    let is_initiator = alice.is_initiator();
    
    c.bench_function("serialize_state_cbor", |b| {
        b.iter(|| {
            let serialized = serialization::serialize_state_cbor(
                black_box(state),
                black_box(&semantic_hint),
                black_box(is_initiator),
            );
            black_box(serialized)
        });
    });
}

fn bench_deserialize_cbor(c: &mut Criterion) {
    let alice = setup_session();
    let state = alice.get_state().unwrap();
    let semantic_hint = alice.semantic_hint();
    let is_initiator = alice.is_initiator();
    let serialized = serialization::serialize_state_cbor(state, &semantic_hint, is_initiator);
    
    c.bench_function("deserialize_state_cbor", |b| {
        b.iter(|| {
            let (state, hint, init) = serialization::deserialize_state_cbor(black_box(&serialized)).unwrap();
            black_box((state, hint, init))
        });
    });
}

fn bench_serialize_roundtrip(c: &mut Criterion) {
    let alice = setup_session();
    let state = alice.get_state().unwrap();
    let semantic_hint = alice.semantic_hint();
    let is_initiator = alice.is_initiator();
    
    c.bench_function("serialize_deserialize_roundtrip", |b| {
        b.iter(|| {
            let serialized = serialization::serialize_state_cbor(
                black_box(state),
                black_box(&semantic_hint),
                black_box(is_initiator),
            );
            let (_, _, _) = serialization::deserialize_state_cbor(black_box(&serialized)).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_serialize_cbor,
    bench_deserialize_cbor,
    bench_serialize_roundtrip
);
criterion_main!(benches);

