"""
PQ-FSR Performance Benchmarks
=============================
Comprehensive performance benchmarks for PQ-FSR protocol.

Measures:
- Handshake latency
- Encryption/decryption latency
- Throughput
- Memory usage
- Bandwidth overhead
"""

import time
import statistics
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pqfsr import RatchetSession, DilithiumSignatures


def format_time(ns):
    """Format nanoseconds to human-readable time"""
    if ns < 1000:
        return f"{ns:.2f} ns"
    elif ns < 1_000_000:
        return f"{ns / 1000:.2f} μs"
    elif ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    else:
        return f"{ns / 1_000_000_000:.2f} s"


def format_bytes(bytes_val):
    """Format bytes to human-readable size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} TB"


def benchmark_handshake(iterations=1000):
    """Benchmark complete handshake flow"""
    print("\n" + "=" * 60)
    print("HANDSHAKE LATENCY BENCHMARK")
    print("=" * 60)
    
    times = []
    
    for _ in range(iterations):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice_bench", max_skip=50)
        bob = RatchetSession.create_responder(semantic_hint=b"bob_bench", max_skip=50)
        
        start = time.perf_counter_ns()
        request = alice.create_handshake_request()
        request_time = time.perf_counter_ns() - start
        
        start = time.perf_counter_ns()
        response = bob.accept_handshake(request)
        accept_time = time.perf_counter_ns() - start
        
        start = time.perf_counter_ns()
        alice.finalize_handshake(response)
        finalize_time = time.perf_counter_ns() - start
        
        total_time = request_time + accept_time + finalize_time
        times.append(total_time)
    
    mean = statistics.mean(times)
    median = statistics.median(times)
    stdev = statistics.stdev(times) if len(times) > 1 else 0
    min_time = min(times)
    max_time = max(times)
    
    print(f"Iterations: {iterations}")
    print(f"Mean:   {format_time(mean)}")
    print(f"Median: {format_time(median)}")
    print(f"StdDev: {format_time(stdev)}")
    print(f"Min:    {format_time(min_time)}")
    print(f"Max:    {format_time(max_time)}")
    print(f"Throughput: {iterations / (sum(times) / 1_000_000_000):.2f} handshakes/sec")


def benchmark_encryption(message_sizes=[64, 256, 1024, 4096, 16384, 65536], iterations=1000):
    """Benchmark encryption/decryption for different message sizes"""
    print("\n" + "=" * 60)
    print("ENCRYPTION/DECRYPTION LATENCY BENCHMARK")
    print("=" * 60)
    
    # Setup session pair
    alice = RatchetSession.create_initiator(semantic_hint=b"alice_bench", max_skip=50)
    bob = RatchetSession.create_responder(semantic_hint=b"bob_bench", max_skip=50)
    
    request = alice.create_handshake_request()
    response = bob.accept_handshake(request)
    alice.finalize_handshake(response)
    
    for size in message_sizes:
        message = b"x" * size
        
        # Encryption benchmark
        encrypt_times = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            packet = alice.encrypt(message, b"")
            encrypt_times.append(time.perf_counter_ns() - start)
        
        # Decryption benchmark
        packet = alice.encrypt(message, b"")
        decrypt_times = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            plaintext = bob.decrypt(packet, b"")
            decrypt_times.append(time.perf_counter_ns() - start)
            # Need to re-encrypt for next iteration
            packet = alice.encrypt(message, b"")
        
        encrypt_mean = statistics.mean(encrypt_times)
        decrypt_mean = statistics.mean(decrypt_times)
        total_mean = encrypt_mean + decrypt_mean
        
        # Calculate bandwidth overhead
        packet_size = len(packet["header"]["ratchet_pub"]) + len(packet["ciphertext"])
        overhead = packet_size - size
        overhead_percent = (overhead / size) * 100 if size > 0 else 0
        
        print(f"\nMessage Size: {format_bytes(size)}")
        print(f"  Encrypt: {format_time(encrypt_mean)} (mean)")
        print(f"  Decrypt: {format_time(decrypt_mean)} (mean)")
        print(f"  Total:   {format_time(total_mean)} (mean)")
        print(f"  Throughput: {size / (encrypt_mean / 1_000_000_000):.2f} bytes/sec")
        print(f"  Packet Size: {format_bytes(packet_size)}")
        print(f"  Overhead: {format_bytes(overhead)} ({overhead_percent:.1f}%)")


def benchmark_signatures(iterations=1000):
    """Benchmark Dilithium signature operations"""
    print("\n" + "=" * 60)
    print("SIGNATURE PERFORMANCE BENCHMARK")
    print("=" * 60)
    
    # Key generation
    keygen_times = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        pk, sk = DilithiumSignatures.generate_key_pair()
        keygen_times.append(time.perf_counter_ns() - start)
    
    pk, sk = DilithiumSignatures.generate_key_pair()
    message = b"test message" * 10  # ~120 bytes
    
    # Signing
    sign_times = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        signature = DilithiumSignatures.sign_message(message, sk)
        sign_times.append(time.perf_counter_ns() - start)
    
    signature = DilithiumSignatures.sign_message(message, sk)
    
    # Verification
    verify_times = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        valid = DilithiumSignatures.verify_signature(message, signature, pk)
        verify_times.append(time.perf_counter_ns() - start)
    
    print(f"Iterations: {iterations}")
    print(f"\nKey Generation:")
    print(f"  Mean: {format_time(statistics.mean(keygen_times))}")
    print(f"\nSigning (~120 bytes):")
    print(f"  Mean: {format_time(statistics.mean(sign_times))}")
    print(f"\nVerification:")
    print(f"  Mean: {format_time(statistics.mean(verify_times))}")


def benchmark_serialization(iterations=1000):
    """Benchmark state serialization/deserialization"""
    print("\n" + "=" * 60)
    print("SERIALIZATION PERFORMANCE BENCHMARK")
    print("=" * 60)
    
    # Setup session with some state
    alice = RatchetSession.create_initiator(semantic_hint=b"alice_bench", max_skip=50)
    bob = RatchetSession.create_responder(semantic_hint=b"bob_bench", max_skip=50)
    
    request = alice.create_handshake_request()
    response = bob.accept_handshake(request)
    alice.finalize_handshake(response)
    
    # Send some messages to populate state
    for _ in range(10):
        packet = alice.encrypt(b"test message", b"")
        bob.decrypt(packet, b"")
    
    # CBOR serialization
    cbor_serialize_times = []
    cbor_deserialize_times = []
    
    for _ in range(iterations):
        start = time.perf_counter_ns()
        state_cbor = alice.export_state(use_cbor=True)
        cbor_serialize_times.append(time.perf_counter_ns() - start)
        
        start = time.perf_counter_ns()
        alice_restored = RatchetSession.from_serialized(state_cbor)
        cbor_deserialize_times.append(time.perf_counter_ns() - start)
    
    # JSON serialization
    json_serialize_times = []
    json_deserialize_times = []
    
    for _ in range(iterations):
        start = time.perf_counter_ns()
        state_json = alice.export_state(use_cbor=False)
        json_serialize_times.append(time.perf_counter_ns() - start)
        
        start = time.perf_counter_ns()
        alice_restored = RatchetSession.from_serialized(state_json)
        json_deserialize_times.append(time.perf_counter_ns() - start)
    
    state_cbor = alice.export_state(use_cbor=True)
    state_json = alice.export_state(use_cbor=False)
    
    print(f"Iterations: {iterations}")
    print(f"\nCBOR Format:")
    print(f"  Serialize:   {format_time(statistics.mean(cbor_serialize_times))} (mean)")
    print(f"  Deserialize: {format_time(statistics.mean(cbor_deserialize_times))} (mean)")
    print(f"  Size:        {format_bytes(len(state_cbor))}")
    print(f"\nJSON Format:")
    print(f"  Serialize:   {format_time(statistics.mean(json_serialize_times))} (mean)")
    print(f"  Deserialize: {format_time(statistics.mean(json_deserialize_times))} (mean)")
    print(f"  Size:        {format_bytes(len(state_json))}")
    print(f"\nSize Reduction: {((len(state_json) - len(state_cbor)) / len(state_json) * 100):.1f}% smaller (CBOR vs JSON)")


def benchmark_end_to_end(iterations=100):
    """Benchmark complete end-to-end message exchange"""
    print("\n" + "=" * 60)
    print("END-TO-END BENCHMARK")
    print("=" * 60)
    
    times = []
    message = b"Hello, PQ-FSR world!" * 50  # ~1KB
    
    for _ in range(iterations):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice_bench", max_skip=50)
        bob = RatchetSession.create_responder(semantic_hint=b"bob_bench", max_skip=50)
        
        start = time.perf_counter_ns()
        
        # Handshake
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Exchange messages
        for _ in range(10):
            packet = alice.encrypt(message, b"")
            plaintext = bob.decrypt(packet, b"")
            assert plaintext == message
        
        total_time = time.perf_counter_ns() - start
        times.append(total_time)
    
    mean = statistics.mean(times)
    print(f"Iterations: {iterations}")
    print(f"Mean time per session (handshake + 10 messages): {format_time(mean)}")
    print(f"Throughput: {iterations / (sum(times) / 1_000_000_000):.2f} sessions/sec")


def main():
    """Run all benchmarks"""
    print("=" * 60)
    print("PQ-FSR PERFORMANCE BENCHMARKS")
    print("=" * 60)
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    
    try:
        benchmark_handshake(iterations=1000)
        benchmark_encryption(iterations=1000)
        benchmark_signatures(iterations=1000)
        benchmark_serialization(iterations=1000)
        benchmark_end_to_end(iterations=100)
        
        print("\n" + "=" * 60)
        print("BENCHMARKS COMPLETE")
        print("=" * 60)
    except Exception as e:
        print(f"\nError during benchmarking: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
