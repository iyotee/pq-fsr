# PQ-FSR Performance Benchmarks

**Last Updated**: 2025  
**Test Environment**: macOS, Python 3.13.2, Rust stable

## Overview

This document provides comprehensive performance benchmarks for the PQ-FSR implementation. All benchmarks were run using the Python benchmark suite (`tools/benchmark.py`) and Rust benchmarks (`pqfsr_core/benches/`).

## Handshake Performance

**Latency**:
- Mean: 8.35 ms
- Median: 8.22 ms
- StdDev: 794 μs
- Min: 7.56 ms
- Max: 19.97 ms

**Throughput**: 119.72 handshakes/sec

The handshake includes:
- KEM key pair generation (Kyber768)
- Dilithium signature generation and verification
- Root key derivation
- State initialization

## Encryption/Decryption Performance

### Small Messages (64 bytes)

- **Encrypt**: 443.88 μs (mean)
- **Decrypt**: 581.54 μs (mean)
- **Total**: 1.03 ms (mean)
- **Throughput**: 144,183 bytes/sec
- **Packet Size**: 1.23 KB
- **Overhead**: 1.17 KB (1875.0% for small messages)

### Medium Messages (256 bytes)

- **Encrypt**: 525.51 μs (mean)
- **Decrypt**: 672.22 μs (mean)
- **Total**: 1.20 ms (mean)
- **Throughput**: 487,143 bytes/sec
- **Packet Size**: 1.42 KB
- **Overhead**: 1.17 KB (468.8%)

### Large Messages (1 KB)

- **Encrypt**: 927.85 μs (mean)
- **Decrypt**: 1.00 ms (mean)
- **Total**: 1.93 ms (mean)
- **Throughput**: 1,103,632 bytes/sec (1.1 MB/s)
- **Packet Size**: 2.17 KB
- **Overhead**: 1.17 KB (117.2%)

### Very Large Messages (64 KB)

- **Encrypt**: 33.59 ms (mean)
- **Decrypt**: 28.78 ms (mean)
- **Total**: 62.38 ms (mean)
- **Throughput**: 1,950,801 bytes/sec (1.95 MB/s)
- **Packet Size**: 65.17 KB
- **Overhead**: 1.17 KB (1.8% - minimal for large messages)

### Observations

- **Fixed Overhead**: ~1.17 KB per packet (KEM ciphertext, ratchet public key, semantic tag)
- **Throughput**: Scales well with message size, reaching ~2 MB/s for large messages
- **Efficiency**: Overhead percentage decreases significantly with larger messages

## Signature Performance (Dilithium)

**Key Generation**: 126.21 μs (mean)  
**Signing** (~120 bytes): 283.97 μs (mean)  
**Verification**: 126.09 μs (mean)

Dilithium signatures provide strong post-quantum security with reasonable performance for handshake authentication.

## Serialization Performance

### CBOR Format (Default)

- **Serialize**: 866.14 μs (mean)
- **Deserialize**: 2.49 ms (mean)
- **Size**: ~10.05 KB (for typical session state)

### JSON Format (Backward Compatibility)

- **Serialize**: 1.64 ms (mean)
- **Deserialize**: 2.91 ms (mean)
- **Size**: ~10.12 KB

### Comparison

- **Size Reduction**: CBOR is 0.7% smaller than JSON
- **Speed**: CBOR is faster for serialization (866μs vs 1.64ms)
- **Recommendation**: Use CBOR for production (default), JSON for debugging

## End-to-End Performance

**Complete Session** (handshake + 10 messages):
- Mean time: 26.68 ms
- Throughput: 37.48 sessions/sec

This includes:
- Full handshake (request, accept, finalize)
- 10 message exchanges (encrypt/decrypt)
- State management

## Bandwidth Overhead Analysis

The protocol adds a fixed overhead of approximately **1.17 KB** per packet, consisting of:
- KEM ciphertext (Kyber768): ~1088 bytes
- Ratchet public key: ~32 bytes
- Semantic tag: 16 bytes
- Header information: ~34 bytes

**Overhead by Message Size**:
- 64 bytes: 1875% overhead (1.17 KB / 64 B)
- 256 bytes: 468.8% overhead
- 1 KB: 117.2% overhead
- 4 KB: 29.3% overhead
- 16 KB: 7.3% overhead
- 64 KB: 1.8% overhead

**Recommendation**: For optimal efficiency, use messages of at least 1 KB. The overhead becomes negligible (>10%) for messages larger than 4 KB.

## Performance Characteristics

### Strengths

1. **Fast Handshake**: ~8ms for complete handshake with post-quantum security
2. **Good Throughput**: Up to ~2 MB/s for large messages
3. **Efficient Signatures**: Dilithium operations complete in <300μs
4. **Compact Serialization**: CBOR provides efficient state storage

### Trade-offs

1. **Fixed Overhead**: ~1.17 KB per packet (acceptable for messages >1 KB)
2. **Handshake Latency**: Includes KEM and signature operations (necessary for security)
3. **Memory**: State serialization ~10 KB (reasonable for session storage)

## Comparison Notes

- **Signal Protocol**: PQ-FSR provides similar security properties with post-quantum primitives
- **Performance**: Comparable to classical ratchets for large messages (>1 KB)
- **Overhead**: Higher for small messages due to post-quantum primitives, but acceptable for typical use cases

## Running Benchmarks

### Python Benchmarks

```bash
python3 tools/benchmark.py
```

### Rust Benchmarks

```bash
cd pqfsr_core
cargo bench --no-default-features
```

## Future Optimizations

Potential areas for improvement:
- Pre-computed KEM keys (speculative key generation)
- Batch signature verification
- Optimized CBOR serialization
- Memory-mapped state storage

