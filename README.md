# pq-fsr

Reference implementation of the **Post-Quantum Forward-Secret Ratchet (PQ-FSR)** protocol. The goal of this repository is to provide a compact, dependency-light codebase that researchers can audit, benchmark, and extend.

> **Status**: Proof-of-concept. Cryptanalysis and production reviews are strongly encouraged before any deployment.

## Features

- **"Chronos-Entropy" Architecture**: An adaptive, organic ratchet strategy that dynamically switches between high-security Quantum Pulses (KEM) and high-performance Fluid Flow (Hash Ratchet) based on network conditions and entropy decay.
- **Native forward secrecy and post-compromise security** in a single primitive.
- **High-Performance Rust Core**: All cryptographic operations are implemented in Rust (`pqfsr_core`) for maximum performance and security.
- **Python Bindings**: Complete PyO3 bindings provide a Python-friendly API while leveraging the Rust implementation.
- **Kyber768 KEM**: Post-quantum key encapsulation using Kyber768.
- **Dilithium Signatures**: Post-quantum digital signatures for handshake authentication.
- **CBOR Serialization**: Compact binary serialization format (default), with JSON for backward compatibility.
- **Speculative Key Generation**: Supports pre-computation of ephemeral keys to minimize latency.

## Repository Layout

```
pq-fsr/
├── README.md                 # This document
├── pyproject.toml            # Build / packaging metadata
├── docs/
│   ├── README_RUST.md        # Rust implementation documentation
│   └── spec/
│       └── forward_secret_ratchet.md   # Full protocol specification (NIST-style)
├── pqfsr_core/               # Rust core implementation (REQUIRED)
│   ├── src/                  # Rust source code
│   │   ├── lib.rs            # PyO3 bindings
│   │   ├── crypto.rs         # Cryptographic primitives
│   │   ├── state.rs          # Data structures
│   │   ├── strategy.rs       # Adaptive strategy
│   │   ├── ratchet.rs        # Protocol core
│   │   ├── session.rs        # Session API
│   │   ├── serialization.rs  # Serialization (CBOR/JSON)
│   │   ├── signatures.rs     # Dilithium signatures
│   │   └── error.rs           # Standardized error handling
│   ├── tests/                # Rust test suite (56 tests passing)
│   └── python/pqfsr/         # Python wrapper
│       ├── __init__.py       # Public API
│       └── rust_wrapper.py   # Python compatibility layer
├── tests/                    # Python test suite (125 tests passing)
├── examples/
│   └── examples.ipynb        # Comprehensive usage examples
└── tools/
    └── benchmark.py          # Performance benchmarking
```

## Installation

### Prerequisites

- Rust toolchain (for building the core)
- Python 3.8+
- `maturin` (for building Python bindings): `pip install maturin`

### Build and Install

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install Rust core
cd pqfsr_core
maturin develop
cd ..

# Install Python package
pip install -e .[dev]
```

The Rust core (`pqfsr_core`) is **required** - there is no Python fallback. All cryptographic operations are performed in Rust for maximum performance and security.

## Architecture: Chronos-Entropy

The heart of PQ-FSR is the **Organic Strategy** engine. Unlike traditional protocols that follow rigid rules (e.g., "ratchet every message"), PQ-FSR adapts:

1.  **Quantum Pulse (KEM Ratchet)**: Triggered when entropy decays (time/message count) or opportunistically on large packets. Provides Post-Compromise Security (PCS).
2.  **Fluid Flow (Hash Ratchet)**: Used during high-velocity bursts or stable network conditions to maximize throughput. Provides Forward Secrecy (FS).
3.  **Burst Protection**: The protocol intelligently downgrades to Hash Ratchet during unidirectional bursts to prevent "Root Key Loss" in case of packet drops, ensuring robust message skipping support.

## Quick Start

```python
from pqfsr import RatchetSession

# Pretend we already have long-term keys / fingerprints
alice = RatchetSession.create_initiator(semantic_hint=b"alice", max_skip=32)
bob = RatchetSession.create_responder(semantic_hint=b"bob", max_skip=32)

request = alice.create_handshake_request()
response = bob.accept_handshake(request)
alice.finalize_handshake(response)

packet = alice.encrypt(b"hello quantum")
plaintext = bob.decrypt(packet)
assert plaintext == b"hello quantum"
```

See [`examples/examples.ipynb`](examples/examples.ipynb) for a comprehensive notebook walkthrough including failure recovery, serialization, post-compromise security, and custom KEM usage.

## Testing

### Python Tests

```bash
python3 -m unittest discover tests
```

**Status**: ✅ **128 tests passing, 1 skipped** (hypothesis optional)

The comprehensive test suite includes error handling, security properties, edge cases, handshake variations, serialization, CBOR, signatures, test vectors, and integration scenarios.

### Rust Tests

```bash
cd pqfsr_core
cargo test --no-default-features
```

**Status**: ✅ **60 tests passing**

- `crypto_test.rs`: 5 tests (HKDF, ChaCha20-Poly1305)
- `serialization_test.rs`: 10 tests (JSON, CBOR, wire format)
- `session_test.rs`: 7 tests (handshake, version negotiation, replay protection)
- `signatures_test.rs`: 4 tests (Dilithium)
- `ratchet_test.rs`: 9 tests (bootstrap, encrypt, decrypt)
- `strategy_test.rs`: 14 tests (OrganicStrategy, RatchetMode)
- `integration_test.rs`: 15 tests (end-to-end scenarios, state persistence, forward secrecy)

## Implementation Status

### ✅ Completed Features

- ✅ Complete Rust implementation with PyO3 bindings
- ✅ Kyber768 KEM integration
- ✅ Dilithium signature support
- ✅ CBOR serialization (default, with JSON fallback)
- ✅ Handshake replay protection (TTL cache, timestamp validation)
- ✅ Version negotiation
- ✅ Standardized error handling (PQFSRError)
- ✅ Comprehensive test coverage (56 Rust tests, 125 Python tests)

### 📋 Roadmap

- Performance benchmarks
- Formal verification (ProVerif/Tamarin models)
- Traffic analysis mitigation (padding)
- Group messaging support

## Performance

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for comprehensive performance metrics.

**Quick Summary**:
- Handshake: 119.72 handshakes/sec (8.35ms mean)
- Encryption: Up to 1.95 MB/s for large messages
- Signatures: Key gen 126μs, Sign 284μs, Verify 126μs
- Serialization: CBOR 0.7% smaller and faster than JSON

Run benchmarks:
```bash
# Python benchmarks
python3 tools/benchmark.py

# Rust benchmarks
cd pqfsr_core && cargo bench --no-default-features
```

## Spec & Documentation

- Full protocol details: [`docs/spec/forward_secret_ratchet.md`](docs/spec/forward_secret_ratchet.md)
- Rust implementation: [`docs/README_RUST.md`](docs/README_RUST.md)
- Performance benchmarks: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)

## Threat Matrix

| Threat | Impact | Mitigation |
|--------|--------|------------|
| State compromise | Attacker decrypts future messages | PCS: Adaptive "Quantum Pulse" rotates KEM-derived root keys |
| Ciphertext replay | Duplicate delivery could re-trigger decrypt | Counters + semantic tags (16-byte digest) detect replays |
| Packet tampering | Forged ciphertexts may desync state | HMAC tag verification (constant-time) rejects tampered packets |
| Side-channel leakage | Timing may leak key comparison results | Use of `hmac.compare_digest`; constant-time annotations mark critical checks |
| Storage theft | Serialized state reveals secrets | Specification mandates encrypting `export_state()` output at rest |

## License

Copyright © 2025 Jeremy Noverraz 1988-2025. All rights reserved. Usage requires prior written permission.
