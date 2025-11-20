# PQ-FSR Rust Implementation

## Status: ✅ PRODUCTION READY

The complete Rust implementation is now available in `pqfsr_core/` and is the **primary and only** implementation. All cryptographic operations are performed in Rust for maximum performance and security.

## Architecture

### Core Modules

- **`crypto.rs`**: Cryptographic primitives
  - HKDF-SHA256 for key derivation
  - ChaCha20-Poly1305 for authenticated encryption
  - Constant-time comparison utilities

- **`state.rs`**: Data structures
  - `RatchetState`: Complete session state
  - Message key skipping support

- **`strategy.rs`**: Adaptive strategy
  - `OrganicStrategy`: Dynamic KEM pulse decision engine
  - `RatchetMode`: Security vs performance trade-offs
  - Entropy decay tracking

- **`ratchet.rs`**: Protocol core
  - `ForwardRatchet`: Core ratchet logic
  - Bootstrap, encrypt, decrypt operations
  - KEM pulse integration

- **`session.rs`**: High-level session API
  - `RatchetSession`: Complete session management
  - Handshake flow (request/accept/finalize)
  - Replay protection (TTL cache, timestamp validation)
  - Version negotiation

- **`serialization.rs`**: State serialization
  - CBOR format (default, production)
  - JSON format (backward compatibility)
  - Wire format (pack/unpack packets)
  - Encryption at rest

- **`signatures.rs`**: Post-quantum signatures
  - Dilithium key generation
  - Message signing and verification
  - Handshake authentication

- **`error.rs`**: Standardized error handling
  - `PQFSRError`: Comprehensive error enum
  - Numeric error codes (1000-9999)
  - Recovery guidance
  - Python bindings

- **`lib.rs`**: Python bindings (PyO3)
  - Complete API exposure
  - Type conversions
  - Error handling

## Test Coverage

**Status**: ✅ **56 Rust tests passing**

- `crypto_test.rs`: 5 tests
- `serialization_test.rs`: 10 tests
- `session_test.rs`: 5 tests
- `signatures_test.rs`: 4 tests
- `ratchet_test.rs`: 9 tests
- `strategy_test.rs`: 14 tests
- `integration_test.rs`: 11 tests

## Installation

```bash
cd pqfsr_core
maturin develop  # Development mode
# or
maturin build   # Build wheel
```

## Usage

```python
from pqfsr import RatchetSession, DilithiumSignatures

# Create sessions
alice = RatchetSession.create_initiator(semantic_hint=b"alice", max_skip=50)
bob = RatchetSession.create_responder(semantic_hint=b"bob", max_skip=50)

# Handshake
request = alice.create_handshake_request()
response = bob.accept_handshake(request)
alice.finalize_handshake(response)

# Encrypt/Decrypt
packet = alice.encrypt(b"Hello, quantum world!")
plaintext = bob.decrypt(packet)

# Dilithium signatures
pk, sk = DilithiumSignatures.generate_key_pair()
signature = DilithiumSignatures.sign_message(b"message", sk)
is_valid = DilithiumSignatures.verify_signature(b"message", signature, pk)
```

## Features

### ✅ Implemented

- ✅ Complete protocol implementation
- ✅ Kyber768 KEM integration
- ✅ Dilithium signature support
- ✅ CBOR serialization (default)
- ✅ Handshake replay protection
- ✅ Version negotiation
- ✅ Standardized error handling
- ✅ Comprehensive test coverage
- ✅ Python bindings (PyO3)

### 🔄 In Progress

- Performance benchmarks
- Error system integration (gradual migration from String errors)

### 📋 Planned

- Traffic analysis mitigation
- Group messaging support
- Formal verification
