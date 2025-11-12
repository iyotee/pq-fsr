# PQ-FSR Whitepaper Summary

## Executive Overview

The Post-Quantum Forward-Secret Ratchet (PQ-FSR) is a messaging primitive that integrates Kyber-compatible KEM steps with a deterministic key-schedule to deliver forward secrecy (FS) and post-compromise security (PCS) in asynchronous environments. Unlike classical double ratchets that combine elliptic-curve Diffie-Hellman with symmetric ratchets, PQ-FSR operates solely with post-quantum assumptions and exposes a compact API suitable for constrained devices.

## Motivation vs Existing NIST PQC Standards

| Capability | Kyber (ML-KEM) | Dilithium (ML-DSA) | SPHINCS+ (SLH-DSA) | PQ-FSR |
|------------|----------------|--------------------|--------------------|--------|
| Key encapsulation | ✅ | ❌ | ❌ | ✅ (per-message) |
| Digital signatures | ❌ | ✅ | ✅ | ❌ (delegated) |
| Forward secrecy | ❌ | ❌ | ❌ | ✅ |
| Post-compromise security | ❌ | ❌ | ❌ | ✅ |
| Asynchronous messaging | ❌ | ❌ | ❌ | ✅ |

PQ-FSR complements the NIST portfolio by covering the protocol layer that currently depends on ad-hoc combinations of PQ KEMs with classical ratchets.

## Security Goals & Model

- **IND-CCA2 KEM foundation**: assumes Kyber-level security for shared secrets.
- **HKDF-SHA256**: used for root/chain/message derivations; modeled as PRF.
- **Adversary**: full channel control, adaptive state compromise, quantum polynomial-time computation.
- **Guarantees**: confidentiality and integrity for delivered messages; FS and PCS once an uncompromised inbound packet is processed.

Known limitations and clarifications:
- Each outbound message rotates KEM keys; out-of-order delivery is supported when packets are replayed in the same sequence they were emitted.
- Storage of serialized state MUST be encrypted at rest.
- AEAD wrapper (currently XOR + HMAC) should be replaced with ChaCha20-Poly1305 or AES-GCM for production deployments.

## Algorithmic Outline

1. **Handshake**: Initiator and responder exchange Kyber prekeys and semantic digests; both derive `rk = HKDF(dig_AB, ss, "PQ-FSR root")`.
2. **Send**: For every message, sender encapsulates to the latest remote public key, rotates `rk`, derives `(mk, nonce)`, and emits `{header, ciphertext, tag}`.
3. **Receive**: Receiver decapsulates, recomputes `rk`, validates semantic tag, and decrypts. Skipped packets within the same ratchet step are cached.
4. **Post-compromise**: After compromise, attacker loses visibility once an honest inbound packet refreshes the root.

## Performance Snapshot (Reference Implementation)

| Scenario | Messages | Size | Encrypt (s) | Decrypt (s) | Notes |
|----------|----------|------|-------------|-------------|-------|
| Desktop (Python 3.13) | 1,000 | 256 bytes | 0.18 | 0.17 | Pure Python, no native bindings |
| Desktop (Python 3.13) | 1,000 | 1 KB | 0.54 | 0.51 | Linearly scaling; no optimisation |
| Raspberry Pi 4 (est.) | 1,000 | 256 bytes | ~0.72 | ~0.69 | Estimated from CPython benchmarks |

The `tools/benchmark.py` script reproduces these measurements.

## Research & Standardisation Roadmap

1. **Security review**: open GitHub issues targeting cryptanalysis, constant-time validation, and protocol modelling.
2. **Formal analysis**: prove FS/PCS in the style of UC or Game-based frameworks; integrate with ProVerif/Tamarin (planned).
3. **Interoperability vectors**: publish JSON/hex test vectors (in `tests/test_vectors.py`).
4. **Optimised implementations**: provide Rust/C reference hooking into `pq-fsr` API while preserving deterministic test vectors.
5. **NIST alignment**: prepare dossier referencing security categories, performance, and implementation guidance for future PQ messaging calls.

## Contact & Contribution

- Repository: https://github.com/iyotee/pq-fsr
- Issue labels: `spec`, `security`, `implementation`, `benchmark`
- Preferred feedback: public GitHub issues or private disclosures to security@csf.example
