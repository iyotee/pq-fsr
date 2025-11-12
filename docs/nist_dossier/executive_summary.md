# PQ-FSR Executive Summary for NIST Engagement

## Purpose

PQ-FSR (Post-Quantum Forward-Secret Ratchet) fills a critical gap in the NIST PQC portfolio by standardising a protocol primitive that offers forward secrecy (FS) and post-compromise security (PCS) in asynchronous messaging environments. It operates exclusively on post-quantum assumptions and integrates cleanly with existing ML-KEM deployments.

## Highlights

- **Security category alignment**: Designed for Kyber512/768/1024 (NIST Levels 1/3/5). Security scales with underlying KEM strength.
- **Robustness goals**: Provides confidentiality, integrity, FS, PCS, replay protection, and deterministic transcript validation.
- **Transcript determinism**: Reference implementation yields reproducible vectors for interoperability testing.
- **Implementation readiness**: Python reference (`pq-fsr`) with CI, property-based tests, and benchmark harness. Planned native (Rust/C) bindings leverage identical HKDF/KEM workflow.

## Deliverables Included

1. **Specification** – `docs/spec/forward_secret_ratchet.md`
2. **Executive summary** (this document)
3. **Test vectors** – `docs/nist_dossier/test_vectors.json`
4. **Reference implementation** – `src/pqfsr/ratchet.py`
5. **Test suite report** – `pytest` log (generate via `pytest -q`)
6. **Performance data** – `tools/benchmark.py` (smoke test executed in CI)

## Evaluation Checklist

| Criterion | Status | Notes |
|-----------|--------|-------|
| Functionality description | ✅ | Spec + whitepaper summary |
| Security assumptions | ✅ | Section 3 of spec + threat matrix |
| Proof overview | ⚠️ | Informal arguments; formal proof in progress |
| Performance | ✅ | Benchmarks for 256 B & 1 KB payloads |
| Implementation guidance | ✅ | README, threat matrix, serialization notes |
| Test vectors | ✅ | Deterministic JSON vectors |
| Side-channel analysis | ⚠️ | Constant-time touchpoints documented; dedicated audit planned |

## Next Steps Requested from NIST Reviewers

1. Feedback on spec clarity, especially handshake semantics and PCS definition.
2. Cryptanalysis of per-message KEM rotation strategy and semantic tag binding.
3. Guidance on integration into potential “PQC Messaging” track (if established).
4. Recommendations for additional benchmarks (hardware targets, energy profile).

## Points of Contact

- Primary maintainer: CSF-Crypto PQ Team (security@csf.example)
- Repository: https://github.com/iyotee/pq-fsr
