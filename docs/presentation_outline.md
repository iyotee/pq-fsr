# PQ-FSR Presentation Outline

1. **Title Slide**
   - Project name, authors, contact (security@csf.example)
   - One-line pitch: “Post-Quantum Forward-Secret Ratchet for asynchronous messaging”

2. **Motivation & Gap Analysis**
   - Current NIST PQC portfolio (Kyber/Dilithium/SPHINCS+/McEliece)
   - Missing capability: protocol-level FS/PCS
   - Real-world use cases (messaging apps, IoT command channels, key rotation)

3. **Threat Model & Goals**
   - Channel adversary, adaptive compromise, quantum attacker
   - Desired properties (FS, PCS, replay protection, minimal metadata)

4. **Protocol Overview**
   - Handshake flow (diagram of Req/Resp)
   - Send/receive ratchet interplay (per-message Kyber encapsulation)
   - State variables maintained by each party

5. **Security Arguments**
   - Dependence on Kyber IND-CCA2 and HKDF PRF properties
   - PCS recovery timeline (diagram)
   - Limitations and future work (AEAD choice, out-of-order scope)

6. **Implementation Status**
   - Reference Python package (`pq-fsr`)
   - Test coverage summary (deterministic vectors, Hypothesis checks)
   - Benchmark highlights (desktop vs embedded estimates)

7. **Roadmap & Call to Action**
   - Planned formal proofs, native bindings, public review campaign
   - Desired feedback from NIST/academia (cryptanalysis, performance tuning)
   - How to contribute (GitHub issues, mailing lists, workshops)

8. **Appendix / Backup Slides**
   - Detailed parameter tables (Kyber variants vs security levels)
   - Comparison to classical double ratchet (EC Diffie-Hellman)
   - Serialization formats and test vector snippets
