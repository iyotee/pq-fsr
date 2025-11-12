# PQ-FSR Mapping to NIST Evaluation Criteria

| Criterion | PQ-FSR Artifact / Reference | Notes |
|-----------|----------------------------|-------|
| Security strength | `docs/spec/forward_secret_ratchet.md` §3, §9 | Targets Kyber security levels; future work: formal proofs |
| Design rationale | `docs/whitepaper.md`, README threat matrix | Motivations vs existing PQC primitives |
| Algorithm specification | `docs/spec/forward_secret_ratchet.md` | Includes notation, algorithms, and transcripts |
| Reference implementation | `src/pqfsr/ratchet.py` | Pure Python, deterministic RNG injection for testing |
| Test vectors | `docs/nist_dossier/test_vectors.json`, `tests/test_vectors.py` | Hex-encoded handshake + message sample |
| Proof of correctness | (Planned) – currently informal arguments in §9 of spec | To be supplemented with formal proof document |
| Performance analysis | `tools/benchmark.py`, README "Roadmap" section | Benchmark script produces per-message timings |
| Side-channel considerations | README threat matrix, inline constant-time comments | Highlights use of `hmac.compare_digest` and areas needing native hardening |
| Reference parameters | README "Roadmap" + spec §10 | Lists KEM variants and MAX_SKIP guidance |
| Supporting documentation | `docs/presentation_outline.md`, `docs/outreach_checklist.md` | Materials for workshops and reviewer coordination |
