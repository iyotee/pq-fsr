# pq-fsr

Reference implementation of the **Post-Quantum Forward-Secret Ratchet (PQ-FSR)** protocol. The goal of this repository is to provide a compact, dependency-light codebase that researchers can audit, benchmark, and extend without pulling the full CSF-Crypto stack.

> **Status**: Proof-of-concept. Cryptanalysis and production reviews are strongly encouraged before any deployment.

## Features

- Native forward secrecy and post-compromise security in a single primitive
- Kyber-style KEM abstraction with a pure-Python fallback for testing
- HKDF-like key schedule (SHA-256 based) to ease analysis and reproducibility
- Deterministic test harness with out-of-order delivery and state snapshot checks
- Zero external dependencies at runtime (only the standard library)

## Repository Layout

```
pq-fsr/
├── README.md                 # This document
├── pyproject.toml            # Build / packaging metadata
├── docs/
│   └── spec/
│       └── forward_secret_ratchet.md   # Full protocol specification (NIST-style)
├── src/
│   └── pqfsr/
│       ├── __init__.py       # Public API
│       └── ratchet.py        # Reference ratchet implementation
└── tests/
    └── test_ratchet.py       # Unit tests covering handshake & recovery
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

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

See [`examples/examples.ipynb`](#) *(to be added)* for a notebook walkthrough including failure recovery and serialization.

## Testing

```bash
pytest -q
```

The test suite uses a deterministic stub KEM to avoid third-party dependencies while still exercising the ratchet logic, skipped messages, and post-compromise recovery.

## Spec & Roadmap

- Full protocol details: [`docs/spec/forward_secret_ratchet.md`](docs/spec/forward_secret_ratchet.md)
- Planned milestones: integration of real Kyber bindings, benchmarking harness, and formal verification artifacts.
- NIST-style dossier materials: [`docs/nist_dossier/`](docs/nist_dossier/executive_summary.md)

## Relationship to CSF-Crypto

PQ-FSR was extracted from the CSF-Crypto project to give the research community a focused artifact. The CSF implementation now depends on this reference design for its forward-secret messaging layer; upstream changes will be synchronized here before release.

## Threat Matrix

| Threat | Impact | Mitigation |
|--------|--------|------------|
| State compromise | Attacker decrypts future messages | PCS: next honest inbound packet rotates KEM-derived root keys |
| Ciphertext replay | Duplicate delivery could re-trigger decrypt | Counters + semantic tags (16-byte digest) detect replays |
| Packet tampering | Forged ciphertexts may desync state | HMAC tag verification (constant-time) rejects tampered packets |
| Side-channel leakage | Timing may leak key comparison results | Use of `hmac.compare_digest`; constant-time annotations mark critical checks |
| Storage theft | Serialized state reveals secrets | Specification mandates encrypting `export_state()` output at rest |

## Roadmap

- ✅ Publish reference implementation (`src/pqfsr/ratchet.py`) with deterministic tests (`tests/test_vectors.py`).
- ✅ Provide Hypothesis-based regression checks (`tests/test_property.py`).
- ✅ Deliver benchmarking harness (`tools/benchmark.py`).
- 🔄 Formal security proof (Game-based / UC) – in progress.
- 🔄 Native bindings (Rust/C) sharing test vectors – planned.
- 🔄 Public cryptanalysis review: contact list and issue templates – planned.

## Contributing & Feedback

1. Fork the repository and enable the optional dev dependencies: `pip install -e .[dev]`.
2. Run the full test suite (`pytest -q`) and, where relevant, execute `tools/benchmark.py` before submitting patches.
3. Open GitHub issues using the planned templates (spec, security, implementation, benchmark) and provide reproducible vectors.
4. Security-sensitive disclosures: email security@csf.example with encrypted details (PGP key to be published).
5. Join upcoming PQC forums (announced in issues) for synchronous discussions and review sessions.

## License

Copyright © 2025 CSF-Crypto. All rights reserved. Usage requires prior written permission.
