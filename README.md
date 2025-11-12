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

## Relationship to CSF-Crypto

PQ-FSR was extracted from the CSF-Crypto project to give the research community a focused artifact. The CSF implementation now depends on this reference design for its forward-secret messaging layer; upstream changes will be synchronized here before release.

## License

Copyright © 2025 CSF-Crypto. All rights reserved. Usage requires prior written permission.
