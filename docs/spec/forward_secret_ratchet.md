# PQ-FSR: Post-Quantum Forward-Secret Ratchet Specification

## Goals

- Deliver forward secrecy (FS) and post-compromise security (PCS) in a single primitive suitable for asynchronous messaging.
- Leverage a post-quantum KEM (Kyber-compatible interface) to refresh root keys on every sending ratchet step.
- Keep all symmetric material derivable from transcript data (HKDF-style) so that implementations can be deterministic for testing.
- Remain analytics-friendly: constant-time where feasible, bounded skipped-key cache, and well-defined serialization formats.

## Threat Model

- The adversary can compromise long-term identity keys or medium-term storage at arbitrary times.
- The adversary can record, delay, drop, or reorder any ciphertexts on the wire.
- The adversary cannot forge KEM ciphertexts or MACs without compromising the corresponding private state.
- Side-channel leakage is limited to timing/power (no invasive hardware attacks). Implementations should minimise data-dependent branching.

## Components

1. **Identity Layer**
   - Each party exposes a public prekey bundle: KEM public key + optional signature over metadata.
   - Semantic hints (32–64 bytes) allow applications to mix external entropy into the transcript (optional in the reference code).

2. **Handshake**
   - Initiator sends `{version, handshake_id, kem_public, ratchet_public, semantic_hint}`.
   - Responder encapsulates to `kem_public`, returns `{version, handshake_id, kem_ciphertext, ratchet_public, semantic_hint}`.
   - Both parties derive an initial root key `RK0 = HKDF(SS || semantic_A || semantic_B, "PQ-FSR root")`.

3. **Symmetric Ratchet**
   - Maintain per-direction counters `send_count` and `recv_count`.
   - Derive message keys with `HKDF(chain_key || counter, "PQ-FSR msg")`.
   - Nonces are derived from the same material; no random IVs are required beyond the KEM entropy.

4. **KEM Ratchet**
   - Every outbound message encapsulates to the latest remote ratchet public key.
   - The shared secret from the KEM step refreshes the root key: `root = HKDF(root || shared_secret, "PQ-FSR root")`.
   - Fresh send/receive chain keys are computed as:
     - `send_chain = HKDF(root, "PQ-FSR chain A->B")`
     - `recv_chain = HKDF(root, "PQ-FSR chain B->A")` (roles swapped for the responder).

5. **Skipped Message Cache**
   - Store up to `max_skip` message keys keyed by `(counter)`.
   - When a message arrives with `count < recv_count`, try the cache and delete on use. Overflow drops the oldest entry.

6. **Post-Compromise Recovery**
   - Once an attacker exfiltrates device state, learning future plaintexts requires intercepting the next KEM ratchet message.
   - After the first uncompromised inbound message, the attacker loses access to subsequent traffic.

## Message Format

```
struct RatchetPacket {
    uint32 version;
    uint32 message_index;
    bytes  kem_ciphertext;
    bytes  ratchet_public_key; // included when the sender rotates keys
    bytes  semantic_tag;       // HKDF output binding semantic hints + counter
    bytes  nonce;              // Derived IV (for audit/debug; optional on the wire)
    bytes  ciphertext;         // XOR stream in the reference implementation
    bytes  auth_tag;           // HMAC-SHA256 in the reference implementation
}
```

Applications may omit the explicit `nonce` field if both sides derive it deterministically (which the reference code does). It is included here to ease interoperability testing.

## Constant-Time Guidance

- Always compare MACs, semantic tags, and cached keys using constant-time equality.
- Avoid branching on secrets when looking up skipped keys.
- Memory zeroisation (`hmac.compare_digest` + `bytearray` scrubbing) is best-effort in Python; native implementations should wipe keys deterministically.

## Serialization

- Sessions can export/import state as JSON using only fixed-size byte strings and integers.
- Persisted fields: root key, chain keys, counters, local/remote ratchet keys, skipped cache, semantic hints.
- Consumers must encrypt serialized blobs at rest; the format does not provide standalone secrecy.

## Compliance Checklist

- [x] Forward secrecy: each message derives from a fresh KEM shared secret.
- [x] Post-compromise security: state snapshots fail to decrypt after one honest incoming ratchet step.
- [x] Skipped message replay window bounded by `max_skip`.
- [x] Deterministic test harness to validate protocol transcripts across implementations.
- [ ] Production-grade Kyber bindings (planned).
- [ ] Formal verification of the state machine (planned).
