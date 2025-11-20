"""Test utilities for PQ-FSR test suite."""

import hashlib
import copy
from typing import Callable, Tuple

from pqfsr import RatchetSession


def make_rng(seed: bytes) -> Callable[[int], bytes]:
    """Create a deterministic RNG function from a seed."""
    counter = 0

    def rng(n: int) -> bytes:
        nonlocal counter
        buffer = bytearray()
        while len(buffer) < n:
            block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
            buffer.extend(block)
            counter += 1
        return bytes(buffer[:n])

    return rng


def create_test_sessions(
    seed: bytes = b"test-seed",
    semantic_hint_a: bytes = b"alice",
    semantic_hint_b: bytes = b"bob",
    max_skip: int = 50, # Updated default
) -> Tuple[RatchetSession, RatchetSession]:
    """Create and handshake two test sessions."""
    # Rust implementation doesn't need KEM or RNG parameters
    alice = RatchetSession.create_initiator(
        semantic_hint=semantic_hint_a, max_skip=max_skip
    )
    bob = RatchetSession.create_responder(
        semantic_hint=semantic_hint_b, max_skip=max_skip
    )

    request = alice.create_handshake_request()
    response = bob.accept_handshake(request)
    alice.finalize_handshake(response)

    return alice, bob


def validate_packet_structure(packet: dict) -> bool:
    """Validate that a packet has the expected structure."""
    # Updated for new format where auth_tag is optional/implicit
    required_keys = {"header", "ciphertext"} # nonce is optional
    if not all(key in packet for key in required_keys):
        return False

    header = packet["header"]
    required_header_keys = {"version", "count", "ratchet_pub", "kem_ciphertext", "semantic_tag"}
    if not all(key in header for key in required_header_keys):
        return False

    return True


def tamper_packet(packet: dict, field: str, value) -> dict:
    """Create a tampered copy of a packet."""
    tampered = copy.deepcopy(packet)
    if field == "ciphertext":
        tampered["ciphertext"] = value
    elif field == "auth_tag":
        # If auth_tag is separate, tamper it.
        # If using XORHMACCipher (default in tests), it's part of ciphertext (last 32 bytes).
        # But RatchetSession.encrypt returns 'ciphertext' containing both.
        # So tampering 'auth_tag' means tampering the end of 'ciphertext'.
        if "auth_tag" in tampered:
             tampered["auth_tag"] = value
        else:
             # Tamper the end of ciphertext
             ct = tampered["ciphertext"]
             if len(ct) >= 32:
                 # Replace last 32 bytes
                 tampered["ciphertext"] = ct[:-32] + value[-32:] if len(value) >= 32 else ct[:-32] + value
    elif field in tampered["header"]:
        tampered["header"][field] = value
    elif field == "nonce":
        tampered["nonce"] = value
    return tampered
