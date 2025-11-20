import hashlib
import unittest
from typing import List

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

from pqfsr import RatchetSession


def make_rng(seed: bytes):
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


class TestProperty(unittest.TestCase):
    def setUp(self):
        if not HAS_HYPOTHESIS:
            self.skipTest("Hypothesis not installed")

    @unittest.skipIf(not HAS_HYPOTHESIS, "Hypothesis not installed")
    def test_sequence_roundtrip_wrapper(self):
        # We need to wrap hypothesis tests in a way that unittest discovery finds them
        # but doesn't crash on import.
        # However, hypothesis 'given' decorator runs at import time/definition time.
        # So we cannot easily conditionally define them inside a class without hacks.
        # Better approach: If hypothesis is missing, define dummy tests or skip the whole file logic.
        pass

if HAS_HYPOTHESIS:
    @settings(max_examples=50)
    @given(st.lists(st.binary(min_size=0, max_size=64), min_size=1, max_size=6))
    def test_sequence_roundtrip(messages: List[bytes]):
        # Rust implementation doesn't need KEM or RNG parameters
        alice = RatchetSession.create_initiator(semantic_hint=b"alpha")
        bob = RatchetSession.create_responder(semantic_hint=b"beta")

        req = alice.create_handshake_request()
        resp = bob.accept_handshake(req)
        alice.finalize_handshake(resp)

        packets = [alice.encrypt(m) for m in messages]
        recovered = [bob.decrypt(pkt) for pkt in packets]

        assert recovered == messages


    @settings(max_examples=25)
    @given(st.lists(st.binary(min_size=1, max_size=40), min_size=2, max_size=5))
    def test_post_compromise_security(messages: List[bytes]):
        # Rust implementation doesn't need KEM or RNG parameters
        alice = RatchetSession.create_initiator(semantic_hint=b"alpha")
        bob = RatchetSession.create_responder(semantic_hint=b"beta")

        req = alice.create_handshake_request()
        resp = bob.accept_handshake(req)
        alice.finalize_handshake(resp)

        compromised_blob = None

        for idx, message in enumerate(messages):
            packet = alice.encrypt(message)
            bob.decrypt(packet)
            if idx == 0:
                compromised_blob = alice.export_state()

        # Rust implementation doesn't need KEM or RNG parameters
        compromised = RatchetSession.from_serialized(compromised_blob)

        future_packet = alice.encrypt(b"future-secret")
        bob_plain = bob.decrypt(future_packet)
        assert bob_plain == b"future-secret"

        # The compromised snapshot must fail to decrypt due to nonce mismatch / missing root update
        try:
            compromised.decrypt(future_packet)
        except ValueError:
            pass
        else:
            raise AssertionError("Compromised snapshot unexpectedly decrypted the packet")
else:
    # Define dummy tests so unittest doesn't complain about no tests
    class TestHypothesisMissing(unittest.TestCase):
        def test_hypothesis_missing(self):
            print("Skipping property tests: Hypothesis not installed")
