import hashlib
from typing import List

from hypothesis import given, settings
from hypothesis import strategies as st

from pqfsr import RatchetSession, InMemoryKEM


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


@settings(max_examples=50)
@given(st.lists(st.binary(min_size=0, max_size=64), min_size=1, max_size=6))
def test_sequence_roundtrip(messages: List[bytes]):
    seed = hashlib.sha256(b"".join(msg + b"|" for msg in messages)).digest()
    rng_a = make_rng(seed + b"A")
    rng_b = make_rng(seed + b"B")
    kem_a = InMemoryKEM(rng_a)
    kem_b = InMemoryKEM(rng_b)

    alice = RatchetSession.create_initiator(semantic_hint=b"alpha", random_bytes=rng_a, kem=kem_a)
    bob = RatchetSession.create_responder(semantic_hint=b"beta", random_bytes=rng_b, kem=kem_b)

    req = alice.create_handshake_request()
    resp = bob.accept_handshake(req)
    alice.finalize_handshake(resp)

    packets = [alice.encrypt(m) for m in messages]
    recovered = [bob.decrypt(pkt) for pkt in packets]

    assert recovered == messages


@settings(max_examples=25)
@given(st.lists(st.binary(min_size=1, max_size=40), min_size=2, max_size=5))
def test_post_compromise_security(messages: List[bytes]):
    seed = hashlib.sha256(b"PCS" + b"".join(messages)).digest()
    rng_a = make_rng(seed + b"A")
    rng_b = make_rng(seed + b"B")
    kem_a = InMemoryKEM(rng_a)
    kem_b = InMemoryKEM(rng_b)

    alice = RatchetSession.create_initiator(semantic_hint=b"alpha", random_bytes=rng_a, kem=kem_a)
    bob = RatchetSession.create_responder(semantic_hint=b"beta", random_bytes=rng_b, kem=kem_b)

    req = alice.create_handshake_request()
    resp = bob.accept_handshake(req)
    alice.finalize_handshake(resp)

    compromised_blob = None

    for idx, message in enumerate(messages):
        packet = alice.encrypt(message)
        bob.decrypt(packet)
        if idx == 0:
            compromised_blob = alice.export_state()

    compromised_rng = make_rng(seed + b"C")
    compromised_kem = InMemoryKEM(compromised_rng)
    compromised = RatchetSession.from_serialized(
        compromised_blob,
        random_bytes=compromised_rng,
        kem=compromised_kem,
    )

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
