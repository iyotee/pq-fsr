import hashlib

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


def test_deterministic_vectors():
    seed = b"pqfsr-vector-seed"
    rng_a = make_rng(seed + b"A")
    rng_b = make_rng(seed + b"B")
    kem_a = InMemoryKEM(rng_a)
    kem_b = InMemoryKEM(rng_b)

    alice = RatchetSession.create_initiator(semantic_hint=b"alice", random_bytes=rng_a, kem=kem_a)
    bob = RatchetSession.create_responder(semantic_hint=b"bob", random_bytes=rng_b, kem=kem_b)

    req = alice.create_handshake_request()
    resp = bob.accept_handshake(req)
    alice.finalize_handshake(resp)

    packet = alice.encrypt(b"deterministic message")
    assert packet["header"]["count"] == 0
    assert packet["header"]["semantic_tag"].hex() == "f1c8fac36b9fed7c16f0d78efbc8274a"
    assert packet["nonce"].hex() == "0a68a652d45d484435f100cc8e474787"

    plaintext = bob.decrypt(packet)
    assert plaintext == b"deterministic message"

    # Round-trip a response to ensure symmetry
    reply = bob.encrypt(b"ack")
    assert reply["header"]["count"] == 0
    recovered = alice.decrypt(reply)
    assert recovered == b"ack"
