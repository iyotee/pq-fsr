from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

import hashlib
import hmac

__all__ = ["RatchetSession", "InMemoryKEM"]

_LABEL_A_TO_B = b"CHAIN|A2B"
_LABEL_B_TO_A = b"CHAIN|B2A"
_DIRECTION_SEND = b"SEND"
_NONCE_LEN = 16
_MAX_SKIP_DEFAULT = 32


def _hkdf(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Simplified HKDF using HMAC-SHA256."""
    if length <= 0:
        raise ValueError("length must be positive")

    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    blocks = []
    previous = b""
    counter = 1
    while len(b"".join(blocks)) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        blocks.append(previous)
        counter += 1
    return b"".join(blocks)[:length]


def _mix_root(previous_root: Optional[bytes], shared_secret: bytes, semantic_digest: bytes) -> bytes:
    base = (previous_root or b"\x00" * 32) + shared_secret + semantic_digest
    return hashlib.sha256(base).digest()


def _derive_chain_seed(root_key: bytes, semantic_digest: bytes, label: bytes) -> bytes:
    return _hkdf(root_key, semantic_digest, label, length=32)


def _derive_message_material(chain_key: bytes, counter: int) -> Tuple[bytes, bytes, bytes]:
    counter_bytes = counter.to_bytes(8, byteorder="big")
    base = chain_key + counter_bytes + _DIRECTION_SEND
    message_key = hashlib.sha256(base + b"MSG").digest()
    next_chain = hashlib.sha256(base + b"CHAIN").digest()
    nonce = hashlib.sha256(base + b"NONCE").digest()[:_NONCE_LEN]
    return message_key, next_chain, nonce


def _compute_semantic_tag(combined_digest: bytes, counter: int) -> bytes:
    payload = combined_digest + counter.to_bytes(8, byteorder="big") + _DIRECTION_SEND
    return hashlib.sha256(payload).digest()[:16]


def _expand_keystream(message_key: bytes, nonce: bytes, length: int) -> bytes:
    if length == 0:
        return b""
    blocks = bytearray()
    cursor = 0
    while len(blocks) < length:
        chunk = hashlib.sha256(message_key + nonce + cursor.to_bytes(4, "big")).digest()
        blocks.extend(chunk)
        cursor += 1
    return bytes(blocks[:length])


@dataclass
class RatchetState:
    root_key: bytes
    send_chain_key: bytes
    recv_chain_key: bytes
    send_label: bytes
    recv_label: bytes
    send_count: int
    recv_count: int
    local_ratchet_private: bytes
    local_ratchet_public: bytes
    remote_ratchet_public: Optional[bytes]
    combined_digest: bytes
    local_digest: bytes
    remote_digest: Optional[bytes]
    skipped_message_keys: Dict[int, Tuple[bytes, bytes]] = field(default_factory=dict)
    max_skip: int = _MAX_SKIP_DEFAULT


class InMemoryKEM:
    """Deterministic KEM stub suitable for reference testing."""

    def __init__(self, rng: Optional[Callable[[int], bytes]] = None) -> None:
        self._rng = rng or os.urandom

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        private = self._rng(32)
        public = hashlib.sha256(b"pqfsr-pk" + private).digest()
        return public, private

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        eph = self._rng(32)
        shared = hashlib.sha256(b"pqfsr-ss" + public_key + eph).digest()
        ciphertext = b"PQFSR" + eph + public_key
        return ciphertext, shared

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        if len(ciphertext) < 5 + 32:
            raise ValueError("ciphertext too short")
        eph = ciphertext[5:37]
        public = hashlib.sha256(b"pqfsr-pk" + private_key).digest()
        return hashlib.sha256(b"pqfsr-ss" + public + eph).digest()


class ForwardRatchet:
    def __init__(
        self,
        kem: Optional[InMemoryKEM] = None,
        *,
        max_skip: int = _MAX_SKIP_DEFAULT,
        random_bytes: Optional[Callable[[int], bytes]] = None,
    ) -> None:
        self._random_bytes = random_bytes or os.urandom
        self.kem = kem or InMemoryKEM(self._random_bytes)
        self.max_skip = max_skip

    def generate_kem_key_pair(self) -> Tuple[bytes, bytes]:
        return self.kem.generate_key_pair()

    def bootstrap(
        self,
        *,
        shared_secret: bytes,
        combined_digest: bytes,
        local_digest: bytes,
        remote_digest: Optional[bytes],
        is_initiator: bool,
        local_key_pair: Optional[Tuple[bytes, bytes]] = None,
    ) -> RatchetState:
        root = _mix_root(None, shared_secret, combined_digest)
        if is_initiator:
            send_label = _LABEL_A_TO_B
            recv_label = _LABEL_B_TO_A
        else:
            send_label = _LABEL_B_TO_A
            recv_label = _LABEL_A_TO_B

        send_chain = _derive_chain_seed(root, combined_digest, send_label)
        recv_chain = _derive_chain_seed(root, combined_digest, recv_label)

        if local_key_pair is None:
            local_public, local_private = self.generate_kem_key_pair()
        else:
            local_public, local_private = local_key_pair

        return RatchetState(
            root_key=root,
            send_chain_key=send_chain,
            recv_chain_key=recv_chain,
            send_label=send_label,
            recv_label=recv_label,
            send_count=0,
            recv_count=0,
            local_ratchet_private=local_private,
            local_ratchet_public=local_public,
            remote_ratchet_public=None,
            combined_digest=combined_digest,
            local_digest=local_digest,
            remote_digest=remote_digest,
            skipped_message_keys={},
            max_skip=self.max_skip,
        )

    def _store_skipped_key(self, state: RatchetState, idx: int, message_key: bytes, nonce: bytes) -> None:
        if len(state.skipped_message_keys) >= state.max_skip:
            oldest = sorted(state.skipped_message_keys.keys())[0]
            state.skipped_message_keys.pop(oldest, None)
        state.skipped_message_keys[idx] = (message_key, nonce)

    def _recover_skipped_key(self, state: RatchetState, idx: int) -> Optional[Tuple[bytes, bytes]]:
        return state.skipped_message_keys.pop(idx, None)

    def encrypt(self, state: RatchetState, plaintext: bytes, associated_data: bytes = b"") -> Dict[str, Any]:
        if state.remote_ratchet_public is None:
            raise ValueError("Remote ratchet public key missing")

        kem_ciphertext, shared_secret = self.kem.encapsulate(state.remote_ratchet_public)
        state.root_key = _mix_root(state.root_key, shared_secret, state.combined_digest)
        state.send_chain_key = _derive_chain_seed(state.root_key, state.combined_digest, state.send_label)
        state.recv_chain_key = _derive_chain_seed(state.root_key, state.combined_digest, state.recv_label)

        new_public, new_private = self.generate_kem_key_pair()
        previous_private = state.local_ratchet_private
        state.local_ratchet_private = new_private
        state.local_ratchet_public = new_public

        message_key, next_chain, nonce = _derive_message_material(state.send_chain_key, state.send_count)
        state.send_chain_key = next_chain

        keystream = _expand_keystream(message_key, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))

        auth_tag = hmac.new(message_key, ciphertext + associated_data + nonce, hashlib.sha256).digest()
        semantic_tag = _compute_semantic_tag(state.combined_digest, state.send_count)

        header = {
            "version": 1,
            "count": state.send_count,
            "ratchet_pub": state.local_ratchet_public,
            "kem_ciphertext": kem_ciphertext,
            "semantic_tag": semantic_tag,
        }

        state.send_count += 1
        if previous_private:
            bytearray(previous_private)  # best effort wipe

        return {
            "header": header,
            "ciphertext": ciphertext,
            "auth_tag": auth_tag,
            "nonce": nonce,
        }

    def decrypt(self, state: RatchetState, packet: Dict[str, Any], associated_data: bytes = b"") -> bytes:
        header = packet["header"]
        ciphertext = packet["ciphertext"]
        auth_tag = packet["auth_tag"]
        packet_nonce = packet["nonce"]

        message_index = header["count"]

        if message_index < state.recv_count:
            cached = self._recover_skipped_key(state, message_index)
            if cached is None:
                raise ValueError("Message already processed")
            message_key, nonce = cached
            if not hmac.compare_digest(nonce, packet_nonce):
                raise ValueError("Nonce mismatch")
        else:
            expected_semantic = _compute_semantic_tag(state.combined_digest, message_index)
            if not hmac.compare_digest(expected_semantic, header["semantic_tag"]):  # constant-time check
                raise ValueError("Semantic tag mismatch")

            shared_secret = self.kem.decapsulate(header["kem_ciphertext"], state.local_ratchet_private)
            state.root_key = _mix_root(state.root_key, shared_secret, state.combined_digest)
            state.remote_ratchet_public = header["ratchet_pub"]
            state.send_chain_key = _derive_chain_seed(state.root_key, state.combined_digest, state.send_label)
            state.recv_chain_key = _derive_chain_seed(state.root_key, state.combined_digest, state.recv_label)

            while state.recv_count < message_index:
                msg_key, next_chain, skipped_nonce = _derive_message_material(state.recv_chain_key, state.recv_count)
                state.recv_chain_key = next_chain
                self._store_skipped_key(state, state.recv_count, msg_key, skipped_nonce)
                state.recv_count += 1

            message_key, next_chain, derived_nonce = _derive_message_material(state.recv_chain_key, state.recv_count)
            state.recv_chain_key = next_chain
            state.recv_count += 1
            if not hmac.compare_digest(derived_nonce, packet_nonce):  # constant-time check
                raise ValueError("Nonce mismatch")
            nonce = derived_nonce

        keystream = _expand_keystream(message_key, nonce, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))

        expected_tag = hmac.new(message_key, ciphertext + associated_data + nonce, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_tag, auth_tag):  # constant-time comparison
            raise ValueError("Authentication tag mismatch")

        return plaintext


class RatchetSession:
    """High-level helper mirroring the CSF API but dependency-light."""

    def __init__(
        self,
        *,
        is_initiator: bool,
        semantic_hint: bytes,
        max_skip: int = _MAX_SKIP_DEFAULT,
        random_bytes: Optional[Callable[[int], bytes]] = None,
        kem: Optional[InMemoryKEM] = None,
    ) -> None:
        self.is_initiator = is_initiator
        self._semantic_hint = semantic_hint
        self._random_bytes = random_bytes or os.urandom
        self._ratchet = ForwardRatchet(kem=kem, max_skip=max_skip, random_bytes=self._random_bytes)
        self._state: Optional[RatchetState] = None
        self._ready = False
        self._pending_handshake: Optional[Dict[str, bytes]] = None
        self._remote_digest: Optional[bytes] = None
        self._handshake_id: Optional[bytes] = None

        self._local_digest = hashlib.sha256(b"PQ-FSR-sem" + semantic_hint).digest()

    @classmethod
    def create_initiator(
        cls,
        *,
        semantic_hint: bytes,
        max_skip: int = _MAX_SKIP_DEFAULT,
        random_bytes: Optional[Callable[[int], bytes]] = None,
        kem: Optional[InMemoryKEM] = None,
    ) -> "RatchetSession":
        return cls(
            is_initiator=True,
            semantic_hint=semantic_hint,
            max_skip=max_skip,
            random_bytes=random_bytes,
            kem=kem,
        )

    @classmethod
    def create_responder(
        cls,
        *,
        semantic_hint: bytes,
        max_skip: int = _MAX_SKIP_DEFAULT,
        random_bytes: Optional[Callable[[int], bytes]] = None,
        kem: Optional[InMemoryKEM] = None,
    ) -> "RatchetSession":
        return cls(
            is_initiator=False,
            semantic_hint=semantic_hint,
            max_skip=max_skip,
            random_bytes=random_bytes,
            kem=kem,
        )

    def _combine_digest(self, remote_digest: bytes) -> bytes:
        ordered = sorted([self._local_digest, remote_digest])
        return hashlib.sha256(ordered[0] + ordered[1]).digest()

    # -------------------------- Handshake -------------------------- #
    def create_handshake_request(self) -> Dict[str, bytes]:
        if not self.is_initiator:
            raise ValueError("Only initiators can create handshake requests")
        if self._ready:
            raise ValueError("Handshake already completed")
        if self._pending_handshake is not None:
            raise ValueError("Handshake already pending")

        kem_public, kem_private = self._ratchet.generate_kem_key_pair()
        ratchet_public, ratchet_private = self._ratchet.generate_kem_key_pair()
        handshake_id = self._random_bytes(16)

        self._pending_handshake = {
            "kem_private": kem_private,
            "ratchet_private": ratchet_private,
            "ratchet_public": ratchet_public,
            "handshake_id": handshake_id,
        }

        return {
            "version": b"\x00\x00\x00\x01",
            "handshake_id": handshake_id,
            "kem_public": kem_public,
            "ratchet_public": ratchet_public,
            "semantic_digest": self._local_digest,
        }

    def accept_handshake(self, request: Dict[str, bytes]) -> Dict[str, bytes]:
        if self.is_initiator:
            raise ValueError("Initiator cannot accept handshake")
        if self._ready:
            raise ValueError("Handshake already completed")

        remote_digest = request["semantic_digest"]
        combined_digest = self._combine_digest(remote_digest)
        kem_ciphertext, shared_secret = self._ratchet.kem.encapsulate(request["kem_public"])
        local_ratchet_public, local_ratchet_private = self._ratchet.generate_kem_key_pair()

        state = self._ratchet.bootstrap(
            shared_secret=shared_secret,
            combined_digest=combined_digest,
            local_digest=self._local_digest,
            remote_digest=remote_digest,
            is_initiator=False,
            local_key_pair=(local_ratchet_public, local_ratchet_private),
        )
        state.remote_ratchet_public = request["ratchet_public"]

        self._state = state
        self._remote_digest = remote_digest
        self._handshake_id = request["handshake_id"]
        self._ready = True

        return {
            "version": b"\x00\x00\x00\x01",
            "handshake_id": request["handshake_id"],
            "kem_ciphertext": kem_ciphertext,
            "ratchet_public": local_ratchet_public,
            "semantic_digest": self._local_digest,
        }

    def finalize_handshake(self, response: Dict[str, bytes]) -> None:
        if not self.is_initiator:
            raise ValueError("Responder cannot finalize handshake")
        if self._ready:
            raise ValueError("Handshake already completed")
        if self._pending_handshake is None:
            raise ValueError("No pending handshake")

        pending = self._pending_handshake
        if pending["handshake_id"] != response["handshake_id"]:
            raise ValueError("Handshake identifier mismatch")

        shared_secret = self._ratchet.kem.decapsulate(response["kem_ciphertext"], pending["kem_private"])
        remote_digest = response["semantic_digest"]
        combined_digest = self._combine_digest(remote_digest)

        state = self._ratchet.bootstrap(
            shared_secret=shared_secret,
            combined_digest=combined_digest,
            local_digest=self._local_digest,
            remote_digest=remote_digest,
            is_initiator=True,
            local_key_pair=(pending["ratchet_public"], pending["ratchet_private"]),
        )
        state.remote_ratchet_public = response["ratchet_public"]

        self._state = state
        self._remote_digest = remote_digest
        self._handshake_id = response["handshake_id"]
        self._ready = True
        self._pending_handshake = None

    # -------------------------- Messaging -------------------------- #
    @property
    def is_ready(self) -> bool:
        return self._ready and self._state is not None

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Dict[str, Any]:
        if not self.is_ready:
            raise ValueError("Session not ready")
        return self._ratchet.encrypt(self._state, plaintext, associated_data)

    def decrypt(self, packet: Dict[str, Any], associated_data: bytes = b"") -> bytes:
        if not self.is_ready:
            raise ValueError("Session not ready")
        return self._ratchet.decrypt(self._state, packet, associated_data)

    # -------------------------- Persistence -------------------------- #
    def export_state(self) -> bytes:
        if not self.is_ready:
            raise ValueError("Session not ready")
        state = self._state
        payload = {
            "root_key": state.root_key.hex(),
            "send_chain_key": state.send_chain_key.hex(),
            "recv_chain_key": state.recv_chain_key.hex(),
            "send_label": state.send_label.decode(),
            "recv_label": state.recv_label.decode(),
            "send_count": state.send_count,
            "recv_count": state.recv_count,
            "local_ratchet_private": state.local_ratchet_private.hex(),
            "local_ratchet_public": state.local_ratchet_public.hex(),
            "remote_ratchet_public": state.remote_ratchet_public.hex() if state.remote_ratchet_public else None,
            "combined_digest": state.combined_digest.hex(),
            "local_digest": state.local_digest.hex(),
            "remote_digest": state.remote_digest.hex() if state.remote_digest else None,
            "skipped_keys": [
                (idx, key.hex(), nonce.hex()) for idx, (key, nonce) in sorted(state.skipped_message_keys.items())
            ],
            "max_skip": state.max_skip,
            "semantic_hint": self._semantic_hint.hex(),
            "is_initiator": self.is_initiator,
        }
        return json.dumps(payload).encode("utf-8")

    @classmethod
    def from_serialized(
        cls,
        blob: bytes,
        *,
        random_bytes: Optional[Callable[[int], bytes]] = None,
        kem: Optional[InMemoryKEM] = None,
    ) -> "RatchetSession":
        payload = json.loads(blob.decode("utf-8"))
        session = cls(
            is_initiator=payload["is_initiator"],
            semantic_hint=bytes.fromhex(payload["semantic_hint"]),
            max_skip=payload["max_skip"],
            random_bytes=random_bytes,
            kem=kem,
        )
        state = RatchetState(
            root_key=bytes.fromhex(payload["root_key"]),
            send_chain_key=bytes.fromhex(payload["send_chain_key"]),
            recv_chain_key=bytes.fromhex(payload["recv_chain_key"]),
            send_label=payload["send_label"].encode(),
            recv_label=payload["recv_label"].encode(),
            send_count=payload["send_count"],
            recv_count=payload["recv_count"],
            local_ratchet_private=bytes.fromhex(payload["local_ratchet_private"]),
            local_ratchet_public=bytes.fromhex(payload["local_ratchet_public"]),
            remote_ratchet_public=bytes.fromhex(payload["remote_ratchet_public"]) if payload["remote_ratchet_public"] else None,
            combined_digest=bytes.fromhex(payload["combined_digest"]),
            local_digest=bytes.fromhex(payload["local_digest"]),
            remote_digest=bytes.fromhex(payload["remote_digest"]) if payload["remote_digest"] else None,
            skipped_message_keys={int(idx): (bytes.fromhex(key), bytes.fromhex(nonce)) for idx, key, nonce in payload["skipped_keys"]},
            max_skip=payload["max_skip"],
        )
        session._state = state
        session._local_digest = state.local_digest
        session._remote_digest = state.remote_digest
        session._handshake_id = None
        session._ready = True
        return session
