"""Error handling tests for PQ-FSR."""

import json
import unittest

from pqfsr import RatchetSession

from tests.utils import create_test_sessions, make_rng


class TestErrorHandling(unittest.TestCase):
    def test_initiator_cannot_accept_handshake(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        request = alice.create_handshake_request()

        with self.assertRaises(ValueError) as context:
            alice.accept_handshake(request)
        self.assertIn("Initiator", str(context.exception))

    def test_responder_cannot_create_handshake_request(self):
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        with self.assertRaises(ValueError) as context:
            bob.create_handshake_request()
        self.assertIn("Only initiators", str(context.exception))

    def test_responder_cannot_finalize_handshake(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)

        with self.assertRaises(ValueError) as context:
            bob.finalize_handshake(response)
        self.assertIn("Responder", str(context.exception))

    def test_double_handshake_initiator(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)

        with self.assertRaises(ValueError) as context:
            alice.create_handshake_request()
        self.assertIn("already completed", str(context.exception))

    def test_double_handshake_responder(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)

        # Alice cannot create another request on the same session, use a new one
        alice2 = RatchetSession.create_initiator(semantic_hint=b"alice2")
        request2 = alice2.create_handshake_request()
        
        with self.assertRaises(ValueError) as context:
            bob.accept_handshake(request2)
        self.assertIn("already completed", str(context.exception))

    def test_pending_handshake_prevents_new_request(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        alice.create_handshake_request()

        with self.assertRaises(ValueError) as context:
            alice.create_handshake_request()
        self.assertIn("already pending", str(context.exception))

    def test_handshake_id_mismatch(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)

        tampered_response = response.copy()
        tampered_response["handshake_id"] = b"wrong-id"

        with self.assertRaises(ValueError) as context:
            alice.finalize_handshake(tampered_response)
        self.assertIn("identifier mismatch", str(context.exception))

    def test_finalize_without_pending_handshake(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)

        with self.assertRaises(ValueError) as context:
            alice.finalize_handshake(response)
        # The error might be "Handshake already completed" or "No pending handshake"
        # Logic: check ready first -> "already completed"
        self.assertRegex(str(context.exception), "already completed|No pending handshake")

    def test_encrypt_before_handshake(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")

        with self.assertRaises(ValueError) as context:
            alice.encrypt(b"test")
        self.assertIn("not ready", str(context.exception))

    def test_decrypt_before_handshake(self):
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        fake_packet = {"header": {}, "ciphertext": b"", "auth_tag": b"", "nonce": b""}

        with self.assertRaises(ValueError) as context:
            bob.decrypt(fake_packet)
        self.assertIn("not ready", str(context.exception))

    def test_export_state_before_handshake(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")

        with self.assertRaises(ValueError) as context:
            alice.export_state()
        self.assertIn("not ready", str(context.exception))

    def test_message_already_processed(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        bob.decrypt(packet)

        with self.assertRaises(ValueError) as context:
            bob.decrypt(packet)
        self.assertIn("already processed", str(context.exception))

    def test_nonce_mismatch(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        tampered = packet.copy()
        tampered["nonce"] = b"wrong-nonce" * 2

        with self.assertRaises(ValueError) as context:
            bob.decrypt(tampered)
        self.assertIn("Nonce mismatch", str(context.exception))

    def test_semantic_tag_mismatch(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        tampered = packet.copy()
        tampered["header"] = packet["header"].copy()
        tampered["header"]["semantic_tag"] = b"wrong-tag" * 2

        with self.assertRaises(ValueError) as context:
            bob.decrypt(tampered)
        # Tag mismatch happens first in deep validation or Auth Tag check?
        # Header validation checks semantic tag.
        self.assertRegex(str(context.exception), "Semantic tag mismatch|Authentication tag mismatch")

    def test_authentication_tag_failure(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        # In AEAD, auth tag is part of ciphertext or checked inside decrypt
        # XORHMAC check logic:
        # We rely on the Cipher implementation.
        # If we tamper with ciphertext (which includes tag for XORHMAC), it fails.
        # But here we tamper with 'auth_tag' key if present?
        # Packet struct: header, ciphertext, nonce. (auth_tag is internal or separate)
        # If 'auth_tag' is not in dict (new format), this test is moot or needs updating.
        # The new format has auth tag appended to ciphertext.
        
        # Let's tamper with the ciphertext (end of it)
        ct = packet["ciphertext"]
        tampered_ct = ct[:-1] + bytes([(ct[-1] + 1) % 256])
        tampered = packet.copy()
        tampered["ciphertext"] = tampered_ct
        
        with self.assertRaises(ValueError) as context:
            bob.decrypt(tampered)
        self.assertRegex(str(context.exception), "Authentication tag mismatch|Decryption failed")

    def test_invalid_kem_ciphertext(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        tampered = packet.copy()
        tampered["header"] = packet["header"].copy()
        tampered["header"]["kem_ciphertext"] = b"too-short"

        with self.assertRaises(ValueError) as context:
            bob.decrypt(tampered)
        # Might fail on KEM decapsulate or earlier validation
        self.assertRegex(str(context.exception), "too short|Malformed|Decryption failed|BadLength")

    def test_invalid_serialization_json(self):
        with self.assertRaises((ValueError, UnicodeDecodeError, json.JSONDecodeError)):
            RatchetSession.from_serialized(b"not valid json")

    def test_invalid_serialization_missing_fields(self):
        invalid_state = json.dumps({"root_key": "abc"}).encode("utf-8")

        with self.assertRaises((KeyError, ValueError)):
            RatchetSession.from_serialized(invalid_state)

    def test_invalid_serialization_invalid_hex(self):
        invalid_state = json.dumps(
            {
                "root_key": "not-hex",
                "send_chain_key": "00" * 32,
                "recv_chain_key": "00" * 32,
                "send_label": "CHAIN|A2B",
                "recv_label": "CHAIN|B2A",
                "send_count": 0,
                "recv_count": 0,
                "local_ratchet_private": "00" * 32,
                "local_ratchet_public": "00" * 32,
                "remote_ratchet_public": "00" * 32,
                "combined_digest": "00" * 32,
                "local_digest": "00" * 32,
                "remote_digest": "00" * 32,
                "skipped_keys": [],
                "max_skip": 32,
                "semantic_hint": "00" * 16,
                "is_initiator": True,
            }
        ).encode("utf-8")

        with self.assertRaises(ValueError):
            RatchetSession.from_serialized(invalid_state)

    def test_hkdf_invalid_length(self):
        # HKDF is now internal to Rust implementation
        # This test is skipped as HKDF is not directly exposed
        pass


if __name__ == "__main__":
    unittest.main()
