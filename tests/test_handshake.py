"""Handshake-specific tests for PQ-FSR."""

import unittest

from pqfsr import RatchetSession

from tests.utils import create_test_sessions, make_rng


class TestHandshake(unittest.TestCase):
    def test_handshake_state_machine_initiator(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        self.assertFalse(alice.is_ready)

        request = alice.create_handshake_request()
        self.assertFalse(alice.is_ready)
        self.assertIn("handshake_id", request)
        self.assertIn("kem_public", request)
        self.assertIn("ratchet_public", request)
        self.assertIn("semantic_digest", request)

        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        response = bob.accept_handshake(request)

        alice.finalize_handshake(response)
        self.assertTrue(alice.is_ready)

    def test_handshake_state_machine_responder(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        self.assertFalse(bob.is_ready)

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)

        self.assertTrue(bob.is_ready)
        self.assertIn("handshake_id", response)
        self.assertIn("kem_ciphertext", response)
        self.assertIn("ratchet_public", response)
        self.assertIn("semantic_digest", response)

    def test_handshake_id_verification(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        original_id = request["handshake_id"]

        response = bob.accept_handshake(request)
        self.assertEqual(response["handshake_id"], original_id)

        alice.finalize_handshake(response)

    def test_handshake_id_preserved_through_roundtrip(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        request_id = request["handshake_id"]

        response = bob.accept_handshake(request)
        self.assertEqual(response["handshake_id"], request_id)

        alice.finalize_handshake(response)

    def test_handshake_with_different_semantic_hints(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice-identity")
        bob = RatchetSession.create_responder(semantic_hint=b"bob-identity")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)

        packet = alice.encrypt(b"test")
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, b"test")

    def test_handshake_with_custom_kem(self):
        """Test that custom KEM is no longer supported (KEM is now internal)."""
        # Custom KEM is no longer supported - the Rust implementation uses Kyber768 internally
        # This test is kept for documentation but will use default KEM
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)

        packet = alice.encrypt(b"test")
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, b"test")

    def test_handshake_creates_different_keys(self):
        alice1 = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob1 = RatchetSession.create_responder(semantic_hint=b"bob")

        request1 = alice1.create_handshake_request()
        response1 = bob1.accept_handshake(request1)
        alice1.finalize_handshake(response1)

        alice2 = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob2 = RatchetSession.create_responder(semantic_hint=b"bob")

        request2 = alice2.create_handshake_request()
        response2 = bob2.accept_handshake(request2)
        alice2.finalize_handshake(response2)

        self.assertNotEqual(request1["handshake_id"], request2["handshake_id"])
        self.assertNotEqual(request1["kem_public"], request2["kem_public"])

    def test_handshake_version_field(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        self.assertEqual(request["version"], b"\x00\x00\x00\x01")

        response = bob.accept_handshake(request)
        self.assertEqual(response["version"], b"\x00\x00\x00\x01")

    def test_handshake_semantic_digest_ordering(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        alice_digest = request["semantic_digest"]

        response = bob.accept_handshake(request)
        bob_digest = response["semantic_digest"]

        self.assertNotEqual(alice_digest, bob_digest)

        alice.finalize_handshake(response)

        combined = alice.get_combined_digest(bob_digest)
        self.assertEqual(combined, alice._state.combined_digest)
        self.assertEqual(combined, bob._state.combined_digest)

    def test_handshake_with_same_semantic_hint(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"same")
        bob = RatchetSession.create_responder(semantic_hint=b"same")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)

        packet = alice.encrypt(b"test")
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, b"test")

    def test_handshake_creates_valid_ratchet_state(self):
        alice, bob = create_test_sessions()

        self.assertIsNotNone(alice._state)
        self.assertIsNotNone(bob._state)
        self.assertIsNotNone(alice._state.root_key)
        self.assertIsNotNone(bob._state.root_key)
        self.assertEqual(alice._state.root_key, bob._state.root_key)
        self.assertIsNotNone(alice._state.remote_ratchet_public)
        self.assertIsNotNone(bob._state.remote_ratchet_public)

    def test_handshake_ratchet_keys_different(self):
        alice, bob = create_test_sessions()

        self.assertNotEqual(
            alice._state.local_ratchet_public, bob._state.local_ratchet_public
        )
        self.assertEqual(
            alice._state.local_ratchet_public, bob._state.remote_ratchet_public
        )
        self.assertEqual(
            bob._state.local_ratchet_public, alice._state.remote_ratchet_public
        )

    def test_handshake_chain_keys_initialized(self):
        alice, bob = create_test_sessions()

        self.assertIsNotNone(alice._state.send_chain_key)
        self.assertIsNotNone(alice._state.recv_chain_key)
        self.assertIsNotNone(bob._state.send_chain_key)
        self.assertIsNotNone(bob._state.recv_chain_key)

        self.assertEqual(alice._state.send_chain_key, bob._state.recv_chain_key)
        self.assertEqual(bob._state.send_chain_key, alice._state.recv_chain_key)

    def test_handshake_counters_initialized(self):
        alice, bob = create_test_sessions()

        self.assertEqual(alice._state.send_count, 0)
        self.assertEqual(alice._state.recv_count, 0)
        self.assertEqual(bob._state.send_count, 0)
        self.assertEqual(bob._state.recv_count, 0)

    def test_handshake_skipped_keys_empty(self):
        alice, bob = create_test_sessions()

        self.assertEqual(len(alice._state.skipped_message_keys), 0)
        self.assertEqual(len(bob._state.skipped_message_keys), 0)


if __name__ == "__main__":
    unittest.main()

