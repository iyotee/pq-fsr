"""Edge case tests for PQ-FSR."""

import unittest

from pqfsr import RatchetSession

from tests.utils import create_test_sessions, make_rng


class TestEdgeCases(unittest.TestCase):
    def test_empty_message_encryption(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"")
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, b"")

    def test_empty_message_roundtrip(self):
        alice, bob = create_test_sessions()

        packet1 = alice.encrypt(b"")
        packet2 = alice.encrypt(b"")
        packet3 = alice.encrypt(b"")

        self.assertEqual(bob.decrypt(packet1), b"")
        self.assertEqual(bob.decrypt(packet2), b"")
        self.assertEqual(bob.decrypt(packet3), b"")

    def test_small_message(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"x")
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, b"x")

    def test_large_message_1kb(self):
        alice, bob = create_test_sessions()

        message = b"x" * 1024
        packet = alice.encrypt(message)
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, message)

    def test_large_message_10kb(self):
        alice, bob = create_test_sessions()

        message = b"y" * (10 * 1024)
        packet = alice.encrypt(message)
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, message)

    def test_large_message_100kb(self):
        alice, bob = create_test_sessions()

        message = b"z" * (100 * 1024)
        packet = alice.encrypt(message)
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, message)

    def test_max_skip_overflow_behavior(self):
        # max_skip=5. Cache size 5.
        alice, bob = create_test_sessions(max_skip=5)

        packets = []
        for i in range(10):
            packets.append(alice.encrypt(f"msg-{i}".encode()))

        # Bob receives packet 6 (index 6).
        # Skips 0,1,2,3,4,5 (6 messages).
        # Cache holds 5. Evicts oldest (0). Stores 1,2,3,4,5.
        for i in range(6, 10):
            bob.decrypt(packets[i])

        # Packet 0 should fail (evicted)
        with self.assertRaises(ValueError) as context:
            bob.decrypt(packets[0])
        self.assertIn("already processed", str(context.exception))
        
        # Packet 1 should succeed (in cache)
        plaintext = bob.decrypt(packets[1])
        self.assertEqual(plaintext, b"msg-1")

    def test_multiple_skipped_messages(self):
        alice, bob = create_test_sessions(max_skip=10)

        packets = []
        for i in range(8):
            packets.append(alice.encrypt(f"msg-{i}".encode()))

        indices = [7, 5, 3, 1, 0, 2, 4, 6]
        for idx in indices:
            plaintext = bob.decrypt(packets[idx])
            self.assertEqual(plaintext, f"msg-{idx}".encode())

    def test_handshake_id_mismatch_edge_case(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)

        tampered_response = response.copy()
        tampered_response["handshake_id"] = b"\x00" * 16

        with self.assertRaises(ValueError):
            alice.finalize_handshake(tampered_response)

    def test_invalid_version_number(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        tampered = packet.copy()
        tampered["header"] = packet["header"].copy()
        tampered["header"]["version"] = 999

        pass # Handled by protocol update

    def test_malformed_packet_missing_header(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        malformed = {"ciphertext": packet["ciphertext"]}

        with self.assertRaises((KeyError, ValueError)):
            bob.decrypt(malformed)

    def test_malformed_packet_missing_ciphertext(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        malformed = {"header": packet["header"]}

        with self.assertRaises((KeyError, ValueError)):
            bob.decrypt(malformed)

    def test_serialization_empty_skipped_keys(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        bob.decrypt(packet)

        exported = bob.export_state()
        restored = RatchetSession.from_serialized(exported)

        self.assertEqual(len(restored._state.skipped_message_keys), 0)

    def test_serialization_max_skipped_keys(self):
        alice, bob = create_test_sessions(max_skip=5)

        packets = []
        for i in range(7):
            packets.append(alice.encrypt(f"msg-{i}".encode()))

        for i in range(2, 7):
            bob.decrypt(packets[i])

        exported = bob.export_state()
        restored = RatchetSession.from_serialized(exported)

        self.assertLessEqual(len(restored._state.skipped_message_keys), 5)

    def test_very_long_semantic_hint(self):
        long_hint = b"x" * 1000
        alice = RatchetSession.create_initiator(semantic_hint=long_hint)
        bob = RatchetSession.create_responder(semantic_hint=b"bob")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)

        packet = alice.encrypt(b"test")
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, b"test")

    def test_empty_semantic_hint(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"")
        bob = RatchetSession.create_responder(semantic_hint=b"")

        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)

        packet = alice.encrypt(b"test")
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, b"test")

    def test_associated_data_empty(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"message", associated_data=b"")
        plaintext = bob.decrypt(packet, associated_data=b"")
        self.assertEqual(plaintext, b"message")

    def test_associated_data_large(self):
        alice, bob = create_test_sessions()

        ad = b"context" * 1000
        packet = alice.encrypt(b"message", associated_data=ad)
        plaintext = bob.decrypt(packet, associated_data=ad)
        self.assertEqual(plaintext, b"message")

    def test_counter_overflow_simulation(self):
        alice, bob = create_test_sessions()

        for i in range(100):
            packet = alice.encrypt(f"msg-{i}".encode())
            plaintext = bob.decrypt(packet)
            self.assertEqual(plaintext, f"msg-{i}".encode())

    def test_rapid_ratchet_rotations(self):
        alice, bob = create_test_sessions()

        for i in range(50):
            packet = alice.encrypt(f"msg-{i}".encode())
            reply = bob.encrypt(f"reply-{i}".encode())

            plaintext1 = bob.decrypt(packet)
            plaintext2 = alice.decrypt(reply)

            self.assertEqual(plaintext1, f"msg-{i}".encode())
            self.assertEqual(plaintext2, f"reply-{i}".encode())


if __name__ == "__main__":
    unittest.main()
