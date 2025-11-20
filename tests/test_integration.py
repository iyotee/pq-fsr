"""Integration tests for PQ-FSR."""

import unittest

from pqfsr import RatchetSession

from tests.utils import create_test_sessions


class TestIntegration(unittest.TestCase):
    def test_multiple_concurrent_sessions(self):
        alice1, bob1 = create_test_sessions(seed=b"session-1")
        alice2, bob2 = create_test_sessions(seed=b"session-2")

        packet1 = alice1.encrypt(b"session-1-msg")
        packet2 = alice2.encrypt(b"session-2-msg")

        plaintext1 = bob1.decrypt(packet1)
        plaintext2 = bob2.decrypt(packet2)

        self.assertEqual(plaintext1, b"session-1-msg")
        self.assertEqual(plaintext2, b"session-2-msg")

        with self.assertRaises(ValueError):
            bob1.decrypt(packet2)

        with self.assertRaises(ValueError):
            bob2.decrypt(packet1)

    def test_long_running_session_many_messages(self):
        alice, bob = create_test_sessions()

        for i in range(100):
            packet = alice.encrypt(f"message-{i}".encode())
            plaintext = bob.decrypt(packet)
            self.assertEqual(plaintext, f"message-{i}".encode())

    def test_bidirectional_communication_pattern(self):
        alice, bob = create_test_sessions()

        for i in range(20):
            alice_packet = alice.encrypt(f"alice-{i}".encode())
            bob_packet = bob.encrypt(f"bob-{i}".encode())

            alice_plaintext = bob.decrypt(alice_packet)
            bob_plaintext = alice.decrypt(bob_packet)

            self.assertEqual(alice_plaintext, f"alice-{i}".encode())
            self.assertEqual(bob_plaintext, f"bob-{i}".encode())

    def test_session_recovery_after_state_export(self):
        alice, bob = create_test_sessions()

        packet1 = alice.encrypt(b"before-export")
        bob.decrypt(packet1)

        exported_bob = bob.export_state()
        restored_bob = RatchetSession.from_serialized(exported_bob)

        packet2 = alice.encrypt(b"after-export")
        plaintext = restored_bob.decrypt(packet2)
        self.assertEqual(plaintext, b"after-export")

    def test_multiple_ratchet_rotations(self):
        alice, bob = create_test_sessions()

        for i in range(50):
            packet = alice.encrypt(f"msg-{i}".encode())
            plaintext = bob.decrypt(packet)
            self.assertEqual(plaintext, f"msg-{i}".encode())

        exported_alice = alice.export_state()
        exported_bob = bob.export_state()

        restored_alice = RatchetSession.from_serialized(exported_alice)
        restored_bob = RatchetSession.from_serialized(exported_bob)

        packet = restored_alice.encrypt(b"after-restore")
        plaintext = restored_bob.decrypt(packet)
        self.assertEqual(plaintext, b"after-restore")

    def test_chain_key_exhaustion_scenario(self):
        alice, bob = create_test_sessions()

        for i in range(1000):
            packet = alice.encrypt(f"msg-{i}".encode())
            plaintext = bob.decrypt(packet)
            self.assertEqual(plaintext, f"msg-{i}".encode())

    def test_complex_message_sequence(self):
        alice, bob = create_test_sessions()

        messages = [
            b"short",
            b"medium-length-message",
            b"x" * 1000,
            b"",
            b"y" * 100,
            b"normal message",
        ]

        for msg in messages:
            packet = alice.encrypt(msg)
            plaintext = bob.decrypt(packet)
            self.assertEqual(plaintext, msg)

    def test_alternating_senders(self):
        alice, bob = create_test_sessions()

        for i in range(10):
            alice_msg = f"alice-{i}".encode()
            bob_msg = f"bob-{i}".encode()

            alice_packet = alice.encrypt(alice_msg)
            bob_packet = bob.encrypt(bob_msg)

            bob_received = bob.decrypt(alice_packet)
            alice_received = alice.decrypt(bob_packet)

            self.assertEqual(bob_received, alice_msg)
            self.assertEqual(alice_received, bob_msg)

    def test_session_restoration_multiple_times(self):
        alice, bob = create_test_sessions()

        for restore_count in range(5):
            packet = alice.encrypt(f"before-restore-{restore_count}".encode())
            bob.decrypt(packet)

            exported = bob.export_state()
            restored = RatchetSession.from_serialized(exported)

            follow_up = alice.encrypt(f"after-restore-{restore_count}".encode())
            plaintext = restored.decrypt(follow_up)
            self.assertEqual(plaintext, f"after-restore-{restore_count}".encode())

            bob = restored

    def test_concurrent_sessions_different_semantic_hints(self):
        sessions = []
        for i in range(5):
            alice = RatchetSession.create_initiator(semantic_hint=f"alice-{i}".encode())
            bob = RatchetSession.create_responder(semantic_hint=f"bob-{i}".encode())

            request = alice.create_handshake_request()
            response = bob.accept_handshake(request)
            alice.finalize_handshake(response)

            sessions.append((alice, bob))

        for i, (alice, bob) in enumerate(sessions):
            packet = alice.encrypt(f"msg-{i}".encode())
            plaintext = bob.decrypt(packet)
            self.assertEqual(plaintext, f"msg-{i}".encode())

    def test_large_scale_message_exchange(self):
        alice, bob = create_test_sessions()

        total_messages = 500
        for i in range(total_messages):
            if i % 2 == 0:
                packet = alice.encrypt(f"alice-{i}".encode())
                plaintext = bob.decrypt(packet)
                self.assertEqual(plaintext, f"alice-{i}".encode())
            else:
                packet = bob.encrypt(f"bob-{i}".encode())
                plaintext = alice.decrypt(packet)
                self.assertEqual(plaintext, f"bob-{i}".encode())

    def test_state_export_import_chain(self):
        alice, bob = create_test_sessions()

        for i in range(10):
            packet = alice.encrypt(f"msg-{i}".encode())
            bob.decrypt(packet)

            if i % 3 == 0:
                exported = bob.export_state()
                bob = RatchetSession.from_serialized(exported)

        packet = alice.encrypt(b"final")
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, b"final")


if __name__ == "__main__":
    unittest.main()

