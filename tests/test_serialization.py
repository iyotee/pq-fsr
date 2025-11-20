"""Serialization tests for PQ-FSR."""

import json
import unittest

from pqfsr import RatchetSession

from tests.utils import create_test_sessions


class TestSerialization(unittest.TestCase):
    def test_round_trip_serialization_basic(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        bob.decrypt(packet)

        exported = bob.export_state()
        restored = RatchetSession.from_serialized(exported)

        follow_up = alice.encrypt(b"follow-up")
        plaintext = restored.decrypt(follow_up)
        self.assertEqual(plaintext, b"follow-up")

    def test_round_trip_serialization_with_skipped_keys(self):
        alice, bob = create_test_sessions(max_skip=10)

        packets = []
        for i in range(5):
            packets.append(alice.encrypt(f"msg-{i}".encode()))

        for i in range(2, 5):
            bob.decrypt(packets[i])

        exported = bob.export_state()
        restored = RatchetSession.from_serialized(exported)

        self.assertEqual(len(restored._state.skipped_message_keys), 2)

        plaintext0 = restored.decrypt(packets[0])
        plaintext1 = restored.decrypt(packets[1])

        self.assertEqual(plaintext0, b"msg-0")
        self.assertEqual(plaintext1, b"msg-1")

    def test_serialization_preserves_all_state(self):
        alice, bob = create_test_sessions()

        for i in range(3):
            packet = alice.encrypt(f"msg-{i}".encode())
            bob.decrypt(packet)

        exported = bob.export_state()
        restored = RatchetSession.from_serialized(exported)

        self.assertEqual(restored._state.root_key, bob._state.root_key)
        self.assertEqual(restored._state.send_chain_key, bob._state.send_chain_key)
        self.assertEqual(restored._state.recv_chain_key, bob._state.recv_chain_key)
        self.assertEqual(restored._state.send_count, bob._state.send_count)
        self.assertEqual(restored._state.recv_count, bob._state.recv_count)
        self.assertEqual(restored._state.local_ratchet_public, bob._state.local_ratchet_public)
        self.assertEqual(restored._state.remote_ratchet_public, bob._state.remote_ratchet_public)
        self.assertEqual(restored._state.combined_digest, bob._state.combined_digest)
        self.assertEqual(restored._state.local_digest, bob._state.local_digest)
        self.assertEqual(restored._state.remote_digest, bob._state.remote_digest)
        self.assertEqual(restored._state.max_skip, bob._state.max_skip)
        self.assertEqual(restored._semantic_hint, bob._semantic_hint)
        self.assertEqual(restored.is_initiator, bob.is_initiator)

    def test_serialization_various_skip_cache_sizes(self):
        for max_skip in [1, 5, 10, 32, 100]:
            with self.subTest(max_skip=max_skip):
                alice, bob = create_test_sessions(max_skip=max_skip)

                packets = []
                for i in range(max_skip + 5):
                    packets.append(alice.encrypt(f"msg-{i}".encode()))

                for i in range(max_skip, max_skip + 5):
                    bob.decrypt(packets[i])

                exported = bob.export_state()
                restored = RatchetSession.from_serialized(exported)

                self.assertLessEqual(len(restored._state.skipped_message_keys), max_skip)

    def test_serialization_invalid_json(self):
        with self.assertRaises((ValueError, json.JSONDecodeError, UnicodeDecodeError)):
            RatchetSession.from_serialized(b"not json")

    def test_serialization_missing_root_key(self):
        invalid_state = json.dumps(
            {
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

    def test_serialization_missing_skipped_keys(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        bob.decrypt(packet)

        # Use JSON for this test (needs to parse JSON)
        exported = bob.export_state(use_cbor=False)
        data = json.loads(exported.decode("utf-8"))
        
        # Handle versioned schema wrapper
        if "data" in data:
            del data["data"]["skipped_keys"]
        else:
            del data["skipped_keys"]

        invalid_state = json.dumps(data).encode("utf-8")

        with self.assertRaises(ValueError):
            RatchetSession.from_serialized(invalid_state)

    def test_serialization_invalid_hex_string(self):
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

    def test_serialization_invalid_integer_type(self):
        invalid_state = json.dumps(
            {
                "root_key": "00" * 32,
                "send_chain_key": "00" * 32,
                "recv_chain_key": "00" * 32,
                "send_label": "CHAIN|A2B",
                "recv_label": "CHAIN|B2A",
                "send_count": "not-an-int",
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

        with self.assertRaises((ValueError, TypeError)):
            RatchetSession.from_serialized(invalid_state)

    def test_serialization_during_handshake_fails(self):
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        alice.create_handshake_request()

        with self.assertRaises(ValueError) as context:
            alice.export_state()
        self.assertIn("not ready", str(context.exception))

    def test_serialization_with_none_remote_digest(self):
        alice, bob = create_test_sessions()

        # Use JSON for this test (needs to parse JSON)
        exported = alice.export_state(use_cbor=False)
        data = json.loads(exported.decode("utf-8"))

        # Check inside data wrapper
        self.assertIsNotNone(data["data"]["remote_digest"])

    def test_serialization_roundtrip_preserves_functionality(self):
        alice, bob = create_test_sessions()

        packet1 = alice.encrypt(b"message-1")
        bob.decrypt(packet1)

        exported_bob = bob.export_state()
        restored_bob = RatchetSession.from_serialized(exported_bob)

        packet2 = alice.encrypt(b"message-2")
        plaintext1 = bob.decrypt(packet2)
        plaintext2 = restored_bob.decrypt(packet2)

        self.assertEqual(plaintext1, b"message-2")
        self.assertEqual(plaintext2, b"message-2")

    def test_serialization_empty_skipped_keys_format(self):
        alice, bob = create_test_sessions()

        packet = alice.encrypt(b"test")
        bob.decrypt(packet)

        # Use JSON for this test (needs to parse JSON)
        exported = bob.export_state(use_cbor=False)
        data = json.loads(exported.decode("utf-8"))

        self.assertEqual(data["data"]["skipped_keys"], [])

    def test_serialization_skipped_keys_format(self):
        alice, bob = create_test_sessions(max_skip=10)

        packets = []
        for i in range(5):
            packets.append(alice.encrypt(f"msg-{i}".encode()))

        for i in range(2, 5):
            bob.decrypt(packets[i])

        # Use JSON for this test (needs to parse JSON)
        exported = bob.export_state(use_cbor=False)
        data = json.loads(exported.decode("utf-8"))

        self.assertIsInstance(data["data"]["skipped_keys"], list)
        self.assertEqual(len(data["data"]["skipped_keys"]), 2)
        for item in data["data"]["skipped_keys"]:
            self.assertIsInstance(item, list)
            self.assertEqual(len(item), 3)
            self.assertIsInstance(item[0], (int, str))
            self.assertIsInstance(item[1], str)
            self.assertIsInstance(item[2], str)


if __name__ == "__main__":
    unittest.main()
