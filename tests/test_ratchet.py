import unittest

from pqfsr import RatchetSession


class TestPQFSR(unittest.TestCase):
    def setUp(self) -> None:
        self.alice = RatchetSession.create_initiator(semantic_hint=b"alice", max_skip=8)
        self.bob = RatchetSession.create_responder(semantic_hint=b"bob", max_skip=8)

        request = self.alice.create_handshake_request()
        response = self.bob.accept_handshake(request)
        self.alice.finalize_handshake(response)

    def test_basic_roundtrip(self) -> None:
        packet = self.alice.encrypt(b"hello pq")
        plaintext = self.bob.decrypt(packet)
        self.assertEqual(b"hello pq", plaintext)

        reply = self.bob.encrypt(b"roger")
        echo = self.alice.decrypt(reply)
        self.assertEqual(b"roger", echo)

    def test_state_serialization(self) -> None:
        packet = self.alice.encrypt(b"stateful")
        self.bob.decrypt(packet)

        exported = self.bob.export_state()
        restored = RatchetSession.from_serialized(exported)

        follow_up = self.alice.encrypt(b"post-restore")
        plaintext = restored.decrypt(follow_up)
        self.assertEqual(b"post-restore", plaintext)

    def test_post_compromise(self) -> None:
        first = self.alice.encrypt(b"secret-1")
        self.bob.decrypt(first)

        compromised = RatchetSession.from_serialized(self.alice.export_state())

        second = self.alice.encrypt(b"secret-2")
        self.bob.decrypt(second)

        with self.assertRaises(ValueError):
            compromised.decrypt(second)


if __name__ == "__main__":
    unittest.main()
