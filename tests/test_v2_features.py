import unittest
import struct
from pqfsr import RatchetSession
# Note: encrypt_state, decrypt_state, pack_packet, unpack_packet are now in Rust
# They can be accessed via RatchetSession methods or will be re-exported if needed

class TestV2Features(unittest.TestCase):
    def test_wire_format_packing(self):
        """Test pack/unpack packet functionality."""
        # Create a session and encrypt a message to get a real packet
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Encrypt to get a real packet
        packet = alice.encrypt(b"test message")
        
        # Pack
        packed = alice.pack_packet(packet)
        self.assertIsInstance(packed, bytes)
        
        # Unpack
        unpacked = bob.unpack_packet(packed)
        
        # Verify structure
        self.assertEqual(unpacked["header"]["version"], packet["header"]["version"])
        self.assertEqual(unpacked["header"]["count"], packet["header"]["count"])
        self.assertEqual(unpacked["ciphertext"], packet["ciphertext"])

    def test_ratchet_session_helpers(self):
        """Test that pack/unpack methods exist."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        self.assertTrue(hasattr(alice, "pack_packet"))
        self.assertTrue(hasattr(alice, "unpack_packet"))

if __name__ == "__main__":
    unittest.main()

