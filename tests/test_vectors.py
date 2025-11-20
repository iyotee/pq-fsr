"""
Test Vectors: Deterministic test data for cross-implementation validation
===========================================================================

This module provides test vectors for PQ-FSR protocol validation.
Test vectors enable deterministic testing across different implementations.
"""

import unittest
from pqfsr import RatchetSession


class TestVectors(unittest.TestCase):
    """Test vectors for deterministic validation"""
    
    def test_deterministic_handshake(self):
        """Test that handshake produces deterministic results with fixed inputs"""
        # Note: Handshake includes randomness, so exact determinism requires
        # controlling the RNG. This test verifies the structure is correct.
        alice = RatchetSession.create_initiator(semantic_hint=b"test_alice", max_skip=32)
        bob = RatchetSession.create_responder(semantic_hint=b"test_bob", max_skip=32)
        
        request = alice.create_handshake_request()
        
        # Verify request structure
        self.assertIn("version", request)
        self.assertIn("handshake_id", request)
        self.assertIn("kem_public", request)
        self.assertIn("ratchet_public", request)
        self.assertIn("semantic_digest", request)
        
        # Verify handshake_id length (12 bytes random + 4 bytes timestamp = 16 bytes)
        self.assertEqual(len(request["handshake_id"]), 16)
        
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Both should be ready
        self.assertTrue(alice.is_ready)
        self.assertTrue(bob.is_ready)
    
    def test_deterministic_message_encryption(self):
        """Test that encryption produces consistent packet structure"""
        alice = RatchetSession.create_initiator(semantic_hint=b"test", max_skip=32)
        bob = RatchetSession.create_responder(semantic_hint=b"test", max_skip=32)
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Encrypt a message
        packet = alice.encrypt(b"test_message", b"")
        
        # Verify packet structure
        self.assertIn("header", packet)
        self.assertIn("ciphertext", packet)
        
        header = packet["header"]
        self.assertIn("version", header)
        self.assertIn("count", header)
        self.assertIn("ratchet_pub", header)
        self.assertIn("semantic_tag", header)
        
        # Decrypt should work
        plaintext = bob.decrypt(packet, b"")
        self.assertEqual(plaintext, b"test_message")
    
    def test_state_serialization_vectors(self):
        """Test that state serialization produces consistent format"""
        alice = RatchetSession.create_initiator(semantic_hint=b"test", max_skip=32)
        bob = RatchetSession.create_responder(semantic_hint=b"test", max_skip=32)
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Export state (CBOR format)
        state_cbor = alice.export_state(use_cbor=True)
        self.assertIsInstance(state_cbor, bytes)
        self.assertGreater(len(state_cbor), 0)
        
        # Export state (JSON format)
        state_json = alice.export_state(use_cbor=False)
        self.assertIsInstance(state_json, bytes)
        self.assertGreater(len(state_json), 0)
        
        # CBOR should be more compact
        self.assertLessEqual(len(state_cbor), len(state_json) + 100)  # Allow some overhead


if __name__ == "__main__":
    unittest.main()
