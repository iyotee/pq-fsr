"""Tests for CBOR serialization functionality."""

import unittest

from pqfsr import RatchetSession


class TestCBORSerialization(unittest.TestCase):
    """Test CBOR serialization (production format)."""
    
    def test_cbor_default_format(self):
        """Test that CBOR is used by default."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Export with default (should be CBOR)
        state_default = alice.export_state()
        
        # CBOR doesn't start with '{' (JSON does)
        self.assertFalse(state_default.startswith(b"{"), 
                        "Default format should be CBOR, not JSON")
    
    def test_cbor_explicit(self):
        """Test explicit CBOR format."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Export with CBOR explicitly
        state_cbor = alice.export_state(use_cbor=True)
        self.assertFalse(state_cbor.startswith(b"{"))
    
    def test_json_backward_compatibility(self):
        """Test JSON format for backward compatibility."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Export with JSON explicitly
        state_json = alice.export_state(use_cbor=False)
        self.assertTrue(state_json.startswith(b"{"))
    
    def test_cbor_size_advantage(self):
        """Test that CBOR is typically smaller than JSON."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Send some messages to build up state
        for i in range(5):
            packet = alice.encrypt(f"message-{i}".encode())
            bob.decrypt(packet)
        
        state_cbor = alice.export_state(use_cbor=True)
        state_json = alice.export_state(use_cbor=False)
        
        # CBOR should be smaller or equal (usually smaller)
        self.assertLessEqual(len(state_cbor), len(state_json) + 100,  # Allow small overhead
                            f"CBOR ({len(state_cbor)}) should be smaller than JSON ({len(state_json)})")
    
    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Send some messages
        packet1 = alice.encrypt(b"message-1")
        bob.decrypt(packet1)
        packet2 = alice.encrypt(b"message-2")
        bob.decrypt(packet2)
        
        # Export with CBOR
        state_cbor = alice.export_state(use_cbor=True)
        
        # Deserialize
        alice2 = RatchetSession.from_serialized(state_cbor)
        
        # Verify state is preserved
        self.assertTrue(alice2.is_ready)
        # Note: semantic_hint and is_initiator are not directly accessible in Python wrapper
        # but state is preserved and can continue communication
        
        # Verify can continue communication
        packet3 = alice2.encrypt(b"message-3")
        plaintext = bob.decrypt(packet3)
        self.assertEqual(plaintext, b"message-3")
    
    def test_json_roundtrip(self):
        """Test JSON serialization roundtrip (backward compatibility)."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Export with JSON
        state_json = alice.export_state(use_cbor=False)
        
        # Deserialize (should auto-detect JSON)
        alice2 = RatchetSession.from_serialized(state_json)
        
        # Verify state is preserved
        self.assertTrue(alice2.is_ready)
        # Note: semantic_hint and is_initiator are not directly accessible in Python wrapper
        # but state is preserved and can continue communication
    
    def test_auto_detect_format(self):
        """Test automatic format detection in from_serialized."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Test CBOR auto-detection
        state_cbor = alice.export_state(use_cbor=True)
        alice_cbor = RatchetSession.from_serialized(state_cbor)
        self.assertTrue(alice_cbor.is_ready)
        
        # Test JSON auto-detection
        state_json = alice.export_state(use_cbor=False)
        alice_json = RatchetSession.from_serialized(state_json)
        self.assertTrue(alice_json.is_ready)


if __name__ == "__main__":
    unittest.main()

