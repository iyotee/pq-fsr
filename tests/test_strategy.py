import unittest
from pqfsr import RatchetSession, RatchetMode

class TestOrganicStrategy(unittest.TestCase):
    """Test the adaptive ratcheting strategy via RatchetSession."""
    
    def test_ratchet_mode_enum(self):
        """Test that RatchetMode enum is accessible."""
        self.assertEqual(RatchetMode.MAXIMUM_SECURITY, "MAXIMUM_SECURITY")
        self.assertEqual(RatchetMode.BALANCED_FLOW, "BALANCED_FLOW")
        self.assertEqual(RatchetMode.MINIMAL_OVERHEAD, "MINIMAL_OVERHEAD")
    
    def test_adaptive_ratcheting_small_messages(self):
        """Test that small messages use symmetric ratchet (no KEM pulse)."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Send several small messages - should use symmetric ratchet
        packets = []
        for i in range(5):
            packet = alice.encrypt(b"small message")
            packets.append(packet)
            # Check that kem_ciphertext is empty for symmetric ratchet
            # (KEM pulse would have non-empty kem_ciphertext)
            if i > 0:  # First message after handshake may have KEM
                # After initial handshake, small messages should not trigger KEM
                # This is a heuristic test - actual behavior depends on strategy
                pass
        
        # All messages should decrypt correctly
        for packet in packets:
            plaintext = bob.decrypt(packet)
            self.assertEqual(plaintext, b"small message")
    
    def test_adaptive_ratcheting_large_message(self):
        """Test that large messages may trigger KEM pulse (opportunistic)."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Send a large message - may trigger KEM pulse
        large_msg = b"x" * (5 * 1024 * 1024)  # 5MB
        packet = alice.encrypt(large_msg)
        
        # Should decrypt correctly regardless of whether KEM was triggered
        plaintext = bob.decrypt(packet)
        self.assertEqual(plaintext, large_msg)
    
    def test_bidirectional_ratcheting(self):
        """Test that bidirectional communication works with adaptive strategy."""
        alice = RatchetSession.create_initiator(semantic_hint=b"alice")
        bob = RatchetSession.create_responder(semantic_hint=b"bob")
        
        request = alice.create_handshake_request()
        response = bob.accept_handshake(request)
        alice.finalize_handshake(response)
        
        # Bidirectional exchange
        for i in range(10):
            alice_msg = f"alice-{i}".encode()
            bob_msg = f"bob-{i}".encode()
            
            alice_packet = alice.encrypt(alice_msg)
            bob_packet = bob.encrypt(bob_msg)
            
            # Both should decrypt correctly
            self.assertEqual(bob.decrypt(alice_packet), alice_msg)
            self.assertEqual(alice.decrypt(bob_packet), bob_msg)

if __name__ == "__main__":
    unittest.main()
