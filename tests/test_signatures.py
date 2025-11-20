"""Tests for Dilithium signature functionality."""

import unittest

from pqfsr import DilithiumSignatures


class TestDilithiumSignatures(unittest.TestCase):
    """Test Dilithium (ML-DSA) signature operations."""
    
    def test_generate_key_pair(self):
        """Test key pair generation."""
        result = DilithiumSignatures.generate_key_pair()
        pk, sk = result
        
        self.assertIsInstance(pk, bytes)
        self.assertIsInstance(sk, bytes)
        self.assertGreater(len(pk), 0)
        self.assertGreater(len(sk), 0)
        self.assertNotEqual(pk, sk)
        
        # Generate another pair - should be different
        result2 = DilithiumSignatures.generate_key_pair()
        pk2, sk2 = result2
        self.assertNotEqual(pk, pk2)
        self.assertNotEqual(sk, sk2)
    
    def test_sign_and_verify(self):
        """Test signing and verification."""
        result = DilithiumSignatures.generate_key_pair()
        pk, sk = result
        message = b"Hello, quantum world!"
        
        signature = DilithiumSignatures.sign_message(message, sk)
        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 0)
        
        valid = DilithiumSignatures.verify_signature(message, signature, pk)
        self.assertTrue(valid)
    
    def test_sign_and_verify_wrong_message(self):
        """Test that wrong message fails verification."""
        result = DilithiumSignatures.generate_key_pair()
        pk, sk = result
        message = b"Hello, quantum world!"
        wrong_message = b"Hello, classical world!"
        
        signature = DilithiumSignatures.sign_message(message, sk)
        valid = DilithiumSignatures.verify_signature(wrong_message, signature, pk)
        self.assertFalse(valid)
    
    def test_sign_and_verify_wrong_key(self):
        """Test that wrong public key fails verification."""
        result1 = DilithiumSignatures.generate_key_pair()
        pk1, sk1 = result1
        result2 = DilithiumSignatures.generate_key_pair()
        pk2, _sk2 = result2
        message = b"Hello, quantum world!"
        
        signature = DilithiumSignatures.sign_message(message, sk1)
        valid = DilithiumSignatures.verify_signature(message, signature, pk2)
        self.assertFalse(valid)
    
    def test_sign_and_verify_empty_message(self):
        """Test signing and verifying empty message."""
        result = DilithiumSignatures.generate_key_pair()
        pk, sk = result
        message = b""
        
        signature = DilithiumSignatures.sign_message(message, sk)
        valid = DilithiumSignatures.verify_signature(message, signature, pk)
        self.assertTrue(valid)
    
    def test_sign_and_verify_large_message(self):
        """Test signing and verifying large message."""
        result = DilithiumSignatures.generate_key_pair()
        pk, sk = result
        message = b"x" * 10000  # 10KB message
        
        signature = DilithiumSignatures.sign_message(message, sk)
        valid = DilithiumSignatures.verify_signature(message, signature, pk)
        self.assertTrue(valid)
    
    def test_signature_consistency(self):
        """Test that same message and key produce valid signatures (may not be identical due to randomness)."""
        result = DilithiumSignatures.generate_key_pair()
        pk, sk = result
        message = b"Consistency test message"
        
        sig1 = DilithiumSignatures.sign_message(message, sk)
        sig2 = DilithiumSignatures.sign_message(message, sk)
        
        # Both signatures should verify (even if not identical)
        valid1 = DilithiumSignatures.verify_signature(message, sig1, pk)
        valid2 = DilithiumSignatures.verify_signature(message, sig2, pk)
        self.assertTrue(valid1)
        self.assertTrue(valid2)
    
    def test_invalid_secret_key(self):
        """Test that invalid secret key raises error."""
        message = b"test"
        invalid_sk = b"invalid" * 10
        
        with self.assertRaises(ValueError):
            DilithiumSignatures.sign_message(message, invalid_sk)
    
    def test_invalid_public_key(self):
        """Test that invalid public key raises error."""
        result = DilithiumSignatures.generate_key_pair()
        pk, sk = result
        message = b"test"
        signature = DilithiumSignatures.sign_message(message, sk)
        invalid_pk = b"invalid" * 10
        
        with self.assertRaises(ValueError):
            DilithiumSignatures.verify_signature(message, signature, invalid_pk)
    
    def test_invalid_signature_format(self):
        """Test that invalid signature format returns False or raises error."""
        result = DilithiumSignatures.generate_key_pair()
        pk, sk = result
        message = b"test"
        invalid_sig = b"invalid" * 10
        
        # Invalid signature should either raise ValueError or return False
        try:
            valid = DilithiumSignatures.verify_signature(message, invalid_sig, pk)
            self.assertFalse(valid, "Invalid signature should return False")
        except ValueError:
            # Also acceptable - invalid format raises error
            pass


if __name__ == "__main__":
    unittest.main()

