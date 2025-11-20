import unittest
from pqfsr import RatchetSession

class TestSpeculativeKEM(unittest.TestCase):
    def test_nuclear_reactor_available(self):
        """Test that NuclearReactor (speculative KEM keygen) is available."""
        try:
            from pqfsr_core import NuclearReactor
            # NuclearReactor is available - test basic functionality
            reactor = NuclearReactor()
            # Give it a moment to start
            import time
            time.sleep(0.1)
            
            # Test that it can generate keys
            pk, sk = reactor.get_keypair()
            self.assertIsNotNone(pk)
            self.assertIsNotNone(sk)
            
            # Test encapsulation/decapsulation
            # Convert lists to bytes for PyO3
            pk_bytes = bytes(pk) if isinstance(pk, list) else pk
            sk_bytes = bytes(sk) if isinstance(sk, list) else sk
            ct, ss = reactor.encapsulate(pk_bytes)
            # Convert ct and ss to bytes if they're lists
            ct_bytes = bytes(ct) if isinstance(ct, list) else ct
            ss_bytes = bytes(ss) if isinstance(ss, list) else ss
            decapped = reactor.decapsulate(ct_bytes, sk_bytes)
            decapped_bytes = bytes(decapped) if isinstance(decapped, list) else decapped
            self.assertEqual(ss_bytes, decapped_bytes)
        except ImportError:
            # NuclearReactor not available - skip test
            self.skipTest("NuclearReactor not available")

if __name__ == "__main__":
    unittest.main()

