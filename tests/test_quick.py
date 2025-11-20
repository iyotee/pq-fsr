#!/usr/bin/env python3
"""Quick test script to validate Rust implementation."""

import sys
import os

# Add pq-fsr to path
sys.path.insert(0, os.path.dirname(__file__))

try:
    from pqfsr import RatchetSession
    print("✓ Import successful")
except ImportError as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)

# Test basic creation
try:
    alice = RatchetSession.create_initiator(semantic_hint=b"alice")
    bob = RatchetSession.create_responder(semantic_hint=b"bob")
    print("✓ Session creation successful")
except Exception as e:
    print(f"✗ Session creation failed: {e}")
    sys.exit(1)

# Test handshake
try:
    request = alice.create_handshake_request()
    print("✓ Handshake request created")
    
    response = bob.accept_handshake(request)
    print("✓ Handshake accepted")
    
    alice.finalize_handshake(response)
    print("✓ Handshake finalized")
    
    assert alice.is_ready
    assert bob.is_ready
    print("✓ Sessions are ready")
except Exception as e:
    print(f"✗ Handshake failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test encryption/decryption
try:
    msg = b"Hello, world!"
    packet = alice.encrypt(msg)
    print("✓ Encryption successful")
    
    decrypted = bob.decrypt(packet)
    print("✓ Decryption successful")
    
    assert decrypted == msg
    print("✓ Roundtrip successful")
except Exception as e:
    print(f"✗ Encryption/decryption failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n✅ All basic tests passed!")

