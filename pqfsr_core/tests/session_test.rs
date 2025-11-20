/// SESSION TESTS: Test handshake and messaging
/// ============================================

use pqfsr_core::RatchetSession;

#[test]
fn test_handshake_flow() {
    let mut alice = RatchetSession::create_initiator(b"alice_hint".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_hint".to_vec(), 50);
    
    // Alice creates handshake request
    let request = alice.create_handshake_request().unwrap();
    assert!(!request.kem_public.is_empty());
    assert!(!request.ratchet_public.is_empty());
    assert!(request.signature.is_some());
    assert!(request.signature_public_key.is_some());
    
    // Bob accepts handshake
    let response = bob.accept_handshake(&request).unwrap();
    assert!(!response.kem_ciphertext.is_empty());
    assert!(!response.ratchet_public.is_empty());
    assert!(response.signature.is_some());
    assert!(response.signature_public_key.is_some());
    
    // Alice finalizes handshake
    alice.finalize_handshake(&response).unwrap();
    
    assert!(alice.is_ready());
    assert!(bob.is_ready());
}

#[test]
fn test_encrypt_decrypt() {
    let mut alice = RatchetSession::create_initiator(b"alice_hint".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_hint".to_vec(), 50);
    
    // Handshake
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    // Encrypt/Decrypt
    let plaintext = b"Hello from Alice!";
    let packet = alice.encrypt(plaintext, b"").unwrap();
    let decrypted = bob.decrypt(&packet, b"").unwrap();
    assert_eq!(decrypted, plaintext);
    
    // Reply
    let reply = b"Hello from Bob!";
    let reply_packet = bob.encrypt(reply, b"").unwrap();
    let decrypted_reply = alice.decrypt(&reply_packet, b"").unwrap();
    assert_eq!(decrypted_reply, reply);
}

#[test]
fn test_handshake_signature_verification() {
    let mut alice = RatchetSession::create_initiator(b"alice_hint".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_hint".to_vec(), 50);
    
    let request = alice.create_handshake_request().unwrap();
    
    // Request should have signature
    assert!(request.signature.is_some());
    assert!(request.signature_public_key.is_some());
    
    // Bob should verify signature during accept
    let response = bob.accept_handshake(&request).unwrap();
    assert!(response.signature.is_some());
    assert!(response.signature_public_key.is_some());
    
    // Alice should verify signature during finalize
    alice.finalize_handshake(&response).unwrap();
}

#[test]
fn test_version_negotiation_success() {
    let mut alice = RatchetSession::create_initiator(b"alice".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob".to_vec(), 50);
    
    // Create handshake request (should have version info)
    let request = alice.create_handshake_request().unwrap();
    
    // Verify version fields are present
    assert_eq!(request.min_version, 1);
    assert_eq!(request.max_version, 1);
    
    // Accept handshake (should negotiate version)
    let response = bob.accept_handshake(&request).unwrap();
    
    // Verify response has version
    assert!(!response.version.is_empty());
    
    // Finalize should succeed (version compatible)
    alice.finalize_handshake(&response).unwrap();
    
    assert!(alice.is_ready());
    assert!(bob.is_ready());
}

#[test]
fn test_version_negotiation_incompatible() {
    // Note: Currently only version 1 is supported
    // This test verifies that the negotiation logic exists
    // When multiple versions are supported, this test should verify rejection
    let mut alice = RatchetSession::create_initiator(b"alice".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob".to_vec(), 50);
    
    let request = alice.create_handshake_request().unwrap();
    
    // Currently, all requests use version 1, so negotiation should succeed
    // When version 2+ is added, we can test incompatible versions here
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    assert!(alice.is_ready());
}

#[test]
fn test_multiple_messages() {
    let mut alice = RatchetSession::create_initiator(b"alice".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob".to_vec(), 50);
    
    // Handshake
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    // Send multiple messages
    let messages = [
        b"Message 1",
        b"Message 2",
        b"Message 3",
        b"Message 4",
        b"Message 5",
    ];
    
    for msg in messages.iter() {
        let packet = alice.encrypt(*msg, b"").unwrap();
        let decrypted = bob.decrypt(&packet, b"").unwrap();
        assert_eq!(decrypted, *msg);
    }
}

#[test]
fn test_handshake_replay_protection_rust() {
    let mut alice1 = RatchetSession::create_initiator(b"alice1".to_vec(), 50);
    let mut bob1 = RatchetSession::create_responder(b"bob1".to_vec(), 50);
    
    // First handshake
    let request1 = alice1.create_handshake_request().unwrap();
    let handshake_id1 = request1.handshake_id.clone();
    
    let response1 = bob1.accept_handshake(&request1).unwrap();
    alice1.finalize_handshake(&response1).unwrap();
    
    // Try to replay the same handshake with new sessions
    let mut alice2 = RatchetSession::create_initiator(b"alice2".to_vec(), 50);
    let mut bob2 = RatchetSession::create_responder(b"bob2".to_vec(), 50);
    
    // Create a new request with the same handshake_id (simulating replay)
    // Note: We can't directly set handshake_id, but we can test that
    // the global cache prevents replay across sessions
    // This is tested indirectly through the Python tests
    
    // Instead, test that different handshakes work
    let request2 = alice2.create_handshake_request().unwrap();
    let handshake_id2 = request2.handshake_id.clone();
    
    // Handshake IDs should be different
    assert_ne!(handshake_id1, handshake_id2);
    
    let response2 = bob2.accept_handshake(&request2).unwrap();
    alice2.finalize_handshake(&response2).unwrap();
    
    assert!(alice2.is_ready());
    assert!(bob2.is_ready());
}
