/// COMMON TEST UTILITIES
/// ======================
/// Shared utilities for Rust tests

use pqfsr_core::RatchetSession;

/// Create a test session pair (alice and bob) with completed handshake
pub fn create_test_session_pair() -> (RatchetSession, RatchetSession) {
    let mut alice = RatchetSession::create_initiator(b"alice_test".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_test".to_vec(), 50);
    
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    (alice, bob)
}

/// Create a test session pair with custom max_skip
pub fn create_test_session_pair_with_skip(max_skip: usize) -> (RatchetSession, RatchetSession) {
    let mut alice = RatchetSession::create_initiator(b"alice_test".to_vec(), max_skip);
    let mut bob = RatchetSession::create_responder(b"bob_test".to_vec(), max_skip);
    
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    (alice, bob)
}

/// Helper to exchange a message between two sessions
pub fn exchange_message(
    sender: &mut RatchetSession,
    receiver: &mut RatchetSession,
    message: &[u8],
) -> Result<Vec<u8>, String> {
    let packet = sender.encrypt(message, b"")?;
    receiver.decrypt(&packet, b"")
}

