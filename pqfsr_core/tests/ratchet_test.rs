/// RATCHET TESTS: Test ForwardRatchet core functionality
/// =====================================================

use pqfsr_core::ForwardRatchet;

#[test]
fn test_bootstrap() {
    let ratchet = ForwardRatchet::new(32);
    let shared_secret = vec![0u8; 32];
    let combined_digest = vec![1u8; 32];
    let local_digest = vec![2u8; 32];
    
    let state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, true, None);
    
    // Verify state initialization
    assert_eq!(state.send_count, 0);
    assert_eq!(state.recv_count, 0);
    assert!(!state.root_key.is_empty());
    assert_eq!(state.root_key.len(), 32);
    assert!(!state.send_chain_key.is_empty());
    assert!(!state.recv_chain_key.is_empty());
}

#[test]
fn test_bootstrap_deterministic() {
    let ratchet = ForwardRatchet::new(32);
    let shared_secret = vec![0u8; 32];
    let combined_digest = vec![1u8; 32];
    let local_digest = vec![2u8; 32];
    
    let state1 = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, true, None);
    let state2 = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, true, None);
    
    // Bootstrap should be deterministic (but keys will differ due to random generation)
    assert_eq!(state1.root_key, state2.root_key);
    assert_eq!(state1.send_chain_key, state2.send_chain_key);
    assert_eq!(state1.recv_chain_key, state2.recv_chain_key);
}

#[test]
fn test_bootstrap_different_inputs() {
    let ratchet = ForwardRatchet::new(32);
    let shared_secret1 = vec![0u8; 32];
    let shared_secret2 = vec![1u8; 32];
    let combined_digest = vec![1u8; 32];
    let local_digest = vec![2u8; 32];
    
    let state1 = ratchet.bootstrap(&shared_secret1, &combined_digest, &local_digest, None, true, None);
    let state2 = ratchet.bootstrap(&shared_secret2, &combined_digest, &local_digest, None, true, None);
    
    // Different inputs should produce different states
    assert_ne!(state1.root_key, state2.root_key);
}

#[test]
fn test_encrypt_basic() {
    let mut ratchet = ForwardRatchet::new(32);
    let shared_secret = vec![0u8; 32];
    let combined_digest = vec![1u8; 32];
    let local_digest = vec![2u8; 32];
    
    // Generate key pairs for both sides
    let (alice_pk, alice_sk) = ratchet.generate_kem_key_pair();
    let (bob_pk, _bob_sk) = ratchet.generate_kem_key_pair();
    
    let mut state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, true, Some((alice_pk.clone(), alice_sk)));
    state.remote_ratchet_public = Some(bob_pk);
    
    let plaintext = b"Hello, World!";
    let ad = b"associated_data";
    
    let packet = ratchet.encrypt(&mut state, plaintext, ad).unwrap();
    
    // Verify packet structure
    assert_eq!(packet.version, 1);
    assert_eq!(packet.count, 0);
    assert!(!packet.ciphertext.is_empty());
    assert!(!packet.semantic_tag.is_empty());
    assert_eq!(packet.semantic_tag.len(), 16);
    
    // State should be updated
    assert_eq!(state.send_count, 1);
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let mut ratchet = ForwardRatchet::new(32);
    let shared_secret = vec![0u8; 32];
    let combined_digest = vec![1u8; 32];
    let local_digest = vec![2u8; 32];
    
    // Generate key pairs
    let (alice_pk, alice_sk) = ratchet.generate_kem_key_pair();
    let (bob_pk, bob_sk) = ratchet.generate_kem_key_pair();
    
    // Alice (initiator) bootstraps
    let mut send_state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, true, Some((alice_pk.clone(), alice_sk)));
    send_state.remote_ratchet_public = Some(bob_pk.clone());
    
    // Bob (responder) bootstraps
    let mut receive_state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, false, Some((bob_pk, bob_sk)));
    receive_state.remote_ratchet_public = Some(alice_pk);
    
    let plaintext = b"Hello, World!";
    let ad = b"associated_data";
    
    // Encrypt
    let packet = ratchet.encrypt(&mut send_state, plaintext, ad).unwrap();
    
    // Decrypt
    let decrypted = ratchet.decrypt(&mut receive_state, &packet, ad).unwrap();
    
    assert_eq!(decrypted, plaintext);
    assert_eq!(receive_state.recv_count, 1);
}

#[test]
fn test_encrypt_multiple_messages() {
    let mut ratchet = ForwardRatchet::new(32);
    let shared_secret = vec![0u8; 32];
    let combined_digest = vec![1u8; 32];
    let local_digest = vec![2u8; 32];
    
    // Generate key pairs
    let (alice_pk, alice_sk) = ratchet.generate_kem_key_pair();
    let (bob_pk, bob_sk) = ratchet.generate_kem_key_pair();
    
    let mut send_state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, true, Some((alice_pk.clone(), alice_sk)));
    send_state.remote_ratchet_public = Some(bob_pk.clone());
    
    let mut receive_state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, false, Some((bob_pk, bob_sk)));
    receive_state.remote_ratchet_public = Some(alice_pk);
    
    let messages = [b"Message 1", b"Message 2", b"Message 3"];
    let ad = b"";
    
    for (i, msg) in messages.iter().enumerate() {
        let packet = ratchet.encrypt(&mut send_state, *msg, ad).unwrap();
        assert_eq!(packet.count, i as u64);
        
        let decrypted = ratchet.decrypt(&mut receive_state, &packet, ad).unwrap();
        assert_eq!(decrypted, *msg);
    }
    
    assert_eq!(send_state.send_count, 3);
    assert_eq!(receive_state.recv_count, 3);
}

#[test]
fn test_decrypt_out_of_order() {
    let mut ratchet = ForwardRatchet::new(32);
    let shared_secret = vec![0u8; 32];
    let combined_digest = vec![1u8; 32];
    let local_digest = vec![2u8; 32];
    
    // Generate key pairs
    let (alice_pk, alice_sk) = ratchet.generate_kem_key_pair();
    let (bob_pk, bob_sk) = ratchet.generate_kem_key_pair();
    
    let mut send_state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, true, Some((alice_pk.clone(), alice_sk)));
    send_state.remote_ratchet_public = Some(bob_pk.clone());
    
    let mut receive_state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, false, Some((bob_pk, bob_sk)));
    receive_state.remote_ratchet_public = Some(alice_pk);
    
    let ad = b"";
    
    // Encrypt 3 messages
    let packet0 = ratchet.encrypt(&mut send_state, b"Message 0", ad).unwrap();
    let packet1 = ratchet.encrypt(&mut send_state, b"Message 1", ad).unwrap();
    let packet2 = ratchet.encrypt(&mut send_state, b"Message 2", ad).unwrap();
    
    // Decrypt out of order: 2, 0, 1
    let decrypted2 = ratchet.decrypt(&mut receive_state, &packet2, ad).unwrap();
    assert_eq!(decrypted2, b"Message 2");
    
    let decrypted0 = ratchet.decrypt(&mut receive_state, &packet0, ad).unwrap();
    assert_eq!(decrypted0, b"Message 0");
    
    let decrypted1 = ratchet.decrypt(&mut receive_state, &packet1, ad).unwrap();
    assert_eq!(decrypted1, b"Message 1");
    
    assert_eq!(receive_state.recv_count, 3);
}

#[test]
fn test_decrypt_wrong_associated_data() {
    let mut ratchet = ForwardRatchet::new(32);
    let shared_secret = vec![0u8; 32];
    let combined_digest = vec![1u8; 32];
    let local_digest = vec![2u8; 32];
    
    // Generate key pairs
    let (alice_pk, alice_sk) = ratchet.generate_kem_key_pair();
    let (bob_pk, bob_sk) = ratchet.generate_kem_key_pair();
    
    let mut send_state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, true, Some((alice_pk.clone(), alice_sk)));
    send_state.remote_ratchet_public = Some(bob_pk.clone());
    
    let mut receive_state = ratchet.bootstrap(&shared_secret, &combined_digest, &local_digest, None, false, Some((bob_pk, bob_sk)));
    receive_state.remote_ratchet_public = Some(alice_pk);
    
    let plaintext = b"Hello, World!";
    let ad1 = b"ad1";
    let ad2 = b"ad2";
    
    let packet = ratchet.encrypt(&mut send_state, plaintext, ad1).unwrap();
    
    // Decrypt with wrong AD should fail
    let result = ratchet.decrypt(&mut receive_state, &packet, ad2);
    assert!(result.is_err());
}

// Note: KEM pulse is tested indirectly through encrypt/decrypt tests
// The pulse is triggered automatically by the strategy based on message size

#[test]
fn test_generate_kem_key_pair() {
    let ratchet = ForwardRatchet::new(32);
    
    let (pk1, sk1) = ratchet.generate_kem_key_pair();
    let (pk2, sk2) = ratchet.generate_kem_key_pair();
    
    // Keys should be non-empty
    assert!(!pk1.is_empty());
    assert!(!sk1.is_empty());
    
    // Different calls should produce different keys
    assert_ne!(pk1, pk2);
    assert_ne!(sk1, sk2);
}

