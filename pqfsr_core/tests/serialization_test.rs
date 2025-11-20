/// SERIALIZATION TESTS: Test state serialization (JSON and CBOR)
/// =============================================================

use pqfsr_core::{RatchetSession, serialize_state, deserialize_state, serialize_state_cbor, deserialize_state_cbor, encrypt_state, decrypt_state, pack_packet, unpack_packet};

#[test]
fn test_serialize_deserialize_state() {
    // Create a session and perform handshake
    let mut alice = RatchetSession::create_initiator(b"alice_hint".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_hint".to_vec(), 50);
    
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    // Export state
    let state = alice.get_state().unwrap();
    let semantic_hint = alice.semantic_hint();
    let is_initiator = alice.is_initiator();
    
    let serialized = serialize_state(state, semantic_hint, is_initiator);
    assert_eq!(serialized.schema_version, 1);
    assert_eq!(serialized.protocol_version, 1);
    
    // Deserialize
    let (deserialized_state, deserialized_hint, deserialized_initiator) = 
        deserialize_state(&serialized).unwrap();
    
    assert_eq!(deserialized_state.root_key, state.root_key);
    assert_eq!(deserialized_state.send_count, state.send_count);
    assert_eq!(deserialized_hint, semantic_hint);
    assert_eq!(deserialized_initiator, is_initiator);
}

#[test]
fn test_cbor_serialization() {
    // Create a session and perform handshake
    let mut alice = RatchetSession::create_initiator(b"alice_hint".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_hint".to_vec(), 50);
    
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    // Export state
    let state = alice.get_state().unwrap();
    let semantic_hint = alice.semantic_hint();
    let is_initiator = alice.is_initiator();
    
    // Serialize to CBOR
    let cbor_bytes = serialize_state_cbor(state, semantic_hint, is_initiator);
    assert!(!cbor_bytes.is_empty());
    
    // Deserialize from CBOR
    let (deserialized_state, deserialized_hint, deserialized_initiator) = 
        deserialize_state_cbor(&cbor_bytes).unwrap();
    
    assert_eq!(deserialized_state.root_key, state.root_key);
    assert_eq!(deserialized_state.send_count, state.send_count);
    assert_eq!(deserialized_hint, semantic_hint);
    assert_eq!(deserialized_initiator, is_initiator);
}

#[test]
fn test_encrypt_decrypt_state() {
    let state_json = b"test_state_data";
    let password = b"test_password";
    
    let encrypted = encrypt_state(state_json, password, None);
    assert!(!encrypted.is_empty());
    assert!(encrypted.starts_with(b"PQFSR_ENC_V1____"));
    
    let decrypted = decrypt_state(&encrypted, password, None).unwrap();
    assert_eq!(decrypted, state_json);
}

#[test]
fn test_encrypt_decrypt_state_wrong_password() {
    let state_json = b"test_state_data";
    let password = b"test_password";
    let wrong_password = b"wrong_password";
    
    let encrypted = encrypt_state(state_json, password, None);
    let result = decrypt_state(&encrypted, wrong_password, None);
    assert!(result.is_err());
}

#[test]
fn test_pack_unpack_packet() {
    use pqfsr_core::ratchet::Packet;
    
    // Create a test packet
    let original_packet = Packet {
        version: 1,
        count: 42,
        pn: 10,
        ratchet_pub: vec![0xAA; 1184], // Kyber768 public key size
        kem_ciphertext: vec![0xBB; 1088], // Kyber768 ciphertext size
        semantic_tag: vec![0xCC; 16],
        ciphertext: vec![0xDD; 100],
        nonce: Some(vec![0xEE; 12]),
    };
    
    // Pack packet
    let packed = pack_packet(&original_packet);
    assert!(!packed.is_empty());
    
    // Unpack packet
    let unpacked = unpack_packet(&packed).unwrap();
    
    // Verify roundtrip
    assert_eq!(unpacked.version, original_packet.version);
    assert_eq!(unpacked.count, original_packet.count);
    assert_eq!(unpacked.pn, original_packet.pn);
    assert_eq!(unpacked.ratchet_pub, original_packet.ratchet_pub);
    assert_eq!(unpacked.kem_ciphertext, original_packet.kem_ciphertext);
    assert_eq!(unpacked.semantic_tag, original_packet.semantic_tag);
    assert_eq!(unpacked.ciphertext, original_packet.ciphertext);
    // Note: nonce is not included in wire format
}

#[test]
fn test_pack_unpack_packet_no_kem() {
    use pqfsr_core::ratchet::Packet;
    
    // Create a packet without KEM (symmetric flow)
    let original_packet = Packet {
        version: 1,
        count: 0,
        pn: 0,
        ratchet_pub: vec![0xAA; 1184],
        kem_ciphertext: vec![], // Empty KEM (symmetric flow)
        semantic_tag: vec![0xCC; 16],
        ciphertext: vec![0xDD; 50],
        nonce: None,
    };
    
    // Pack and unpack
    let packed = pack_packet(&original_packet);
    let unpacked = unpack_packet(&packed).unwrap();
    
    // Verify
    assert_eq!(unpacked.version, original_packet.version);
    assert_eq!(unpacked.count, original_packet.count);
    assert_eq!(unpacked.kem_ciphertext, original_packet.kem_ciphertext);
    assert_eq!(unpacked.ciphertext, original_packet.ciphertext);
}

#[test]
fn test_pack_unpack_packet_roundtrip_with_session() {
    let mut alice = RatchetSession::create_initiator(b"alice".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob".to_vec(), 50);
    
    // Handshake
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    // Encrypt a message
    let plaintext = b"Test message for wire format";
    let packet = alice.encrypt(plaintext, b"").unwrap();
    
    // Pack packet
    let packed = pack_packet(&packet);
    assert!(!packed.is_empty());
    
    // Unpack packet
    let unpacked = unpack_packet(&packed).unwrap();
    
    // Decrypt using unpacked packet
    let decrypted = bob.decrypt(&unpacked, b"").unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_unpack_packet_invalid_data() {
    // Test with too short data (less than minimum header: 1 + 8 + 8 + 2 = 19 bytes)
    let short_data = vec![0u8; 10];
    let result = unpack_packet(&short_data);
    assert!(result.is_err());
    
    // Test with data that claims large lengths but doesn't have enough bytes
    let mut invalid_data = vec![0u8; 20];
    invalid_data[0] = 1; // version
    // count = 0 (bytes 1-8)
    // pn = 0 (bytes 9-16)
    invalid_data[17] = 0xFF; // kem_len high byte
    invalid_data[18] = 0xFF; // kem_len low byte (claims 65535 bytes)
    // But we only have 2 more bytes, so unpack should fail
    let result = unpack_packet(&invalid_data);
    assert!(result.is_err());
}

#[test]
fn test_pack_unpack_packet_format_validation() {
    use pqfsr_core::ratchet::Packet;
    
    // Test packet with various sizes
    let packet = Packet {
        version: 1,
        count: 12345,
        pn: 67890,
        ratchet_pub: vec![0x11; 500],
        kem_ciphertext: vec![0x22; 300],
        semantic_tag: vec![0x33; 16],
        ciphertext: vec![0x44; 2000], // Large ciphertext
        nonce: None,
    };
    
    let packed = pack_packet(&packet);
    let unpacked = unpack_packet(&packed).unwrap();
    
    // Verify all fields
    assert_eq!(unpacked.version, 1);
    assert_eq!(unpacked.count, 12345);
    assert_eq!(unpacked.pn, 67890);
    assert_eq!(unpacked.ratchet_pub.len(), 500);
    assert_eq!(unpacked.kem_ciphertext.len(), 300);
    assert_eq!(unpacked.semantic_tag.len(), 16);
    assert_eq!(unpacked.ciphertext.len(), 2000);
}

#[test]
fn test_json_vs_cbor_size_comparison() {
    let mut alice = RatchetSession::create_initiator(b"alice_hint".to_vec(), 50);
    let mut bob = RatchetSession::create_responder(b"bob_hint".to_vec(), 50);
    
    // Handshake
    let request = alice.create_handshake_request().unwrap();
    let response = bob.accept_handshake(&request).unwrap();
    alice.finalize_handshake(&response).unwrap();
    
    // Send a few messages to build up state
    for _ in 0..5 {
        let packet = alice.encrypt(b"test message", b"").unwrap();
        bob.decrypt(&packet, b"").unwrap();
    }
    
    // Export state
    let state = alice.get_state().unwrap();
    let semantic_hint = alice.semantic_hint();
    let is_initiator = alice.is_initiator();
    
    // Serialize to JSON
    let json_serialized = serialize_state(state, semantic_hint, is_initiator);
    let json_bytes = serde_json::to_vec(&json_serialized).unwrap();
    
    // Serialize to CBOR
    let cbor_bytes = serialize_state_cbor(state, semantic_hint, is_initiator);
    
    // CBOR should be smaller or equal to JSON
    println!("JSON size: {} bytes", json_bytes.len());
    println!("CBOR size: {} bytes", cbor_bytes.len());
    
    // Verify both can be deserialized
    let (json_state, _, _) = deserialize_state(&json_serialized).unwrap();
    let (cbor_state, _, _) = deserialize_state_cbor(&cbor_bytes).unwrap();
    
    // States should match
    assert_eq!(json_state.root_key, cbor_state.root_key);
    assert_eq!(json_state.send_count, cbor_state.send_count);
    
    // CBOR is typically more compact
    assert!(cbor_bytes.len() <= json_bytes.len() + 100); // Allow some overhead for CBOR structure
}

