/// SERIALIZATION MODULE: State Serialization and Wire Format
/// ==========================================================
/// This module handles serialization of ratchet state and wire format packing/unpacking.

use crate::crypto::{hkdf, Cipher, ChaCha20Poly1305Cipher};
use crate::state::RatchetState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ciborium::{into_writer, from_reader};
use std::io::Cursor;

/// Serialized State Structure
#[derive(Serialize, Deserialize)]
pub struct SerializedState {
    pub schema_version: u8,
    pub protocol_version: u8,
    pub data: StateData,
}

#[derive(Serialize, Deserialize)]
pub struct StateData {
    pub root_key: String,
    pub send_chain_key: String,
    pub recv_chain_key: String,
    pub send_label: String,
    pub recv_label: String,
    pub send_count: u64,
    pub recv_count: u64,
    pub previous_send_count: u64,
    pub local_ratchet_private: String,
    pub local_ratchet_public: String,
    pub remote_ratchet_public: Option<String>,
    pub combined_digest: String,
    pub local_digest: String,
    pub remote_digest: Option<String>,
    pub skipped_keys: Vec<(u64, String, String)>,
    pub max_skip: usize,
    pub semantic_hint: String,
    pub is_initiator: bool,
}

/// Serialize state to JSON
pub fn serialize_state(
    state: &RatchetState,
    semantic_hint: &[u8],
    is_initiator: bool,
) -> SerializedState {
    let skipped_keys: Vec<(u64, String, String)> = state
        .skipped_message_keys
        .iter()
        .map(|(idx, (key, nonce))| (*idx, hex::encode(key), hex::encode(nonce)))
        .collect();
    
    SerializedState {
        schema_version: 1,
        protocol_version: 1,
        data: StateData {
            root_key: hex::encode(&state.root_key),
            send_chain_key: hex::encode(&state.send_chain_key),
            recv_chain_key: hex::encode(&state.recv_chain_key),
            send_label: String::from_utf8_lossy(&state.send_label).to_string(),
            recv_label: String::from_utf8_lossy(&state.recv_label).to_string(),
            send_count: state.send_count,
            recv_count: state.recv_count,
            previous_send_count: state.previous_send_count,
            local_ratchet_private: hex::encode(&state.local_ratchet_private),
            local_ratchet_public: hex::encode(&state.local_ratchet_public),
            remote_ratchet_public: state.remote_ratchet_public.as_ref().map(|k| hex::encode(k)),
            combined_digest: hex::encode(&state.combined_digest),
            local_digest: hex::encode(&state.local_digest),
            remote_digest: state.remote_digest.as_ref().map(|d| hex::encode(d)),
            skipped_keys,
            max_skip: state.max_skip,
            semantic_hint: hex::encode(semantic_hint),
            is_initiator,
        },
    }
}

/// Deserialize state from JSON
pub fn deserialize_state(
    payload: &SerializedState,
) -> Result<(RatchetState, Vec<u8>, bool), String> {
    let data = &payload.data;
    
    let skipped_message_keys: HashMap<u64, (Vec<u8>, Vec<u8>)> = data
        .skipped_keys
        .iter()
        .map(|(idx, key_hex, nonce_hex)| {
            let key = hex::decode(key_hex)
                .map_err(|e| format!("Invalid key hex: {}", e))?;
            let nonce = hex::decode(nonce_hex)
                .map_err(|e| format!("Invalid nonce hex: {}", e))?;
            Ok((*idx, (key, nonce)))
        })
        .collect::<Result<HashMap<_, _>, String>>()?;
    
    let state = RatchetState {
        root_key: hex::decode(&data.root_key)
            .map_err(|e| format!("Invalid root_key hex: {}", e))?,
        send_chain_key: hex::decode(&data.send_chain_key)
            .map_err(|e| format!("Invalid send_chain_key hex: {}", e))?,
        recv_chain_key: hex::decode(&data.recv_chain_key)
            .map_err(|e| format!("Invalid recv_chain_key hex: {}", e))?,
        send_label: data.send_label.as_bytes().to_vec(),
        recv_label: data.recv_label.as_bytes().to_vec(),
        send_count: data.send_count,
        recv_count: data.recv_count,
        previous_send_count: data.previous_send_count,
        local_ratchet_private: hex::decode(&data.local_ratchet_private)
            .map_err(|e| format!("Invalid local_ratchet_private hex: {}", e))?,
        local_ratchet_public: hex::decode(&data.local_ratchet_public)
            .map_err(|e| format!("Invalid local_ratchet_public hex: {}", e))?,
        remote_ratchet_public: data.remote_ratchet_public.as_ref()
            .map(|k| hex::decode(k))
            .transpose()
            .map_err(|e| format!("Invalid remote_ratchet_public hex: {}", e))?,
        combined_digest: hex::decode(&data.combined_digest)
            .map_err(|e| format!("Invalid combined_digest hex: {}", e))?,
        local_digest: hex::decode(&data.local_digest)
            .map_err(|e| format!("Invalid local_digest hex: {}", e))?,
        remote_digest: data.remote_digest.as_ref()
            .map(|d| hex::decode(d))
            .transpose()
            .map_err(|e| format!("Invalid remote_digest hex: {}", e))?,
        skipped_message_keys,
        max_skip: data.max_skip,
    };
    
    let semantic_hint = hex::decode(&data.semantic_hint)
        .map_err(|e| format!("Invalid semantic_hint hex: {}", e))?;
    
    Ok((state, semantic_hint, data.is_initiator))
}

/// Serialize state to CBOR (production format)
/// 
/// CBOR is more compact and efficient than JSON for production use.
pub fn serialize_state_cbor(
    state: &RatchetState,
    semantic_hint: &[u8],
    is_initiator: bool,
) -> Vec<u8> {
    let serialized = serialize_state(state, semantic_hint, is_initiator);
    let mut buffer = Vec::new();
    into_writer(&serialized, &mut buffer).expect("CBOR serialization failed");
    buffer
}

/// Deserialize state from CBOR
/// 
/// Automatically detects CBOR format and deserializes.
pub fn deserialize_state_cbor(data: &[u8]) -> Result<(RatchetState, Vec<u8>, bool), String> {
    let mut cursor = Cursor::new(data);
    let payload: SerializedState = from_reader(&mut cursor)
        .map_err(|e| format!("CBOR deserialization failed: {:?}", e))?;
    deserialize_state(&payload)
}

/// Encrypt state at rest
pub fn encrypt_state(state_json: &[u8], password: &[u8], cipher: Option<Box<dyn Cipher>>) -> Vec<u8> {
    let cipher = cipher.unwrap_or_else(|| Box::new(ChaCha20Poly1305Cipher));
    
    let salt = b"PQ-FSR-STATE-ENC";
    let key = hkdf(password, salt, b"enc_key", 32);
    let nonce = hkdf(password, salt, b"enc_nonce", 12);
    
    let header = b"PQFSR_ENC_V1____";
    let ciphertext = cipher.encrypt(&key, &nonce, state_json, header);
    
    [header.as_slice(), &ciphertext].concat()
}

/// Decrypt state at rest
pub fn decrypt_state(blob: &[u8], password: &[u8], cipher: Option<Box<dyn Cipher>>) -> Result<Vec<u8>, String> {
    let cipher = cipher.unwrap_or_else(|| Box::new(ChaCha20Poly1305Cipher));
    
    if blob.len() < 16 {
        return Err("Blob too short".to_string());
    }
    
    let header = &blob[..16];
    if header != b"PQFSR_ENC_V1____" {
        return Err("Invalid encryption header".to_string());
    }
    
    let ciphertext = &blob[16..];
    
    let salt = b"PQ-FSR-STATE-ENC";
    let key = hkdf(password, salt, b"enc_key", 32);
    let nonce = hkdf(password, salt, b"enc_nonce", 12);
    
    cipher.decrypt(&key, &nonce, ciphertext, header)
}

/// Pack packet into binary wire format
pub fn pack_packet(packet: &crate::ratchet::Packet) -> Vec<u8> {
    use std::io::Write;
    
    let mut buf = Vec::new();
    
    // [version: 4][count: 4][pn: 4]
    buf.write_all(&packet.version.to_be_bytes()).unwrap();
    buf.write_all(&packet.count.to_be_bytes()).unwrap();
    buf.write_all(&packet.pn.to_be_bytes()).unwrap();
    
    // [kem_len: 2][kem_ct]
    if packet.kem_ciphertext.len() > 65535 {
        panic!("KEM ciphertext too large");
    }
    buf.write_all(&(packet.kem_ciphertext.len() as u16).to_be_bytes()).unwrap();
    buf.write_all(&packet.kem_ciphertext).unwrap();
    
    // [pub_len: 2][pub] - Changed to u16 to support Kyber768 (1184 bytes)
    if packet.ratchet_pub.len() > 65535 {
        panic!("Ratchet public key too large");
    }
    buf.write_all(&(packet.ratchet_pub.len() as u16).to_be_bytes()).unwrap();
    buf.write_all(&packet.ratchet_pub).unwrap();
    
    // [tag: 16]
    if packet.semantic_tag.len() != 16 {
        panic!("Invalid semantic tag length");
    }
    buf.write_all(&packet.semantic_tag).unwrap();
    
    // [ct_len: 4][ct]
    if packet.ciphertext.len() > 4294967295 {
        panic!("Ciphertext too large");
    }
    buf.write_all(&(packet.ciphertext.len() as u32).to_be_bytes()).unwrap();
    buf.write_all(&packet.ciphertext).unwrap();
    
    buf
}

/// Unpack binary packet
pub fn unpack_packet(data: &[u8]) -> Result<crate::ratchet::Packet, String> {
    if data.len() < 12 {
        return Err("Packet too short".to_string());
    }
    
    let mut offset = 0;
    
    // [version: 4][count: 4][pn: 4]
    let version = u8::from_be_bytes([data[offset]]);
    offset += 1;
    
    let count = u64::from_be_bytes({
        let mut bytes = [0u8; 8];
        bytes[..8].copy_from_slice(&data[offset..offset+8]);
        bytes
    });
    offset += 8;
    
    let pn = u64::from_be_bytes({
        let mut bytes = [0u8; 8];
        bytes[..8].copy_from_slice(&data[offset..offset+8]);
        bytes
    });
    offset += 8;
    
    // [kem_len: 2][kem_ct]
    if data.len() < offset + 2 {
        return Err("Packet too short for KEM length".to_string());
    }
    let kem_len = u16::from_be_bytes([data[offset], data[offset+1]]) as usize;
    offset += 2;
    
    if data.len() < offset + kem_len {
        return Err("Packet too short for KEM ciphertext".to_string());
    }
    let kem_ct = data[offset..offset+kem_len].to_vec();
    offset += kem_len;
    
    // [pub_len: 2][pub] - Changed to u16 to support Kyber768 (1184 bytes)
    if data.len() < offset + 2 {
        return Err("Packet too short for ratchet pub length".to_string());
    }
    let pub_len = u16::from_be_bytes([data[offset], data[offset+1]]) as usize;
    offset += 2;
    
    if data.len() < offset + pub_len {
        return Err("Packet too short for ratchet pub".to_string());
    }
    let ratchet_pub = data[offset..offset+pub_len].to_vec();
    offset += pub_len;
    
    // [tag: 16]
    if data.len() < offset + 16 {
        return Err("Packet too short for semantic tag".to_string());
    }
    let semantic_tag = data[offset..offset+16].to_vec();
    offset += 16;
    
    // [ct_len: 4][ct]
    if data.len() < offset + 4 {
        return Err("Packet too short for ciphertext length".to_string());
    }
    let ct_len = u32::from_be_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3]
    ]) as usize;
    offset += 4;
    
    if data.len() < offset + ct_len {
        return Err("Packet too short for ciphertext".to_string());
    }
    let ciphertext = data[offset..offset+ct_len].to_vec();
    
    Ok(crate::ratchet::Packet {
        version,
        count,
        pn,
        ratchet_pub,
        kem_ciphertext: kem_ct,
        semantic_tag,
        ciphertext,
        nonce: None,
    })
}
