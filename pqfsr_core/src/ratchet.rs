/// RATCHET MODULE: Core Forward-Secret Ratchet Logic
/// ==================================================
/// This module implements the core forward-secret ratchet mechanism.
/// It handles KEM ratcheting, symmetric key derivation, and message encryption/decryption.

use crate::crypto::{hkdf, sha256, constant_time_eq, Cipher, ChaCha20Poly1305Cipher};
use crate::state::RatchetState;
use crate::strategy::{OrganicStrategy, RatchetMode};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::*;
use std::collections::HashMap;
use zeroize::Zeroize;

// Protocol constants
const LABEL_A_TO_B: &[u8] = b"CHAIN|A2B";
const LABEL_B_TO_A: &[u8] = b"CHAIN|B2A";
const DIRECTION_SEND: &[u8] = b"SEND";
const NONCE_LEN: usize = 12;

/// Forward Ratchet: Core protocol implementation
pub struct ForwardRatchet {
    cipher: Box<dyn Cipher>,
    strategy: OrganicStrategy,
    max_skip: usize,
}

impl ForwardRatchet {
    /// Create a new ForwardRatchet
    pub fn new(max_skip: usize) -> Self {
        Self {
            cipher: Box::new(ChaCha20Poly1305Cipher),
            strategy: OrganicStrategy::new(RatchetMode::BalancedFlow),
            max_skip,
        }
    }
    
    /// Create with custom cipher and strategy
    pub fn with_cipher_and_strategy(
        cipher: Box<dyn Cipher>,
        strategy: OrganicStrategy,
        max_skip: usize,
    ) -> Self {
        Self {
            cipher,
            strategy,
            max_skip,
        }
    }
    
    /// Mix root key with shared secret
    fn mix_root(previous_root: Option<&[u8]>, shared_secret: &[u8], semantic_digest: &[u8]) -> Vec<u8> {
        let base = if let Some(prev) = previous_root {
            [prev, shared_secret, semantic_digest].concat()
        } else {
            [[0u8; 32].as_slice(), shared_secret, semantic_digest].concat()
        };
        sha256(&base)
    }
    
    /// Derive chain seed from root key
    fn derive_chain_seed(root_key: &[u8], semantic_digest: &[u8], label: &[u8]) -> Vec<u8> {
        hkdf(root_key, semantic_digest, label, 32)
    }
    
    /// Derive message material (key, next chain, nonce)
    fn derive_message_material(
        chain_key: &[u8],
        counter: u64,
        semantic_digest: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let counter_bytes = counter.to_be_bytes();
        let input_km = [chain_key, &counter_bytes].concat();
        
        let message_key = hkdf(&input_km, semantic_digest, b"PQ-FSR msg", 32);
        let next_chain = hkdf(&input_km, semantic_digest, b"PQ-FSR chain", 32);
        let nonce = hkdf(&input_km, semantic_digest, b"PQ-FSR nonce", NONCE_LEN);
        
        (message_key, next_chain, nonce)
    }
    
    /// Compute semantic tag
    fn compute_semantic_tag(combined_digest: &[u8], counter: u64) -> Vec<u8> {
        let payload = [
            combined_digest,
            &counter.to_be_bytes(),
            DIRECTION_SEND,
        ].concat();
        sha256(&payload)[..16].to_vec()  // First 16 bytes
    }
    
    /// Generate KEM key pair
    pub fn generate_kem_key_pair(&self) -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = kyber768::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
    
    /// Bootstrap ratchet state
    pub fn bootstrap(
        &self,
        shared_secret: &[u8],
        combined_digest: &[u8],
        local_digest: &[u8],
        remote_digest: Option<&[u8]>,
        is_initiator: bool,
        local_key_pair: Option<(Vec<u8>, Vec<u8>)>,
    ) -> RatchetState {
        let root = Self::mix_root(None, shared_secret, combined_digest);
        
        let (send_label, recv_label) = if is_initiator {
            (LABEL_A_TO_B.to_vec(), LABEL_B_TO_A.to_vec())
        } else {
            (LABEL_B_TO_A.to_vec(), LABEL_A_TO_B.to_vec())
        };
        
        let send_chain = Self::derive_chain_seed(&root, combined_digest, &send_label);
        let recv_chain = Self::derive_chain_seed(&root, combined_digest, &recv_label);
        
        let (local_public, local_private) = local_key_pair
            .unwrap_or_else(|| self.generate_kem_key_pair());
        
        RatchetState {
            root_key: root,
            send_chain_key: send_chain,
            recv_chain_key: recv_chain,
            send_label,
            recv_label,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            local_ratchet_private: local_private,
            local_ratchet_public: local_public,
            remote_ratchet_public: None,
            combined_digest: combined_digest.to_vec(),
            local_digest: local_digest.to_vec(),
            remote_digest: remote_digest.map(|d| d.to_vec()),
            skipped_message_keys: HashMap::new(),
            max_skip: self.max_skip,
        }
    }
    
    /// Encrypt a message
    pub fn encrypt(
        &mut self,
        state: &mut RatchetState,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Packet, String> {
        if state.remote_ratchet_public.is_none() {
            return Err("Remote ratchet public key missing".to_string());
        }
        
        let do_pulse = self.strategy.should_trigger_quantum_pulse(plaintext.len());
        
        let mut kem_ciphertext = vec![];
        let mut pn = state.previous_send_count;
        
        if do_pulse {
            // KEM Pulse: Rotate root key
            let remote_pk = PublicKey::from_bytes(&state.remote_ratchet_public.as_ref().unwrap())
                .map_err(|e| format!("Invalid remote public key: {:?}", e))?;
            
            let (ss, ct) = kyber768::encapsulate(&remote_pk);
            let shared_secret = ss.as_bytes().to_vec();
            
            // Mix root key
            state.root_key = Self::mix_root(
                Some(&state.root_key),
                &shared_secret,
                &state.combined_digest,
            );
            
            // Derive new chain keys
            state.send_chain_key = Self::derive_chain_seed(
                &state.root_key,
                &state.combined_digest,
                &state.send_label,
            );
            state.recv_chain_key = Self::derive_chain_seed(
                &state.root_key,
                &state.combined_digest,
                &state.recv_label,
            );
            
            // Generate new key pair
            let (new_public, new_private) = self.generate_kem_key_pair();
            
            // Zeroize old private key
            state.local_ratchet_private.zeroize();
            state.local_ratchet_private = new_private;
            state.local_ratchet_public = new_public;
            
            // Update epoch tracking
            state.previous_send_count = state.send_count;
            state.send_count = 0;
            pn = state.previous_send_count;
            
            kem_ciphertext = ct.as_bytes().to_vec();
            self.strategy.record_pulse();
        } else {
            self.strategy.record_flow(plaintext.len());
            pn = state.previous_send_count;
        }
        
        // Derive message material
        let (message_key, next_chain, nonce) = Self::derive_message_material(
            &state.send_chain_key,
            state.send_count,
            &state.combined_digest,
        );
        state.send_chain_key = next_chain;
        
        // Compute semantic tag
        let semantic_tag = Self::compute_semantic_tag(&state.combined_digest, state.send_count);
        
        // Build associated data
        let ad_bind = [
            associated_data,
            &semantic_tag,
            &state.send_count.to_be_bytes(),
            &pn.to_be_bytes(),
        ].concat();
        
        // Encrypt
        let ciphertext = self.cipher.encrypt(&message_key, &nonce, plaintext, &ad_bind);
        
        state.send_count += 1;
        
        Ok(Packet {
            version: 1,
            count: state.send_count - 1,  // Count before increment
            pn,
            ratchet_pub: state.local_ratchet_public.clone(),
            kem_ciphertext,
            semantic_tag,
            ciphertext,
            nonce: Some(nonce),
        })
    }
    
    /// Decrypt a message
    pub fn decrypt(
        &mut self,
        state: &mut RatchetState,
        packet: &Packet,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let message_index = packet.count;
        let is_pulse = !packet.kem_ciphertext.is_empty();
        
        // Check semantic tag
        let expected_semantic = Self::compute_semantic_tag(&state.combined_digest, message_index);
        if !constant_time_eq(&expected_semantic, &packet.semantic_tag) {
            return Err("Semantic tag mismatch".to_string());
        }
        
        // Check skipped message cache
        if let Some((cached_key, cached_nonce)) = state.recover_skipped_key(message_index) {
            if let Some(ref packet_nonce) = packet.nonce {
                if !constant_time_eq(&cached_nonce, packet_nonce) {
                    return Err("Nonce mismatch".to_string());
                }
            }
            
            let ad_bind = [
                associated_data,
                &packet.semantic_tag,
                &message_index.to_be_bytes(),
                &packet.pn.to_be_bytes(),
            ].concat();
            
            match self.cipher.decrypt(&cached_key, &cached_nonce, &packet.ciphertext, &ad_bind) {
                Ok(plaintext) => {
                    self.strategy.record_reception();
                    return Ok(plaintext);
                }
                Err(_) => {
                    return Err("Message already processed".to_string());
                }
            }
        }
        
        // Handle KEM pulse
        if is_pulse {
            // Process skipped messages from previous epoch
            if state.recv_count < packet.pn {
                while state.recv_count < packet.pn {
                    let (msg_key, next_chain, skipped_nonce) = Self::derive_message_material(
                        &state.recv_chain_key,
                        state.recv_count,
                        &state.combined_digest,
                    );
                    state.recv_chain_key = next_chain;
                    state.store_skipped_key(state.recv_count, msg_key, skipped_nonce);
                    state.recv_count += 1;
                }
            }
            
            // Decapsulate KEM
            let ct = Ciphertext::from_bytes(&packet.kem_ciphertext)
                .map_err(|e| format!("Invalid KEM ciphertext: {:?}", e))?;
            let sk = SecretKey::from_bytes(&state.local_ratchet_private)
                .map_err(|e| format!("Invalid local secret key: {:?}", e))?;
            
            let ss = kyber768::decapsulate(&ct, &sk);
            let shared_secret = ss.as_bytes().to_vec();
            
            // Mix root key
            state.root_key = Self::mix_root(
                Some(&state.root_key),
                &shared_secret,
                &state.combined_digest,
            );
            
            // Update remote ratchet public key
            state.remote_ratchet_public = Some(packet.ratchet_pub.clone());
            
            // Derive new chain keys
            state.send_chain_key = Self::derive_chain_seed(
                &state.root_key,
                &state.combined_digest,
                &state.send_label,
            );
            state.recv_chain_key = Self::derive_chain_seed(
                &state.root_key,
                &state.combined_digest,
                &state.recv_label,
            );
            
            state.recv_count = 0;
        }
        
        // Check for out-of-order messages
        if message_index < state.recv_count {
            return Err("Message already processed".to_string());
        }
        
        // Process skipped messages in current epoch
        while state.recv_count < message_index {
            let (msg_key, next_chain, skipped_nonce) = Self::derive_message_material(
                &state.recv_chain_key,
                state.recv_count,
                &state.combined_digest,
            );
            state.recv_chain_key = next_chain;
            state.store_skipped_key(state.recv_count, msg_key, skipped_nonce);
            state.recv_count += 1;
        }
        
        // Derive message material for current message
        let (message_key, next_chain, derived_nonce) = Self::derive_message_material(
            &state.recv_chain_key,
            state.recv_count,
            &state.combined_digest,
        );
        state.recv_chain_key = next_chain;
        
        // Use nonce from packet if provided, otherwise use derived nonce
        // The nonce in the packet is authoritative and should match the derived one
        let nonce = if let Some(ref packet_nonce) = packet.nonce {
            // Verify that packet nonce matches derived nonce (security check)
            if !constant_time_eq(&derived_nonce, packet_nonce) {
                return Err("Nonce mismatch".to_string());
            }
            packet_nonce.clone()
        } else {
            derived_nonce
        };
        
        // Build associated data
        let ad_bind = [
            associated_data,
            &packet.semantic_tag,
            &message_index.to_be_bytes(),
            &packet.pn.to_be_bytes(),
        ].concat();
        
        // Decrypt
        let plaintext = self.cipher.decrypt(&message_key, &nonce, &packet.ciphertext, &ad_bind)?;
        
        state.recv_count += 1;
        self.strategy.record_reception();
        
        Ok(plaintext)
    }
}

/// Packet: Message packet structure
#[derive(Clone, Debug)]
pub struct Packet {
    pub version: u8,
    pub count: u64,
    pub pn: u64,
    pub ratchet_pub: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub semantic_tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
}

