/// STATE MODULE: Core Data Structures
/// ===================================
/// This module defines the core state structures for the PQ-FSR protocol.
/// All sensitive data is automatically zeroized on drop.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

/// Maximum number of skipped message keys to cache (default: 50)
pub const MAX_SKIP_DEFAULT: usize = 50;

/// Ratchet State: Core protocol state
/// 
/// This structure holds all the cryptographic state needed for the forward-secret ratchet.
/// All fields containing secrets are automatically zeroized when dropped.
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetState {
    /// Root key (mixed with KEM shared secrets)
    pub root_key: Vec<u8>,
    
    /// Send chain key (for deriving message keys)
    pub send_chain_key: Vec<u8>,
    
    /// Receive chain key (for deriving message keys)
    pub recv_chain_key: Vec<u8>,
    
    /// Send label (direction identifier)
    pub send_label: Vec<u8>,
    
    /// Receive label (direction identifier)
    pub recv_label: Vec<u8>,
    
    /// Send counter (current message index)
    pub send_count: u64,
    
    /// Receive counter (current message index)
    pub recv_count: u64,
    
    /// Previous send count (PN - for epoch tracking)
    pub previous_send_count: u64,
    
    /// Local ratchet private key
    pub local_ratchet_private: Vec<u8>,
    
    /// Local ratchet public key
    pub local_ratchet_public: Vec<u8>,
    
    /// Remote ratchet public key (optional)
    pub remote_ratchet_public: Option<Vec<u8>>,
    
    /// Combined digest (semantic context)
    pub combined_digest: Vec<u8>,
    
    /// Local digest (identity)
    pub local_digest: Vec<u8>,
    
    /// Remote digest (identity)
    pub remote_digest: Option<Vec<u8>>,
    
    /// Skipped message keys cache: (message_index -> (key, nonce))
    /// Keys are zeroized when removed from cache
    #[serde(skip)]
    pub skipped_message_keys: HashMap<u64, (Vec<u8>, Vec<u8>)>,
    
    /// Maximum number of skipped keys to cache
    pub max_skip: usize,
}

impl RatchetState {
    /// Create a new RatchetState with default max_skip
    pub fn new() -> Self {
        Self {
            root_key: vec![],
            send_chain_key: vec![],
            recv_chain_key: vec![],
            send_label: vec![],
            recv_label: vec![],
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            local_ratchet_private: vec![],
            local_ratchet_public: vec![],
            remote_ratchet_public: None,
            combined_digest: vec![],
            local_digest: vec![],
            remote_digest: None,
            skipped_message_keys: HashMap::new(),
            max_skip: MAX_SKIP_DEFAULT,
        }
    }
    
    /// Store a skipped message key in the cache
    /// Evicts oldest key if cache is full
    pub fn store_skipped_key(&mut self, idx: u64, key: Vec<u8>, nonce: Vec<u8>) {
        if self.skipped_message_keys.len() >= self.max_skip {
            // Evict oldest key (lowest index)
            if let Some(oldest) = self.skipped_message_keys.keys().min().copied() {
                if let Some((mut old_key, mut old_nonce)) = self.skipped_message_keys.remove(&oldest) {
                    old_key.zeroize();
                    old_nonce.zeroize();
                }
            }
        }
        self.skipped_message_keys.insert(idx, (key, nonce));
    }
    
    /// Recover a skipped message key from cache
    pub fn recover_skipped_key(&mut self, idx: u64) -> Option<(Vec<u8>, Vec<u8>)> {
        self.skipped_message_keys.remove(&idx)
    }
}

impl Default for RatchetState {
    fn default() -> Self {
        Self::new()
    }
}

/// Prekey Bundle: Handshake data structure
#[derive(Clone, Serialize, Deserialize)]
pub struct PrekeyBundle {
    /// Protocol version
    pub version: u8,
    
    /// KEM public key
    pub kem_public_key: Vec<u8>,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Optional metadata
    pub metadata: Option<Vec<u8>>,
    
    /// Optional signature (for authentication)
    pub signature: Option<Vec<u8>>,
}

