/// SESSION MODULE: High-Level Session Management
/// ==============================================
/// This module provides the RatchetSession API for handshake and messaging.

use crate::crypto::sha256;
use crate::ratchet::{ForwardRatchet, Packet};
use crate::state::RatchetState;
use crate::signatures::{generate_key_pair as generate_signature_keypair, sign_message, verify_signature};
use pqcrypto_traits::kem::*;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Handshake Request
#[derive(Clone, Debug)]
pub struct HandshakeRequest {
    pub version: Vec<u8>,
    pub min_version: u8,
    pub max_version: u8,
    pub handshake_id: Vec<u8>,
    pub kem_public: Vec<u8>,
    pub ratchet_public: Vec<u8>,
    pub semantic_digest: Vec<u8>,
    pub signature: Option<Vec<u8>>,  // Optional Dilithium signature
    pub signature_public_key: Option<Vec<u8>>,  // Optional Dilithium public key
}

/// Handshake Response
#[derive(Clone, Debug)]
pub struct HandshakeResponse {
    pub version: Vec<u8>,
    pub handshake_id: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub ratchet_public: Vec<u8>,
    pub semantic_digest: Vec<u8>,
    pub signature: Option<Vec<u8>>,  // Optional Dilithium signature
    pub signature_public_key: Option<Vec<u8>>,  // Optional Dilithium public key
}

/// Pending Handshake Data
struct PendingHandshake {
    kem_private: Vec<u8>,
    ratchet_private: Vec<u8>,
    ratchet_public: Vec<u8>,
    handshake_id: Vec<u8>,
}

/// Handshake ID Cache Entry with TTL
#[derive(Clone)]
struct HandshakeCacheEntry {
    /// Timestamp when this handshake_id was first seen (Unix epoch seconds)
    first_seen: u64,
    /// Number of times this handshake_id was seen (for attack detection)
    seen_count: u32,
    /// Last time this entry was accessed (for LRU eviction)
    last_accessed: u64,
}

impl HandshakeCacheEntry {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            first_seen: now,
            seen_count: 1,
            last_accessed: now,
        }
    }
    
    fn update_access(&mut self) {
        self.seen_count += 1;
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    fn is_expired(&self, ttl_seconds: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now - self.first_seen) > ttl_seconds
    }
}

/// Replay Protection Cache with TTL and automatic cleanup
/// 
/// Implements a robust handshake replay protection system with:
/// - TTL-based expiration (default: 24 hours)
/// - Automatic cleanup of expired entries
/// - Attack detection (multiple attempts with same ID)
/// - Memory-efficient eviction policy
/// - Timestamp validation from handshake_id
pub struct HandshakeReplayCache {
    /// Cache entries: handshake_id -> entry metadata
    entries: HashMap<Vec<u8>, HandshakeCacheEntry>,
    /// TTL in seconds (default: 24 hours = 86400 seconds)
    ttl_seconds: u64,
    /// Maximum cache size before eviction (default: 10000 entries)
    max_size: usize,
    /// Timestamp window for validation (reject handshakes too old or too far in future)
    /// Default: 1 hour (3600 seconds) - reject if timestamp is more than 1h old or 5min in future
    timestamp_window_seconds: u64,
    /// Maximum allowed clock skew in seconds (default: 5 minutes = 300 seconds)
    max_clock_skew_seconds: u64,
    /// Statistics
    total_checks: u64,
    replay_detections: u64,
    expired_entries_cleaned: u64,
}

impl HandshakeReplayCache {
    /// Create a new replay protection cache with default settings
    pub fn new() -> Self {
        Self::with_config(86400, 10000, 3600, 300)
    }
    
    /// Create a new cache with custom configuration
    /// 
    /// # Arguments
    /// * `ttl_seconds` - Time to live for cache entries (default: 86400 = 24 hours)
    /// * `max_size` - Maximum number of entries before eviction (default: 10000)
    /// * `timestamp_window_seconds` - Window for timestamp validation (default: 3600 = 1 hour)
    /// * `max_clock_skew_seconds` - Maximum allowed clock skew (default: 300 = 5 minutes)
    pub fn with_config(
        ttl_seconds: u64,
        max_size: usize,
        timestamp_window_seconds: u64,
        max_clock_skew_seconds: u64,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_seconds,
            max_size,
            timestamp_window_seconds,
            max_clock_skew_seconds,
            total_checks: 0,
            replay_detections: 0,
            expired_entries_cleaned: 0,
        }
    }
    
    /// Extract timestamp from handshake_id (last 4 bytes, big-endian u32)
    fn extract_timestamp(handshake_id: &[u8]) -> Option<u32> {
        if handshake_id.len() != 16 {
            return None;
        }
        let timestamp_bytes = &handshake_id[12..16];
        Some(u32::from_be_bytes([
            timestamp_bytes[0],
            timestamp_bytes[1],
            timestamp_bytes[2],
            timestamp_bytes[3],
        ]))
    }
    
    /// Validate handshake_id timestamp is within acceptable window
    fn validate_timestamp(&self, handshake_id: &[u8]) -> Result<(), String> {
        let timestamp = Self::extract_timestamp(handshake_id)
            .ok_or("Invalid handshake_id format (must be 16 bytes)")?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        
        // Check if timestamp is too old (beyond timestamp_window_seconds)
        if timestamp < now.saturating_sub(self.timestamp_window_seconds as u32) {
            return Err(format!(
                "Handshake timestamp too old: {} seconds ago (max: {})",
                now - timestamp,
                self.timestamp_window_seconds
            ));
        }
        
        // Check if timestamp is too far in future (clock skew)
        if timestamp > now + self.max_clock_skew_seconds as u32 {
            return Err(format!(
                "Handshake timestamp too far in future: {} seconds ahead (max skew: {})",
                timestamp - now,
                self.max_clock_skew_seconds
            ));
        }
        
        Ok(())
    }
    
    /// Check if handshake_id is a replay and add it to cache
    /// Returns Ok(()) if not a replay, Err(String) if replay detected
    pub fn check_and_record(&mut self, handshake_id: &[u8]) -> Result<(), String> {
        self.total_checks += 1;
        
        // Validate timestamp first
        self.validate_timestamp(handshake_id)?;
        
        // Clean expired entries periodically (every 100 checks or if cache is full)
        if self.total_checks % 100 == 0 || self.entries.len() >= self.max_size {
            self.cleanup_expired();
        }
        
        // Check if already in cache
        if let Some(entry) = self.entries.get_mut(handshake_id) {
            // Replay detected!
            entry.update_access();
            self.replay_detections += 1;
            
            // Log suspicious activity (multiple attempts)
            if entry.seen_count > 1 {
                return Err(format!(
                    "Replay attack detected: handshake_id seen {} times (first seen {} seconds ago)",
                    entry.seen_count,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() - entry.first_seen
                ));
            }
            
            return Err("Handshake ID already seen (replay attack detected)".to_string());
        }
        
        // Not a replay - add to cache
        // Evict oldest entry if cache is full
        if self.entries.len() >= self.max_size {
            self.evict_oldest();
        }
        
        self.entries.insert(handshake_id.to_vec(), HandshakeCacheEntry::new());
        Ok(())
    }
    
    /// Remove expired entries from cache
    fn cleanup_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let initial_size = self.entries.len();
        self.entries.retain(|_, entry| {
            let expired = entry.is_expired(self.ttl_seconds);
            if expired {
                self.expired_entries_cleaned += 1;
            }
            !expired
        });
        
        let cleaned = initial_size - self.entries.len();
        if cleaned > 0 {
            // Log cleanup (in production, use proper logging)
            // eprintln!("Cleaned {} expired handshake entries", cleaned);
        }
    }
    
    /// Evict oldest entry (LRU policy)
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> (u64, u64, u64, usize) {
        (
            self.total_checks,
            self.replay_detections,
            self.expired_entries_cleaned,
            self.entries.len(),
        )
    }
    
    /// Clear all entries (for testing or reset)
    pub fn clear(&mut self) {
        self.entries.clear();
        self.total_checks = 0;
        self.replay_detections = 0;
        self.expired_entries_cleaned = 0;
    }
}

impl Default for HandshakeReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Global shared replay protection cache (for server-side protection)
/// In production, this should be shared across all sessions on the server
lazy_static::lazy_static! {
    static ref GLOBAL_REPLAY_CACHE: Arc<Mutex<HandshakeReplayCache>> = 
        Arc::new(Mutex::new(HandshakeReplayCache::new()));
}

/// Check handshake_id against global shared cache (for server-side protection)
/// This allows replay detection across different sessions
pub fn check_global_replay_cache(handshake_id: &[u8]) -> Result<(), String> {
    let mut cache = GLOBAL_REPLAY_CACHE.lock().unwrap();
    cache.check_and_record(handshake_id)
}

/// Ratchet Session: High-level API for PQ-FSR protocol
pub struct RatchetSession {
    pub is_initiator: bool,
    pub semantic_hint: Vec<u8>,
    ratchet: ForwardRatchet,
    pub state: Option<RatchetState>,
    pub ready: bool,
    pending_handshake: Option<PendingHandshake>,
    remote_digest: Option<Vec<u8>>,
    handshake_id: Option<Vec<u8>>,
    local_digest: Vec<u8>,
    // Replay protection: robust cache with TTL, automatic cleanup, and attack detection
    replay_cache: HandshakeReplayCache,
}

impl RatchetSession {
    /// Get semantic hint
    pub fn semantic_hint(&self) -> &[u8] {
        &self.semantic_hint
    }
    
    /// Get is_initiator flag
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }
    
    /// Get replay protection cache statistics
    /// Returns: (total_checks, replay_detections, expired_entries_cleaned, current_cache_size)
    pub fn replay_cache_stats(&self) -> (u64, u64, u64, usize) {
        self.replay_cache.stats()
    }
    
    /// Configure replay protection cache (for advanced use cases)
    /// 
    /// # Arguments
    /// * `ttl_seconds` - Time to live for cache entries (default: 86400 = 24 hours)
    /// * `max_size` - Maximum number of entries before eviction (default: 10000)
    /// * `timestamp_window_seconds` - Window for timestamp validation (default: 3600 = 1 hour)
    /// * `max_clock_skew_seconds` - Maximum allowed clock skew (default: 300 = 5 minutes)
    pub fn configure_replay_protection(
        &mut self,
        ttl_seconds: u64,
        max_size: usize,
        timestamp_window_seconds: u64,
        max_clock_skew_seconds: u64,
    ) {
        self.replay_cache = HandshakeReplayCache::with_config(
            ttl_seconds,
            max_size,
            timestamp_window_seconds,
            max_clock_skew_seconds,
        );
    }
}

impl RatchetSession {
    /// Create a new session
    pub fn new(
        is_initiator: bool,
        semantic_hint: Vec<u8>,
        max_skip: usize,
    ) -> Self {
        let local_digest = sha256(&[b"PQ-FSR-sem".as_slice(), &semantic_hint].concat());
        
        Self {
            is_initiator,
            semantic_hint,
            ratchet: ForwardRatchet::new(max_skip),
            state: None,
            ready: false,
            pending_handshake: None,
            remote_digest: None,
            handshake_id: None,
            local_digest,
            replay_cache: HandshakeReplayCache::new(),
        }
    }
    
    /// Create an initiator session
    pub fn create_initiator(semantic_hint: Vec<u8>, max_skip: usize) -> Self {
        Self::new(true, semantic_hint, max_skip)
    }
    
    /// Create a responder session
    pub fn create_responder(semantic_hint: Vec<u8>, max_skip: usize) -> Self {
        Self::new(false, semantic_hint, max_skip)
    }
    
    /// Combine digests (deterministic ordering)
    pub fn combine_digest(&self, remote_digest: &[u8]) -> Vec<u8> {
        let mut ordered = vec![self.local_digest.clone(), remote_digest.to_vec()];
        ordered.sort();
        let combined = [&ordered[0][..], &ordered[1][..]].concat();
        sha256(&combined)
    }
    
    /// Negotiate version: select highest mutually supported version
    /// Returns the negotiated version number
    fn negotiate_version(&self, min_version: u8, max_version: u8) -> Result<u32, String> {
        // Current implementation supports version 1
        const SUPPORTED_MIN: u8 = 1;
        const SUPPORTED_MAX: u8 = 1;
        
        if min_version > max_version {
            return Err("Invalid version range: min_version > max_version".to_string());
        }
        
        // Find highest mutually supported version
        let negotiated = if max_version < SUPPORTED_MIN || min_version > SUPPORTED_MAX {
            return Err(format!(
                "No compatible version found. Requested: {}-{}, Supported: {}-{}",
                min_version, max_version, SUPPORTED_MIN, SUPPORTED_MAX
            ));
        } else {
            // Select the minimum of the two maximums
            std::cmp::min(max_version, SUPPORTED_MAX) as u32
        };
        
        Ok(negotiated)
    }
    
    /// Create a handshake request (initiator only)
    pub fn create_handshake_request(&mut self) -> Result<HandshakeRequest, String> {
        if !self.is_initiator {
            return Err("Only initiators can create handshake requests".to_string());
        }
        if self.ready {
            return Err("Handshake already completed".to_string());
        }
        if self.pending_handshake.is_some() {
            return Err("Handshake already pending".to_string());
        }
        
        let (kem_pub, kem_priv) = self.ratchet.generate_kem_key_pair();
        let (r_pub, r_priv) = self.ratchet.generate_kem_key_pair();
        
        // Generate handshake_id: 12 bytes random + 4 bytes timestamp (big-endian u32)
        // This ensures uniqueness and allows TTL-based expiration
        let mut handshake_id = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut handshake_id[0..12]);
        
        // Add timestamp (seconds since epoch) in last 4 bytes
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        handshake_id[12..16].copy_from_slice(&timestamp.to_be_bytes());
        
        self.pending_handshake = Some(PendingHandshake {
            kem_private: kem_priv,
            ratchet_private: r_priv,
            ratchet_public: r_pub.clone(),
            handshake_id: handshake_id.clone(),
        });
        
        // Generate signature key pair and sign handshake request
        let (sig_pk, sig_sk) = generate_signature_keypair();
        let message_to_sign = [
            &handshake_id[..],
            &kem_pub[..],
            &r_pub[..],
            &self.local_digest[..],
        ].concat();
        let signature = sign_message(&message_to_sign, &sig_sk)
            .map_err(|e| format!("Signature generation failed: {}", e))?;
        
        // Encode version as bytes (big-endian u32) - using max_version as current version
        let version_bytes = 1u32.to_be_bytes().to_vec();
        
        Ok(HandshakeRequest {
            version: version_bytes,
            min_version: 1,
            max_version: 1,
            handshake_id,
            kem_public: kem_pub,
            ratchet_public: r_pub,
            semantic_digest: self.local_digest.clone(),
            signature: Some(signature),
            signature_public_key: Some(sig_pk),
        })
    }
    
    /// Accept a handshake request (responder only)
    pub fn accept_handshake(&mut self, request: &HandshakeRequest) -> Result<HandshakeResponse, String> {
        if self.is_initiator {
            return Err("Initiator cannot accept handshake".to_string());
        }
        if self.ready {
            return Err("Handshake already completed".to_string());
        }
        
        // Robust replay protection: validate timestamp and check cache with TTL
        // Check both local cache (per-session) and global cache (server-side, shared)
        self.replay_cache.check_and_record(&request.handshake_id)
            .map_err(|e| format!("Replay protection (local): {}", e))?;
        
        // Also check global shared cache (for server-side protection across sessions)
        check_global_replay_cache(&request.handshake_id)
            .map_err(|e| format!("Replay protection (global): {}", e))?;
        
        // Version negotiation: select highest mutually supported version
        let negotiated_version = self.negotiate_version(request.min_version, request.max_version)?;
        
        // Verify signature if present
        if let (Some(sig), Some(sig_pk)) = (&request.signature, &request.signature_public_key) {
            let message_to_verify = [
                &request.handshake_id[..],
                &request.kem_public[..],
                &request.ratchet_public[..],
                &request.semantic_digest[..],
            ].concat();
            let valid = verify_signature(&message_to_verify, sig, sig_pk)
                .map_err(|e| format!("Signature verification failed: {}", e))?;
            if !valid {
                return Err("Invalid handshake request signature".to_string());
            }
        }
        
        let remote_digest = &request.semantic_digest;
        let combined = self.combine_digest(remote_digest);
        
        // Encapsulate KEM
        let remote_pk = pqcrypto_traits::kem::PublicKey::from_bytes(&request.kem_public)
            .map_err(|e| format!("Invalid KEM public key: {:?}", e))?;
        let (ss, ct) = pqcrypto_kyber::kyber768::encapsulate(&remote_pk);
        let shared_secret = ss.as_bytes().to_vec();
        
        let (l_pub, l_priv) = self.ratchet.generate_kem_key_pair();
        
        let mut state = self.ratchet.bootstrap(
            &shared_secret,
            &combined,
            &self.local_digest,
            Some(remote_digest),
            false,
            Some((l_pub.clone(), l_priv)),
        );
        state.remote_ratchet_public = Some(request.ratchet_public.clone());
        
        self.state = Some(state);
        self.remote_digest = Some(remote_digest.to_vec());
        self.handshake_id = Some(request.handshake_id.clone());
        // Note: handshake_id already recorded in replay_cache by check_and_record()
        self.ready = true;
        
        // Generate signature key pair and sign handshake response
        let (sig_pk, sig_sk) = generate_signature_keypair();
        let message_to_sign = [
            &request.handshake_id[..],
            &ct.as_bytes()[..],
            &l_pub[..],
            &self.local_digest[..],
        ].concat();
        let signature = sign_message(&message_to_sign, &sig_sk)
            .map_err(|e| format!("Signature generation failed: {}", e))?;
        
        // Encode negotiated version as bytes (big-endian u32)
        let version_bytes = negotiated_version.to_be_bytes().to_vec();
        
        Ok(HandshakeResponse {
            version: version_bytes,
            handshake_id: request.handshake_id.clone(),
            kem_ciphertext: ct.as_bytes().to_vec(),
            ratchet_public: l_pub,
            semantic_digest: self.local_digest.clone(),
            signature: Some(signature),
            signature_public_key: Some(sig_pk),
        })
    }
    
    /// Finalize handshake (initiator only)
    pub fn finalize_handshake(&mut self, response: &HandshakeResponse) -> Result<(), String> {
        if !self.is_initiator {
            return Err("Responder cannot finalize handshake".to_string());
        }
        if self.ready {
            return Err("Handshake already completed".to_string());
        }
        
        let pending = self.pending_handshake.take()
            .ok_or("No pending handshake")?;
        
        if pending.handshake_id != response.handshake_id {
            return Err("Handshake identifier mismatch".to_string());
        }
        
        // Verify negotiated version (should match our request)
        if response.version.len() != 4 {
            return Err("Invalid version format in response".to_string());
        }
        let negotiated_version = u32::from_be_bytes([
            response.version[0],
            response.version[1],
            response.version[2],
            response.version[3],
        ]);
        if negotiated_version != 1 {
            return Err(format!("Unsupported negotiated version: {}", negotiated_version));
        }
        
        // Verify signature if present
        if let (Some(sig), Some(sig_pk)) = (&response.signature, &response.signature_public_key) {
            let message_to_verify = [
                &response.handshake_id[..],
                &response.kem_ciphertext[..],
                &response.ratchet_public[..],
                &response.semantic_digest[..],
            ].concat();
            let valid = verify_signature(&message_to_verify, sig, sig_pk)
                .map_err(|e| format!("Signature verification failed: {}", e))?;
            if !valid {
                return Err("Invalid handshake response signature".to_string());
            }
        }
        
        // Decapsulate KEM
        let ct = pqcrypto_traits::kem::Ciphertext::from_bytes(&response.kem_ciphertext)
            .map_err(|e| format!("Invalid KEM ciphertext: {:?}", e))?;
        let sk = pqcrypto_traits::kem::SecretKey::from_bytes(&pending.kem_private)
            .map_err(|e| format!("Invalid KEM secret key: {:?}", e))?;
        
        let ss = pqcrypto_kyber::kyber768::decapsulate(&ct, &sk);
        let shared_secret = ss.as_bytes().to_vec();
        
        let remote_digest = &response.semantic_digest;
        let combined = self.combine_digest(remote_digest);
        
        let mut state = self.ratchet.bootstrap(
            &shared_secret,
            &combined,
            &self.local_digest,
            Some(remote_digest),
            true,
            Some((pending.ratchet_public, pending.ratchet_private)),
        );
        state.remote_ratchet_public = Some(response.ratchet_public.clone());
        
        self.state = Some(state);
        self.remote_digest = Some(remote_digest.to_vec());
        self.handshake_id = Some(response.handshake_id.clone());
        self.ready = true;
        
        Ok(())
    }
    
    /// Check if session is ready
    pub fn is_ready(&self) -> bool {
        self.ready && self.state.is_some()
    }
    
    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Packet, String> {
        if !self.is_ready() {
            return Err("Session not ready".to_string());
        }
        
        let state = self.state.as_mut().unwrap();
        self.ratchet.encrypt(state, plaintext, associated_data)
    }
    
    /// Decrypt a message
    pub fn decrypt(&mut self, packet: &Packet, associated_data: &[u8]) -> Result<Vec<u8>, String> {
        if !self.is_ready() {
            return Err("Session not ready".to_string());
        }
        
        let state = self.state.as_mut().unwrap();
        self.ratchet.decrypt(state, packet, associated_data)
    }
    
    /// Get state (for serialization)
    pub fn get_state(&self) -> Option<&RatchetState> {
        self.state.as_ref()
    }
    
    /// Get state mutably (for internal use)
    pub fn get_state_mut(&mut self) -> Option<&mut RatchetState> {
        self.state.as_mut()
    }
}

