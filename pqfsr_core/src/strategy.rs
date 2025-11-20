/// STRATEGY MODULE: Adaptive Ratchet Strategy
/// ===========================================
/// This module implements the "Organic Strategy" for adaptive ratcheting,
/// dynamically deciding between KEM pulses and symmetric key flows.

use std::time::{SystemTime, UNIX_EPOCH};

/// Ratchet Mode: Security vs Performance trade-off
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RatchetMode {
    /// Maximum Security: KEM pulse at every message
    MaximumSecurity,
    
    /// Balanced Flow: Adaptive based on metrics
    BalancedFlow,
    
    /// Minimal Overhead: Minimize KEM operations
    MinimalOverhead,
}

/// Metrics: Track ratchet behavior
#[derive(Clone, Debug)]
pub struct Metrics {
    /// Messages since last KEM pulse
    pub msgs_since_last_kem: u64,
    
    /// Bytes sent since last KEM pulse
    pub bytes_sent_since_last_kem: u64,
    
    /// Timestamp of last KEM pulse
    pub time_last_kem: u64,
    
    /// Consecutive sends (burst detection)
    pub consecutive_sends: u64,
    
    /// Last round-trip time (RTT)
    pub last_rtt: f64,
    
    /// Battery low flag
    pub is_battery_low: bool,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            msgs_since_last_kem: 0,
            bytes_sent_since_last_kem: 0,
            time_last_kem: current_timestamp(),
            consecutive_sends: 0,
            last_rtt: 0.0,
            is_battery_low: false,
        }
    }
}

/// Organic Strategy: Adaptive ratchet decision engine
/// 
/// This strategy dynamically decides whether to perform a KEM pulse or
/// use symmetric key flow based on security and performance metrics.
pub struct OrganicStrategy {
    mode: RatchetMode,
    metrics: Metrics,
    
    // Decay thresholds
    max_entropy_decay_msgs: u64,
    max_entropy_decay_time: u64,  // seconds
    max_entropy_decay_bytes: u64,
}

impl OrganicStrategy {
    /// Create a new OrganicStrategy with the specified mode
    pub fn new(mode: RatchetMode) -> Self {
        Self {
            mode,
            metrics: Metrics::default(),
            max_entropy_decay_msgs: 50,
            max_entropy_decay_time: 300,  // 5 minutes
            max_entropy_decay_bytes: 1024 * 1024,  // 1 MB
        }
    }
    
    /// Determine if a quantum pulse (KEM ratchet) should be triggered
    /// 
    /// # Arguments
    /// * `msg_size` - Size of the message in bytes
    /// 
    /// # Returns
    /// `true` if KEM pulse should be triggered, `false` for symmetric flow
    pub fn should_trigger_quantum_pulse(&self, msg_size: usize) -> bool {
        // If we are bursting (consecutive sends > 0), strictly PREVENT pulse
        // to ensure we don't lose root sync if messages are dropped.
        // Only the FIRST message of a burst (ping-pong) can rotate.
        if self.metrics.consecutive_sends > 0 {
            return false;
        }
        
        if self.mode == RatchetMode::MaximumSecurity {
            return true;
        }
        
        let current_time = current_timestamp();
        
        // Check decay thresholds
        let decay_critical = 
            self.metrics.msgs_since_last_kem >= self.max_entropy_decay_msgs ||
            (current_time.saturating_sub(self.metrics.time_last_kem)) >= self.max_entropy_decay_time ||
            self.metrics.bytes_sent_since_last_kem >= self.max_entropy_decay_bytes;
        
        if decay_critical {
            return true;
        }
        
        // Large messages trigger pulse
        if msg_size > 1024 {
            return true;
        }
        
        false
    }
    
    /// Record that a KEM pulse was performed
    pub fn record_pulse(&mut self) {
        self.metrics.msgs_since_last_kem = 0;
        self.metrics.bytes_sent_since_last_kem = 0;
        self.metrics.time_last_kem = current_timestamp();
        self.metrics.consecutive_sends += 1;
    }
    
    /// Record that a symmetric flow was used
    pub fn record_flow(&mut self, msg_size: usize) {
        self.metrics.msgs_since_last_kem += 1;
        self.metrics.bytes_sent_since_last_kem += msg_size as u64;
        self.metrics.consecutive_sends += 1;
    }
    
    /// Record that a message was received (resets burst counter)
    pub fn record_reception(&mut self) {
        self.metrics.consecutive_sends = 0;
    }
    
    /// Adapt strategy based on stress conditions
    pub fn adapt_to_stress(&mut self, latency_spike: bool) {
        if latency_spike {
            // Switch to minimal overhead mode under stress
            self.mode = RatchetMode::MinimalOverhead;
        } else {
            self.mode = RatchetMode::BalancedFlow;
        }
    }
    
    /// Reset metrics
    pub fn reset_metrics(&mut self) {
        self.metrics = Metrics::default();
    }
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

