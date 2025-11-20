/// STRATEGY TESTS: Test OrganicStrategy adaptive behavior
/// ======================================================

use pqfsr_core::{OrganicStrategy, RatchetMode};

#[test]
fn test_strategy_creation() {
    let strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    // Strategy should be created successfully
    assert!(true); // Just verify it doesn't panic
}

#[test]
fn test_maximum_security_mode() {
    let strategy = OrganicStrategy::new(RatchetMode::MaximumSecurity);
    
    // Maximum security should always trigger pulse
    assert!(strategy.should_trigger_quantum_pulse(1));
    assert!(strategy.should_trigger_quantum_pulse(100));
    assert!(strategy.should_trigger_quantum_pulse(10));
}

#[test]
fn test_balanced_flow_mode_small_message() {
    let strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Small messages should not trigger pulse initially
    assert!(!strategy.should_trigger_quantum_pulse(100));
}

#[test]
fn test_balanced_flow_mode_large_message() {
    let strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Large messages (>1024 bytes) should trigger pulse
    assert!(strategy.should_trigger_quantum_pulse(2000));
    assert!(strategy.should_trigger_quantum_pulse(1025));
}

#[test]
fn test_minimal_overhead_mode() {
    let strategy = OrganicStrategy::new(RatchetMode::MinimalOverhead);
    
    // Minimal overhead should avoid pulses for small messages
    assert!(!strategy.should_trigger_quantum_pulse(100));
    assert!(!strategy.should_trigger_quantum_pulse(500));
    
    // But still trigger for very large messages
    assert!(strategy.should_trigger_quantum_pulse(2000));
}

#[test]
fn test_record_pulse() {
    let mut strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Record some flow first
    strategy.record_flow(100);
    strategy.record_flow(200);
    
    // Record pulse should reset counters
    strategy.record_pulse();
    
    // After pulse, small message should not trigger (counters reset)
    assert!(!strategy.should_trigger_quantum_pulse(100));
}

#[test]
fn test_record_flow() {
    let mut strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Record multiple flows
    strategy.record_flow(100);
    strategy.record_flow(200);
    strategy.record_flow(300);
    
    // After 3 messages, should still not trigger (threshold is 50)
    assert!(!strategy.should_trigger_quantum_pulse(100));
}

#[test]
fn test_record_reception() {
    let mut strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Record some sends (creates burst)
    strategy.record_flow(100);
    strategy.record_flow(200);
    
    // During burst, pulse should be prevented
    assert!(!strategy.should_trigger_quantum_pulse(2000)); // Even large message
    
    // Record reception resets burst counter
    strategy.record_reception();
    
    // Now large message should trigger pulse
    assert!(strategy.should_trigger_quantum_pulse(2000));
}

#[test]
fn test_entropy_decay_message_threshold() {
    let mut strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Send 50 messages (threshold is >= 50)
    for _ in 0..50 {
        strategy.record_flow(10);
    }
    
    // After 50 messages, msgs_since_last_kem should be 50, which triggers pulse
    // But we need to check BEFORE recording the 50th flow, or check that it's >= threshold
    // Actually, after 50 record_flow calls, msgs_since_last_kem is 50, which is >= 50
    // So it should trigger. But consecutive_sends is also 50, which prevents pulse!
    // We need to reset consecutive_sends first
    strategy.record_reception();
    
    // Now should trigger pulse due to message count threshold
    assert!(strategy.should_trigger_quantum_pulse(100));
}

#[test]
fn test_entropy_decay_bytes_threshold() {
    let mut strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Send 1MB+ of data (threshold is 1MB = 1048576 bytes)
    let msg_size = 100 * 1024; // 100KB per message
    // 11 messages = 11 * 100KB = 1100KB > 1MB
    for _ in 0..11 {
        strategy.record_flow(msg_size);
    }
    
    // Reset consecutive_sends to allow pulse
    strategy.record_reception();
    
    // Should trigger pulse due to bytes threshold
    assert!(strategy.should_trigger_quantum_pulse(100));
}

#[test]
fn test_burst_protection() {
    let mut strategy = OrganicStrategy::new(RatchetMode::MaximumSecurity);
    
    // Record first flow (creates burst)
    strategy.record_flow(100);
    
    // Even in MaximumSecurity mode, burst should prevent pulse
    assert!(!strategy.should_trigger_quantum_pulse(100));
    
    // Record reception to reset burst
    strategy.record_reception();
    
    // Now should trigger pulse again
    assert!(strategy.should_trigger_quantum_pulse(100));
}

#[test]
fn test_adapt_to_stress() {
    let mut strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Initially, small message should not trigger
    assert!(!strategy.should_trigger_quantum_pulse(100));
    
    // Adapt to stress (latency spike)
    strategy.adapt_to_stress(true);
    
    // After stress adaptation, should still avoid pulses for small messages
    assert!(!strategy.should_trigger_quantum_pulse(100));
    
    // Remove stress
    strategy.adapt_to_stress(false);
    
    // Should return to balanced flow
    assert!(!strategy.should_trigger_quantum_pulse(100));
}

#[test]
fn test_reset_metrics() {
    let mut strategy = OrganicStrategy::new(RatchetMode::BalancedFlow);
    
    // Record some flows
    strategy.record_flow(100);
    strategy.record_flow(200);
    strategy.record_flow(300);
    
    // Reset metrics
    strategy.reset_metrics();
    
    // After reset, should behave like fresh strategy
    assert!(!strategy.should_trigger_quantum_pulse(100));
}

#[test]
fn test_ratchet_mode_enum() {
    // Test that RatchetMode enum works correctly
    let mode1 = RatchetMode::MaximumSecurity;
    let mode2 = RatchetMode::BalancedFlow;
    let mode3 = RatchetMode::MinimalOverhead;
    
    assert_ne!(mode1, mode2);
    assert_ne!(mode2, mode3);
    assert_ne!(mode1, mode3);
    
    // Test clone
    let mode1_clone = mode1;
    assert_eq!(mode1, mode1_clone);
}

