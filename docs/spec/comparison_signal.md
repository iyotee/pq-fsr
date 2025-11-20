# PQ-FSR vs Signal Protocol: Detailed Comparison

This document provides a comprehensive comparison between PQ-FSR (Post-Quantum Forward-Secret Ratchet) and Signal Protocol (Double Ratchet), highlighting similarities, differences, and migration considerations.

---

## Executive Summary

| Aspect | Signal Protocol | PQ-FSR | Winner |
|--------|----------------|--------|--------|
| **Maturity** | ✅ Production (billions of users) | 🔴 Research/Experimental | Signal |
| **Post-Quantum** | ⚠️ SPQR in development | ✅ Native | PQ-FSR |
| **Performance** | ✅ Highly optimized | ⚠️ Reference implementation | Signal |
| **Standardization** | ✅ IETF-standardized | 🔴 Proposed | Signal |
| **Security Model** | ✅ Proven in practice | 🟡 Theoretically sound | Tie |
| **Simplicity** | ⚠️ Complex (X3DH + Double Ratchet) | ✅ Simpler handshake | PQ-FSR |

---

## Cryptographic Foundations

### Signal Protocol

**Asymmetric Ratchet**:
- Uses **Elliptic Curve Diffie-Hellman (ECDH)** with Curve25519
- One DH operation per message
- Fast: ~0.1ms per operation (native)

**Symmetric Ratchet**:
- HKDF-based chain key derivation
- AES-256 in CBC mode (older) or AES-GCM (newer)
- HMAC-SHA256 for authentication

**Handshake (X3DH)**:
- Multiple DH operations:
  1. Identity key exchange
  2. Signed prekey exchange
  3. One-time prekey exchange (optional)
- More complex but provides deniability

### PQ-FSR

**Asymmetric Ratchet**:
- Uses **Key Encapsulation Mechanism (KEM)** with Kyber
- One KEM encapsulation per message
- Slower: ~1-5ms per operation (depends on implementation)

**Symmetric Ratchet**:
- HKDF-based chain key derivation (same as Signal)
- **Reference**: XOR stream + HMAC-SHA256
- **Production**: Should use ChaCha20-Poly1305 or AES-GCM

**Handshake**:
- Single KEM encapsulation step
- Simpler but may lack some properties (deniability)

### Comparison

**Advantages of Signal**:
- ✅ Faster (ECDH is faster than KEM)
- ✅ Proven in production
- ✅ Better performance on mobile devices

**Advantages of PQ-FSR**:
- ✅ Post-quantum secure (future-proof)
- ✅ Simpler handshake
- ✅ Deterministic test vectors (easier interoperability)

---

## Security Properties

### Forward Secrecy

**Signal**: ✅ Each message uses a new DH shared secret  
**PQ-FSR**: ✅ Each message uses a new KEM shared secret

**Verdict**: **Tie** - Both provide forward secrecy

### Post-Compromise Security

**Signal**: ✅ One honest message recovers security  
**PQ-FSR**: ✅ One honest message recovers security

**Verdict**: **Tie** - Both provide post-compromise security

### Post-Quantum Resistance

**Signal**: ⚠️ Vulnerable to quantum attacks (SPQR in development)  
**PQ-FSR**: ✅ Resistant to quantum attacks (native)

**Verdict**: **PQ-FSR wins** - Native post-quantum security

### Deniability

**Signal**: ✅ Provides deniability through X3DH  
**PQ-FSR**: ⚠️ Deniability not explicitly addressed

**Verdict**: **Signal wins** - Better deniability properties

---

## Performance Comparison

### Handshake Latency

| Platform | Signal (X3DH) | PQ-FSR (KEM) | Notes |
|----------|---------------|--------------|-------|
| Desktop (x86_64) | ~10-20ms | ~50-100ms | KEM is slower |
| Mobile (ARM64) | ~20-40ms | ~100-200ms | KEM overhead more noticeable |
| Embedded (Raspberry Pi) | ~50-100ms | ~200-500ms | Limited CPU resources |

### Message Encryption

| Platform | Signal | PQ-FSR (Reference) | PQ-FSR (Optimized) |
|----------|--------|-------------------|-------------------|
| Desktop | ~0.5ms | ~2-5ms | ~1-2ms (estimated) |
| Mobile | ~1-2ms | ~5-10ms | ~2-5ms (estimated) |

**Note**: PQ-FSR performance will improve with native implementations (Rust/C).

### Bandwidth Overhead

**Signal**:
- Header: ~32 bytes
- Ciphertext: Plaintext size + padding
- Total: ~50-100 bytes overhead per message

**PQ-FSR**:
- Header: ~80-120 bytes (KEM ciphertext is larger)
- Ciphertext: Plaintext size + AEAD tag
- Total: ~150-200 bytes overhead per message

**Verdict**: **Signal wins** - Lower bandwidth overhead

---

## Implementation Complexity

### Signal Protocol

**Complexity**: High
- X3DH handshake: Multiple DH operations
- Double ratchet: Two ratchets (asymmetric + symmetric)
- State management: Complex multi-device synchronization
- Error handling: Many edge cases

**Code Size**: ~10,000+ lines (reference implementation)

### PQ-FSR

**Complexity**: Medium
- KEM handshake: Single encapsulation
- KEM ratchet: One ratchet (KEM + symmetric)
- State management: Simpler (single device focus)
- Error handling: Fewer edge cases

**Code Size**: ~500-1000 lines (reference implementation)

**Verdict**: **PQ-FSR wins** - Simpler implementation

---

## Standardization Status

### Signal Protocol

- **IETF RFC**: Not yet (but widely documented)
- **Adoption**: Signal, WhatsApp, Facebook Messenger, Skype
- **Users**: Billions worldwide
- **Review**: Extensive public review and cryptanalysis

### PQ-FSR

- **IETF Draft**: Proposed (not yet submitted)
- **Adoption**: None (research/experimental)
- **Users**: None (research only)
- **Review**: Limited (needs more cryptanalysis)

**Verdict**: **Signal wins** - Widely standardized and adopted

---

## Migration Path

### From Signal to PQ-FSR

**Challenges**:
1. Performance degradation (KEM is slower)
2. Bandwidth increase (larger ciphertexts)
3. Need for new implementations
4. User migration complexity

**Strategy**:
1. **Hybrid Approach**: Support both protocols during transition
2. **Gradual Migration**: Migrate users in phases
3. **Performance Optimization**: Native implementations (Rust/C)
4. **Backward Compatibility**: Maintain Signal support for legacy clients

### From PQ-FSR to Signal

**Not Recommended**: Signal is not post-quantum secure

**Alternative**: Wait for Signal's SPQR (Sparse Post-Quantum Ratchet)

---

## Use Cases

### Signal Protocol is Better For

1. **Production Messaging Apps**: Proven, optimized, standardized
2. **High-Performance Requirements**: Lower latency, lower bandwidth
3. **Multi-Device Synchronization**: Better support for multiple devices
4. **Group Messaging**: Better group protocol support

### PQ-FSR is Better For

1. **Future-Proof Applications**: Post-quantum security requirement
2. **Research and Development**: Easier to implement and test
3. **Constrained Devices**: Simpler protocol (if performance acceptable)
4. **Interoperability Testing**: Deterministic test vectors

---

## Recommendations

### For Production Today

**Use Signal Protocol** if:
- You need production-ready, proven security
- Performance is critical
- You need multi-device support
- You need group messaging

**Consider PQ-FSR** if:
- Post-quantum security is a hard requirement
- You're building for long-term (10+ years)
- You can accept performance trade-offs
- You're willing to contribute to research

### For Future Development

**Hybrid Approach**:
- Support both protocols
- Allow users to choose based on security requirements
- Migrate to PQ-FSR as it matures

**Signal SPQR**:
- Monitor Signal's SPQR development
- Consider migrating to SPQR when available
- SPQR may combine best of both worlds

---

## Conclusion

**Signal Protocol** is the clear winner for **production use today** due to:
- Proven security and performance
- Wide adoption and standardization
- Extensive review and testing

**PQ-FSR** is better for **future-proofing** and **research** due to:
- Native post-quantum security
- Simpler implementation
- Deterministic testing

**Best Strategy**: 
- Use Signal Protocol for production today
- Monitor and contribute to PQ-FSR development
- Plan migration path when PQ-FSR matures
- Consider Signal SPQR as alternative

---

## References

1. Signal Protocol Specification: https://signal.org/docs/
2. Double Ratchet: https://signal.org/docs/specifications/doubleratchet/
3. X3DH Key Agreement: https://signal.org/docs/specifications/x3dh/
4. PQ-FSR Specification: `forward_secret_ratchet.md`
5. Signal SPQR: https://signal.org/blog/spqr/ (when available)

