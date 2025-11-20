/// ERROR MODULE: Standardized Error Handling
/// ===========================================
/// This module provides a comprehensive error system for PQ-FSR with:
/// - Standardized error types
/// - Numeric error codes
/// - Recovery guidance
/// - Python bindings

#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;

/// PQ-FSR Error Types
/// 
/// This enum represents all possible errors in the PQ-FSR system.
/// Each variant includes an error code, message, and recovery guidance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PQFSRError {
    // Session Errors (1000-1999)
    /// Session not ready for operation
    SessionNotReady {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Invalid session state
    InvalidSessionState {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Only initiators can perform this operation
    InitiatorOnly {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Only responders can perform this operation
    ResponderOnly {
        code: u32,
        message: String,
        recovery: String,
    },
    
    // Handshake Errors (2000-2999)
    /// Handshake request creation failed
    HandshakeRequestFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Handshake acceptance failed
    HandshakeAcceptFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Handshake finalization failed
    HandshakeFinalizeFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Handshake replay detected
    HandshakeReplay {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Invalid handshake request format
    InvalidHandshakeRequest {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Invalid handshake response format
    InvalidHandshakeResponse {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Version negotiation failed
    VersionNegotiationFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    
    // Cryptographic Errors (3000-3999)
    /// Encryption failed
    EncryptionFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Decryption failed
    DecryptionFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Semantic tag mismatch
    SemanticTagMismatch {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Nonce mismatch
    NonceMismatch {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Message already processed
    MessageAlreadyProcessed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Invalid key format
    InvalidKeyFormat {
        code: u32,
        message: String,
        recovery: String,
    },
    /// KEM operation failed
    KEMOperationFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    
    // Serialization Errors (4000-4999)
    /// Serialization failed
    SerializationFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Deserialization failed
    DeserializationFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Invalid packet format
    InvalidPacketFormat {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Packet too short
    PacketTooShort {
        code: u32,
        message: String,
        recovery: String,
    },
    /// State encryption failed
    StateEncryptionFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// State decryption failed
    StateDecryptionFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Invalid password for state decryption
    InvalidPassword {
        code: u32,
        message: String,
        recovery: String,
    },
    
    // Signature Errors (5000-5999)
    /// Signature generation failed
    SignatureGenerationFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Signature verification failed
    SignatureVerificationFailed {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Invalid signature format
    InvalidSignatureFormat {
        code: u32,
        message: String,
        recovery: String,
    },
    
    // Generic Errors (9000-9999)
    /// Invalid input parameter
    InvalidInput {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Internal error
    InternalError {
        code: u32,
        message: String,
        recovery: String,
    },
    /// Operation not supported
    NotSupported {
        code: u32,
        message: String,
        recovery: String,
    },
}

impl PQFSRError {
    /// Get error code
    pub fn code(&self) -> u32 {
        match self {
            PQFSRError::SessionNotReady { code, .. } => *code,
            PQFSRError::InvalidSessionState { code, .. } => *code,
            PQFSRError::InitiatorOnly { code, .. } => *code,
            PQFSRError::ResponderOnly { code, .. } => *code,
            PQFSRError::HandshakeRequestFailed { code, .. } => *code,
            PQFSRError::HandshakeAcceptFailed { code, .. } => *code,
            PQFSRError::HandshakeFinalizeFailed { code, .. } => *code,
            PQFSRError::HandshakeReplay { code, .. } => *code,
            PQFSRError::InvalidHandshakeRequest { code, .. } => *code,
            PQFSRError::InvalidHandshakeResponse { code, .. } => *code,
            PQFSRError::VersionNegotiationFailed { code, .. } => *code,
            PQFSRError::SignatureVerificationFailed { code, .. } => *code,
            PQFSRError::EncryptionFailed { code, .. } => *code,
            PQFSRError::DecryptionFailed { code, .. } => *code,
            PQFSRError::SemanticTagMismatch { code, .. } => *code,
            PQFSRError::NonceMismatch { code, .. } => *code,
            PQFSRError::MessageAlreadyProcessed { code, .. } => *code,
            PQFSRError::InvalidKeyFormat { code, .. } => *code,
            PQFSRError::KEMOperationFailed { code, .. } => *code,
            PQFSRError::SerializationFailed { code, .. } => *code,
            PQFSRError::DeserializationFailed { code, .. } => *code,
            PQFSRError::InvalidPacketFormat { code, .. } => *code,
            PQFSRError::PacketTooShort { code, .. } => *code,
            PQFSRError::StateEncryptionFailed { code, .. } => *code,
            PQFSRError::StateDecryptionFailed { code, .. } => *code,
            PQFSRError::InvalidPassword { code, .. } => *code,
            PQFSRError::SignatureGenerationFailed { code, .. } => *code,
            PQFSRError::InvalidSignatureFormat { code, .. } => *code,
            PQFSRError::InvalidInput { code, .. } => *code,
            PQFSRError::InternalError { code, .. } => *code,
            PQFSRError::NotSupported { code, .. } => *code,
        }
    }
    
    /// Get error message
    pub fn message(&self) -> &str {
        match self {
            PQFSRError::SessionNotReady { message, .. } => message,
            PQFSRError::InvalidSessionState { message, .. } => message,
            PQFSRError::InitiatorOnly { message, .. } => message,
            PQFSRError::ResponderOnly { message, .. } => message,
            PQFSRError::HandshakeRequestFailed { message, .. } => message,
            PQFSRError::HandshakeAcceptFailed { message, .. } => message,
            PQFSRError::HandshakeFinalizeFailed { message, .. } => message,
            PQFSRError::HandshakeReplay { message, .. } => message,
            PQFSRError::InvalidHandshakeRequest { message, .. } => message,
            PQFSRError::InvalidHandshakeResponse { message, .. } => message,
            PQFSRError::VersionNegotiationFailed { message, .. } => message,
            PQFSRError::SignatureVerificationFailed { message, .. } => message,
            PQFSRError::EncryptionFailed { message, .. } => message,
            PQFSRError::DecryptionFailed { message, .. } => message,
            PQFSRError::SemanticTagMismatch { message, .. } => message,
            PQFSRError::NonceMismatch { message, .. } => message,
            PQFSRError::MessageAlreadyProcessed { message, .. } => message,
            PQFSRError::InvalidKeyFormat { message, .. } => message,
            PQFSRError::KEMOperationFailed { message, .. } => message,
            PQFSRError::SerializationFailed { message, .. } => message,
            PQFSRError::DeserializationFailed { message, .. } => message,
            PQFSRError::InvalidPacketFormat { message, .. } => message,
            PQFSRError::PacketTooShort { message, .. } => message,
            PQFSRError::StateEncryptionFailed { message, .. } => message,
            PQFSRError::StateDecryptionFailed { message, .. } => message,
            PQFSRError::InvalidPassword { message, .. } => message,
            PQFSRError::SignatureGenerationFailed { message, .. } => message,
            PQFSRError::InvalidSignatureFormat { message, .. } => message,
            PQFSRError::InvalidInput { message, .. } => message,
            PQFSRError::InternalError { message, .. } => message,
            PQFSRError::NotSupported { message, .. } => message,
        }
    }
    
    /// Get recovery guidance
    pub fn recovery(&self) -> &str {
        match self {
            PQFSRError::SessionNotReady { recovery, .. } => recovery,
            PQFSRError::InvalidSessionState { recovery, .. } => recovery,
            PQFSRError::InitiatorOnly { recovery, .. } => recovery,
            PQFSRError::ResponderOnly { recovery, .. } => recovery,
            PQFSRError::HandshakeRequestFailed { recovery, .. } => recovery,
            PQFSRError::HandshakeAcceptFailed { recovery, .. } => recovery,
            PQFSRError::HandshakeFinalizeFailed { recovery, .. } => recovery,
            PQFSRError::HandshakeReplay { recovery, .. } => recovery,
            PQFSRError::InvalidHandshakeRequest { recovery, .. } => recovery,
            PQFSRError::InvalidHandshakeResponse { recovery, .. } => recovery,
            PQFSRError::VersionNegotiationFailed { recovery, .. } => recovery,
            PQFSRError::SignatureVerificationFailed { recovery, .. } => recovery,
            PQFSRError::EncryptionFailed { recovery, .. } => recovery,
            PQFSRError::DecryptionFailed { recovery, .. } => recovery,
            PQFSRError::SemanticTagMismatch { recovery, .. } => recovery,
            PQFSRError::NonceMismatch { recovery, .. } => recovery,
            PQFSRError::MessageAlreadyProcessed { recovery, .. } => recovery,
            PQFSRError::InvalidKeyFormat { recovery, .. } => recovery,
            PQFSRError::KEMOperationFailed { recovery, .. } => recovery,
            PQFSRError::SerializationFailed { recovery, .. } => recovery,
            PQFSRError::DeserializationFailed { recovery, .. } => recovery,
            PQFSRError::InvalidPacketFormat { recovery, .. } => recovery,
            PQFSRError::PacketTooShort { recovery, .. } => recovery,
            PQFSRError::StateEncryptionFailed { recovery, .. } => recovery,
            PQFSRError::StateDecryptionFailed { recovery, .. } => recovery,
            PQFSRError::InvalidPassword { recovery, .. } => recovery,
            PQFSRError::SignatureGenerationFailed { recovery, .. } => recovery,
            PQFSRError::InvalidSignatureFormat { recovery, .. } => recovery,
            PQFSRError::InvalidInput { recovery, .. } => recovery,
            PQFSRError::InternalError { recovery, .. } => recovery,
            PQFSRError::NotSupported { recovery, .. } => recovery,
        }
    }
    
    /// Create session not ready error
    pub fn session_not_ready() -> Self {
        Self::SessionNotReady {
            code: 1001,
            message: "Session is not ready for this operation".to_string(),
            recovery: "Complete the handshake process before attempting this operation".to_string(),
        }
    }
    
    /// Create initiator-only error
    pub fn initiator_only(operation: &str) -> Self {
        Self::InitiatorOnly {
            code: 1002,
            message: format!("Only initiators can {}", operation),
            recovery: "Use an initiator session for this operation".to_string(),
        }
    }
    
    /// Create responder-only error
    pub fn responder_only(operation: &str) -> Self {
        Self::ResponderOnly {
            code: 1003,
            message: format!("Only responders can {}", operation),
            recovery: "Use a responder session for this operation".to_string(),
        }
    }
    
    /// Create handshake replay error
    pub fn handshake_replay(details: &str) -> Self {
        Self::HandshakeReplay {
            code: 2001,
            message: format!("Handshake replay detected: {}", details),
            recovery: "This handshake has already been processed. Start a new handshake if needed".to_string(),
        }
    }
    
    /// Create semantic tag mismatch error
    pub fn semantic_tag_mismatch() -> Self {
        Self::SemanticTagMismatch {
            code: 3001,
            message: "Semantic tag mismatch - packet may be corrupted or from different session".to_string(),
            recovery: "Verify that the packet belongs to this session and was not corrupted".to_string(),
        }
    }
    
    /// Create nonce mismatch error
    pub fn nonce_mismatch() -> Self {
        Self::NonceMismatch {
            code: 3002,
            message: "Nonce mismatch - packet may be corrupted or replayed".to_string(),
            recovery: "Verify packet integrity and ensure it hasn't been replayed".to_string(),
        }
    }
    
    /// Create message already processed error
    pub fn message_already_processed(index: u64) -> Self {
        Self::MessageAlreadyProcessed {
            code: 3003,
            message: format!("Message with index {} has already been processed", index),
            recovery: "This message was already decrypted. Skip it or check for duplicate transmission".to_string(),
        }
    }
    
    /// Create decryption failed error
    pub fn decryption_failed(reason: &str) -> Self {
        Self::DecryptionFailed {
            code: 3004,
            message: format!("Decryption failed: {}", reason),
            recovery: "Verify the packet is valid, belongs to this session, and hasn't been corrupted".to_string(),
        }
    }
    
    /// Create invalid packet format error
    pub fn invalid_packet_format(details: &str) -> Self {
        Self::InvalidPacketFormat {
            code: 4001,
            message: format!("Invalid packet format: {}", details),
            recovery: "Verify packet structure and ensure it was packed correctly".to_string(),
        }
    }
    
    /// Create packet too short error
    pub fn packet_too_short(expected: usize, got: usize) -> Self {
        Self::PacketTooShort {
            code: 4002,
            message: format!("Packet too short: expected at least {} bytes, got {}", expected, got),
            recovery: "Verify packet completeness and ensure no truncation occurred".to_string(),
        }
    }
    
    /// Create invalid password error
    pub fn invalid_password() -> Self {
        Self::InvalidPassword {
            code: 4003,
            message: "Invalid password for state decryption".to_string(),
            recovery: "Verify the password is correct and matches the one used for encryption".to_string(),
        }
    }
    
    /// Create version negotiation failed error
    pub fn version_negotiation_failed(requested: &str, supported: &str) -> Self {
        Self::VersionNegotiationFailed {
            code: 2002,
            message: format!("Version negotiation failed: requested {}, supported {}", requested, supported),
            recovery: "Update to a compatible version or use a version within the supported range".to_string(),
        }
    }
    
    /// Create signature verification failed error
    pub fn signature_verification_failed(reason: &str) -> Self {
        Self::SignatureVerificationFailed {
            code: 2003,
            message: format!("Signature verification failed: {}", reason),
            recovery: "Verify the signature public key is correct and the message hasn't been tampered with".to_string(),
        }
    }
    
    /// Create generic invalid input error
    pub fn invalid_input(field: &str, reason: &str) -> Self {
        Self::InvalidInput {
            code: 9001,
            message: format!("Invalid input for {}: {}", field, reason),
            recovery: format!("Provide a valid value for {}", field),
        }
    }
    
    /// Create internal error
    pub fn internal_error(details: &str) -> Self {
        Self::InternalError {
            code: 9999,
            message: format!("Internal error: {}", details),
            recovery: "This is an unexpected error. Please report it with full details".to_string(),
        }
    }
}

impl std::fmt::Display for PQFSRError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} - Recovery: {}", self.code(), self.message(), self.recovery())
    }
}

impl std::error::Error for PQFSRError {}

/// Result type alias for PQ-FSR operations
pub type PQFSRResult<T> = Result<T, PQFSRError>;

/// Convert from String error to PQFSRError
impl From<String> for PQFSRError {
    fn from(s: String) -> Self {
        // Try to parse common error patterns
        if s.contains("Session not ready") {
            Self::session_not_ready()
        } else if s.contains("Only initiators") {
            Self::initiator_only("perform this operation")
        } else if s.contains("Only responders") {
            Self::responder_only("perform this operation")
        } else if s.contains("Semantic tag mismatch") {
            Self::semantic_tag_mismatch()
        } else if s.contains("Nonce mismatch") {
            Self::nonce_mismatch()
        } else if s.contains("Message already processed") {
            Self::message_already_processed(0)
        } else if s.contains("Handshake replay") {
            Self::handshake_replay(&s)
        } else if s.contains("decrypt") || s.contains("Decryption") {
            Self::decryption_failed(&s)
        } else if s.contains("Invalid packet") {
            Self::invalid_packet_format(&s)
        } else {
            Self::internal_error(&s)
        }
    }
}

// Python bindings
#[cfg(feature = "python")]
#[pyclass]
#[derive(Clone)]
pub struct PQFSRErrorPy {
    inner: PQFSRError,
}

#[cfg(feature = "python")]
#[pymethods]
impl PQFSRErrorPy {
    #[new]
    fn new(code: u32, message: String, recovery: String) -> Self {
        // Create appropriate error variant based on code range
        let inner = match code {
            1001 => PQFSRError::SessionNotReady { code, message, recovery },
            1002 => PQFSRError::InitiatorOnly { code, message, recovery },
            1003 => PQFSRError::ResponderOnly { code, message, recovery },
            2001 => PQFSRError::HandshakeReplay { code, message, recovery },
            2002 => PQFSRError::VersionNegotiationFailed { code, message, recovery },
            2003 => PQFSRError::SignatureVerificationFailed { code, message, recovery },
            3001 => PQFSRError::SemanticTagMismatch { code, message, recovery },
            3002 => PQFSRError::NonceMismatch { code, message, recovery },
            3003 => PQFSRError::MessageAlreadyProcessed { code, message, recovery },
            3004 => PQFSRError::DecryptionFailed { code, message, recovery },
            4001 => PQFSRError::InvalidPacketFormat { code, message, recovery },
            4002 => PQFSRError::PacketTooShort { code, message, recovery },
            4003 => PQFSRError::InvalidPassword { code, message, recovery },
            _ => PQFSRError::InternalError { code, message, recovery },
        };
        Self { inner }
    }
    
    fn code(&self) -> u32 {
        self.inner.code()
    }
    
    fn message(&self) -> String {
        self.inner.message().to_string()
    }
    
    fn recovery(&self) -> String {
        self.inner.recovery().to_string()
    }
    
    fn __str__(&self) -> String {
        format!("{}", self.inner)
    }
    
    fn __repr__(&self) -> String {
        format!("PQFSRError(code={}, message={:?}, recovery={:?})", 
                self.inner.code(), self.inner.message(), self.inner.recovery())
    }
}

#[cfg(feature = "python")]
impl From<PQFSRError> for PyErr {
    fn from(err: PQFSRError) -> Self {
        PyValueError::new_err(format!("[{}] {} - Recovery: {}", 
                                     err.code(), err.message(), err.recovery()))
    }
}

