/// PQ-FSR CORE: Rust Implementation with Python Bindings
/// =======================================================
/// This is the main entry point for the PQ-FSR Rust implementation.
/// It provides Python bindings via PyO3 for all core functionality.

#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::{PyDict, PyBytes};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::*;
#[cfg(feature = "python")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "python")]
use std::collections::VecDeque;

// Module declarations (public for tests)
pub mod crypto;
pub mod state;
pub mod strategy;
pub mod ratchet;
pub mod serialization;
pub mod session;
pub mod signatures;
pub mod error;

// Re-export for Python bindings
pub use crypto::*;
pub use state::*;
pub use strategy::*;
pub use ratchet::*;
pub use serialization::*;
pub use session::*;
pub use signatures::*;
pub use error::*;

/// THE REACTOR: High-Performance Rust Core
/// This module implements the heavy lifting:
/// 1. Speculative Key Generation (generating keys before they are needed)
/// 2. Parallelized KEM operations
/// 3. Constant-time comparison primitives

#[cfg(feature = "python")]
struct KeyPool {
    keys: VecDeque<(Vec<u8>, Vec<u8>)>, // (pk, sk)
}

#[cfg(feature = "python")]
static KEY_POOL_SIZE: usize = 100;

#[cfg(feature = "python")]
#[pyclass]
pub struct NuclearReactor {
    pool: Arc<Mutex<KeyPool>>,
}

#[cfg(feature = "python")]
#[pymethods]
impl NuclearReactor {
    #[new]
    fn new() -> Self {
        let pool = Arc::new(Mutex::new(KeyPool {
            keys: VecDeque::with_capacity(KEY_POOL_SIZE),
        }));
        
        // Spawn a background thread to fill the pool
        let pool_clone = pool.clone();
        std::thread::spawn(move || {
            loop {
                let p = pool_clone.lock().unwrap();
                if p.keys.len() < KEY_POOL_SIZE {
                    // Drop lock while generating
                    drop(p);
                    let (pk, sk) = kyber768::keypair();
                    let mut p = pool_clone.lock().unwrap();
                    p.keys.push_back((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()));
                } else {
                    drop(p);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        });
        Self { pool }
    }

    fn get_keypair(&self) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let mut pool = self.pool.lock().unwrap();
        if let Some((pk, sk)) = pool.keys.pop_front() {
            Ok((pk, sk))
        } else {
            // Fallback if pool empty (should be rare)
            let (pk, sk) = kyber768::keypair();
            Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
        }
    }

    fn encapsulate(&self, remote_pk_bytes: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let pk = PublicKey::from_bytes(remote_pk_bytes)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid public key: {:?}", e)))?;
        let (ss, ct) = kyber768::encapsulate(&pk);
        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    fn decapsulate(&self, ct_bytes: &[u8], sk_bytes: &[u8]) -> PyResult<Vec<u8>> {
        let ct = Ciphertext::from_bytes(ct_bytes)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid ciphertext: {:?}", e)))?;
        let sk = SecretKey::from_bytes(sk_bytes)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid secret key: {:?}", e)))?;
        let ss = kyber768::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }
}

// Python bindings for RatchetMode
#[cfg(feature = "python")]
#[pyclass]
#[derive(Clone, Copy)]
pub struct RatchetModePy {
    mode: strategy::RatchetMode,
}

#[cfg(feature = "python")]
#[pymethods]
impl RatchetModePy {
    #[new]
    fn new(mode_str: &str) -> PyResult<Self> {
        let mode = match mode_str {
            "MAXIMUM_SECURITY" => strategy::RatchetMode::MaximumSecurity,
            "BALANCED_FLOW" => strategy::RatchetMode::BalancedFlow,
            "MINIMAL_OVERHEAD" => strategy::RatchetMode::MinimalOverhead,
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid mode. Use: MAXIMUM_SECURITY, BALANCED_FLOW, or MINIMAL_OVERHEAD"
            )),
        };
        Ok(Self { mode })
    }
    
    #[staticmethod]
    fn maximum_security() -> Self {
        Self { mode: strategy::RatchetMode::MaximumSecurity }
    }
    
    #[staticmethod]
    fn balanced_flow() -> Self {
        Self { mode: strategy::RatchetMode::BalancedFlow }
    }
    
    #[staticmethod]
    fn minimal_overhead() -> Self {
        Self { mode: strategy::RatchetMode::MinimalOverhead }
    }
}

// Python bindings for Packet
#[cfg(feature = "python")]
#[pyclass]
#[derive(Clone)]
pub struct PacketPy {
    inner: ratchet::Packet,
}

#[cfg(feature = "python")]
#[pymethods]
impl PacketPy {
    #[new]
    fn new(
        version: u8,
        count: u64,
        pn: u64,
        ratchet_pub: Vec<u8>,
        kem_ciphertext: Vec<u8>,
        semantic_tag: Vec<u8>,
        ciphertext: Vec<u8>,
        nonce: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner: ratchet::Packet {
                version,
                count,
                pn,
                ratchet_pub,
                kem_ciphertext,
                semantic_tag,
                ciphertext,
                nonce,
            },
        }
    }
    
    fn to_dict(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        let header = PyDict::new(py);
        header.set_item("version", self.inner.version)?;
        header.set_item("count", self.inner.count)?;
        header.set_item("pn", self.inner.pn)?;
        header.set_item("ratchet_pub", self.inner.ratchet_pub.clone())?;
        header.set_item("kem_ciphertext", self.inner.kem_ciphertext.clone())?;
        header.set_item("semantic_tag", self.inner.semantic_tag.clone())?;
        dict.set_item("header", header)?;
        dict.set_item("ciphertext", self.inner.ciphertext.clone())?;
        if let Some(ref nonce) = self.inner.nonce {
            dict.set_item("nonce", nonce.clone())?;
        }
        Ok(dict.into())
    }
    
    /// Get dict without needing Python parameter (uses GIL internally)
    fn to_dict_auto(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| self.to_dict(py))
    }
    
    fn pack(&self) -> Vec<u8> {
        use crate::serialization::pack_packet;
        pack_packet(&self.inner)
    }
    
    #[staticmethod]
    fn unpack(data: Vec<u8>) -> PyResult<Self> {
        use crate::serialization::unpack_packet;
        let packet = unpack_packet(&data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        Ok(Self { inner: packet })
    }
    
    #[staticmethod]
    fn from_dict(dict: &PyAny) -> PyResult<Self> {
        let dict = dict.downcast::<PyDict>()?;
        let header = dict.get_item("header")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'header'"))?
            .downcast::<PyDict>()?;
        
        let version = header.get_item("version")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'version'"))?
            .extract::<u8>()?;
        let count = header.get_item("count")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'count'"))?
            .extract::<u64>()?;
        let pn = header.get_item("pn")
            .map(|v| v.extract::<u64>())
            .transpose()?
            .unwrap_or(0);
        let ratchet_pub = header.get_item("ratchet_pub")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'ratchet_pub'"))?
            .extract::<Vec<u8>>()?;
        let kem_ciphertext = header.get_item("kem_ciphertext")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'kem_ciphertext'"))?
            .extract::<Vec<u8>>()?;
        let semantic_tag = header.get_item("semantic_tag")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'semantic_tag'"))?
            .extract::<Vec<u8>>()?;
        
        let ciphertext = dict.get_item("ciphertext")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'ciphertext'"))?
            .extract::<Vec<u8>>()?;
        let nonce = dict.get_item("nonce")
            .map(|v| v.extract::<Vec<u8>>())
            .transpose()?;
        
        Ok(Self {
            inner: ratchet::Packet {
                version,
                count,
                pn,
                ratchet_pub,
                kem_ciphertext,
                semantic_tag,
                ciphertext,
                nonce,
            },
        })
    }
}

// Python bindings for HandshakeRequest
#[cfg(feature = "python")]
#[pyclass]
#[derive(Clone)]
pub struct HandshakeRequestPy {
    pub inner: session::HandshakeRequest,
}

#[cfg(feature = "python")]
#[pymethods]
impl HandshakeRequestPy {
    fn to_dict(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        dict.set_item("version", self.inner.version.clone())?;
        dict.set_item("min_version", self.inner.min_version)?;
        dict.set_item("max_version", self.inner.max_version)?;
        dict.set_item("handshake_id", self.inner.handshake_id.clone())?;
        dict.set_item("kem_public", self.inner.kem_public.clone())?;
        dict.set_item("ratchet_public", self.inner.ratchet_public.clone())?;
        dict.set_item("semantic_digest", self.inner.semantic_digest.clone())?;
        if let Some(ref sig) = self.inner.signature {
            dict.set_item("signature", sig.clone())?;
        }
        if let Some(ref sig_pk) = self.inner.signature_public_key {
            dict.set_item("signature_public_key", sig_pk.clone())?;
        }
        Ok(dict.into())
    }
    
    /// Get dict without needing Python parameter (uses GIL internally)
    fn to_dict_auto(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| self.to_dict(py))
    }
    
    #[staticmethod]
    fn from_dict(dict: &PyAny) -> PyResult<Self> {
        let dict = dict.downcast::<PyDict>()?;
        Ok(Self {
            inner: session::HandshakeRequest {
                version: dict.get_item("version")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'version'"))?
                    .extract::<Vec<u8>>()?,
                min_version: dict.get_item("min_version")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'min_version'"))?
                    .extract::<u8>()?,
                max_version: dict.get_item("max_version")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'max_version'"))?
                    .extract::<u8>()?,
                handshake_id: dict.get_item("handshake_id")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'handshake_id'"))?
                    .extract::<Vec<u8>>()?,
                kem_public: dict.get_item("kem_public")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'kem_public'"))?
                    .extract::<Vec<u8>>()?,
                ratchet_public: dict.get_item("ratchet_public")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'ratchet_public'"))?
                    .extract::<Vec<u8>>()?,
                semantic_digest: dict.get_item("semantic_digest")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'semantic_digest'"))?
                    .extract::<Vec<u8>>()?,
                signature: dict.get_item("signature").and_then(|v| v.extract::<Vec<u8>>().ok()),
                signature_public_key: dict.get_item("signature_public_key").and_then(|v| v.extract::<Vec<u8>>().ok()),
            },
        })
    }
}

// Python bindings for HandshakeResponse
#[cfg(feature = "python")]
#[pyclass]
#[derive(Clone)]
pub struct HandshakeResponsePy {
    pub inner: session::HandshakeResponse,
}

#[cfg(feature = "python")]
#[pymethods]
impl HandshakeResponsePy {
    fn to_dict(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        dict.set_item("version", self.inner.version.clone())?;
        dict.set_item("handshake_id", self.inner.handshake_id.clone())?;
        dict.set_item("kem_ciphertext", self.inner.kem_ciphertext.clone())?;
        dict.set_item("ratchet_public", self.inner.ratchet_public.clone())?;
        dict.set_item("semantic_digest", self.inner.semantic_digest.clone())?;
        if let Some(ref sig) = self.inner.signature {
            dict.set_item("signature", sig.clone())?;
        }
        if let Some(ref sig_pk) = self.inner.signature_public_key {
            dict.set_item("signature_public_key", sig_pk.clone())?;
        }
        Ok(dict.into())
    }
    
    /// Get dict without needing Python parameter (uses GIL internally)
    fn to_dict_auto(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| self.to_dict(py))
    }
    
    #[staticmethod]
    fn from_dict(dict: &PyAny) -> PyResult<Self> {
        let dict = dict.downcast::<PyDict>()?;
        Ok(Self {
            inner: session::HandshakeResponse {
                version: dict.get_item("version")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'version'"))?
                    .extract::<Vec<u8>>()?,
                handshake_id: dict.get_item("handshake_id")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'handshake_id'"))?
                    .extract::<Vec<u8>>()?,
                kem_ciphertext: dict.get_item("kem_ciphertext")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'kem_ciphertext'"))?
                    .extract::<Vec<u8>>()?,
                ratchet_public: dict.get_item("ratchet_public")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'ratchet_public'"))?
                    .extract::<Vec<u8>>()?,
                semantic_digest: dict.get_item("semantic_digest")
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'semantic_digest'"))?
                    .extract::<Vec<u8>>()?,
                signature: dict.get_item("signature").and_then(|v| v.extract::<Vec<u8>>().ok()),
                signature_public_key: dict.get_item("signature_public_key").and_then(|v| v.extract::<Vec<u8>>().ok()),
            },
        })
    }
}

// Python bindings for RatchetSession
#[cfg(feature = "python")]
#[pyclass]
pub struct RatchetSessionPy {
    pub inner: session::RatchetSession,
}

#[cfg(feature = "python")]
#[pymethods]
impl RatchetSessionPy {
    #[new]
    fn new(
        is_initiator: bool,
        semantic_hint: Vec<u8>,
        max_skip: Option<usize>,
    ) -> Self {
        let max_skip = max_skip.unwrap_or(state::MAX_SKIP_DEFAULT);
        Self {
            inner: session::RatchetSession::new(is_initiator, semantic_hint, max_skip),
        }
    }
    
    #[staticmethod]
    fn create_initiator(semantic_hint: Vec<u8>, max_skip: Option<usize>) -> Self {
        let max_skip = max_skip.unwrap_or(state::MAX_SKIP_DEFAULT);
        Self {
            inner: session::RatchetSession::create_initiator(semantic_hint, max_skip),
        }
    }
    
    #[staticmethod]
    fn create_responder(semantic_hint: Vec<u8>, max_skip: Option<usize>) -> Self {
        let max_skip = max_skip.unwrap_or(state::MAX_SKIP_DEFAULT);
        Self {
            inner: session::RatchetSession::create_responder(semantic_hint, max_skip),
        }
    }
    
    fn create_handshake_request(&mut self) -> PyResult<HandshakeRequestPy> {
        let req = self.inner.create_handshake_request()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        Ok(HandshakeRequestPy { inner: req })
    }
    
    fn accept_handshake(&mut self, request: &HandshakeRequestPy) -> PyResult<HandshakeResponsePy> {
        let resp = self.inner.accept_handshake(&request.inner)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        Ok(HandshakeResponsePy { inner: resp })
    }
    
    fn finalize_handshake(&mut self, response: &HandshakeResponsePy) -> PyResult<()> {
        self.inner.finalize_handshake(&response.inner)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        Ok(())
    }
    
    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
    
    fn semantic_hint(&self) -> Vec<u8> {
        self.inner.semantic_hint().to_vec()
    }
    
    fn is_initiator(&self) -> bool {
        self.inner.is_initiator()
    }
    
    fn get_combined_digest(&self, remote_digest: Vec<u8>) -> PyResult<Vec<u8>> {
        Ok(self.inner.combine_digest(&remote_digest))
    }
    
    fn encrypt(&mut self, plaintext: Vec<u8>, associated_data: Option<Vec<u8>>) -> PyResult<PacketPy> {
        let ad = associated_data.unwrap_or_default();
        let packet = self.inner.encrypt(&plaintext, &ad)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        Ok(PacketPy { inner: packet })
    }
    
    fn decrypt(&mut self, packet: &PacketPy, associated_data: Option<Vec<u8>>) -> PyResult<Vec<u8>> {
        if !self.inner.is_ready() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Session not ready"
            ));
        }
        let ad = associated_data.unwrap_or_default();
        let plaintext = self.inner.decrypt(&packet.inner, &ad)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        Ok(plaintext)
    }
    
    fn export_state(&self, use_cbor: Option<bool>) -> PyResult<Vec<u8>> {
        use crate::serialization::{serialize_state, serialize_state_cbor};
        use serde_json;
        
        if !self.inner.is_ready() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Session not ready"
            ));
        }
        
        let state = self.inner.get_state()
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "State not available"
            ))?;
        
        // Use CBOR by default (production format), JSON for backward compatibility
        let use_cbor_format = use_cbor.unwrap_or(true);
        
        if use_cbor_format {
            // CBOR format (production - more compact and efficient)
            let cbor_bytes = serialize_state_cbor(state, &self.inner.semantic_hint, self.inner.is_initiator);
            Ok(cbor_bytes)
        } else {
            // JSON format (debug/backward compatibility)
            let serialized = serialize_state(state, &self.inner.semantic_hint, self.inner.is_initiator);
            let json_bytes = serde_json::to_vec(&serialized)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("JSON serialization failed: {}", e)
                ))?;
            Ok(json_bytes)
        }
    }
    
    #[staticmethod]
    fn from_serialized(blob: Vec<u8>) -> PyResult<Self> {
        use crate::serialization::{deserialize_state, deserialize_state_cbor};
        
        // Try CBOR first (production format), fallback to JSON (debug format)
        let (state, semantic_hint, is_initiator) = if blob.starts_with(b"{") {
            // JSON format (debug)
            use serde_json;
        let json_str = String::from_utf8(blob)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid UTF-8: {}", e)
            ))?;
        
        let payload: serialization::SerializedState = serde_json::from_str(&json_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid JSON: {}", e)
            ))?;
        
            deserialize_state(&payload)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?
        } else {
            // CBOR format (production)
            deserialize_state_cbor(&blob)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?
        };
        
        let mut session = session::RatchetSession::new(
            is_initiator,
            semantic_hint,
            state.max_skip,
        );
        session.state = Some(state);
        session.ready = true;
        
        Ok(Self { 
            inner: session,
        })
    }
}

// Python bindings for Dilithium Signatures
#[cfg(feature = "python")]
#[pyclass]
pub struct DilithiumSignatures;

#[cfg(feature = "python")]
#[pymethods]
impl DilithiumSignatures {
    /// Generate a Dilithium key pair
    /// 
    /// Returns (public_key, secret_key) as bytes.
    #[staticmethod]
    fn generate_key_pair(py: Python) -> PyResult<PyObject> {
        let (pk, sk) = signatures::generate_key_pair();
        Ok((PyBytes::new(py, &pk), PyBytes::new(py, &sk)).to_object(py))
    }
    
    /// Sign a message using Dilithium
    /// 
    /// # Arguments
    /// * `message` - Message to sign (bytes)
    /// * `secret_key` - Dilithium secret key (bytes)
    /// 
    /// # Returns
    /// Signature bytes
    #[staticmethod]
    fn sign_message(py: Python, message: &[u8], secret_key: &[u8]) -> PyResult<PyObject> {
        let signature = signatures::sign_message(message, secret_key)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        Ok(PyBytes::new(py, &signature).to_object(py))
    }
    
    /// Verify a message signature using Dilithium
    /// 
    /// # Arguments
    /// * `message` - Message to verify (bytes)
    /// * `signature` - Signature bytes (bytes)
    /// * `public_key` - Dilithium public key (bytes)
    /// 
    /// # Returns
    /// `True` if signature is valid, `False` otherwise
    #[staticmethod]
    fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
        signatures::verify_signature(message, signature, public_key)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn pqfsr_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<NuclearReactor>()?;
    m.add_class::<RatchetModePy>()?;
    m.add_class::<PacketPy>()?;
    m.add_class::<HandshakeRequestPy>()?;
    m.add_class::<HandshakeResponsePy>()?;
    m.add_class::<RatchetSessionPy>()?;
    m.add_class::<DilithiumSignatures>()?;
    m.add_class::<error::PQFSRErrorPy>()?;
    Ok(())
}
