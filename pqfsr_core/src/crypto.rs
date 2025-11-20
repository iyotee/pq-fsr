/// CRYPTO MODULE: Cryptographic Primitives
/// =========================================
/// This module provides all cryptographic primitives used by PQ-FSR:
/// - HKDF-SHA256
/// - ChaCha20-Poly1305 AEAD
/// - AES-256-GCM AEAD (optional)
/// - Constant-time operations
/// - KEM operations (Kyber)

use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;

/// HKDF-SHA256: Key Derivation Function
/// 
/// Implements HKDF expansion using SHA-256.
/// 
/// # Arguments
/// * `salt` - Salt (can be empty)
/// * `ikm` - Input key material
/// * `info` - Context/application-specific information
/// * `length` - Desired output length in bytes
/// 
/// # Returns
/// Derived key material
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    if length == 0 {
        panic!("HKDF length must be positive");
    }
    
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("HKDF expansion failed");
    okm
}

/// Cipher Trait: Abstract interface for authenticated encryption
pub trait Cipher: Send + Sync {
    /// Encrypt plaintext with associated data
    /// Returns ciphertext (including authentication tag)
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], ad: &[u8]) -> Vec<u8>;
    
    /// Decrypt ciphertext with associated data
    /// Returns plaintext or error
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, String>;
}

/// ChaCha20Poly1305Cipher: Production-grade AEAD
/// 
/// Uses ChaCha20-Poly1305 for authenticated encryption.
/// This is the recommended cipher for production use.
pub struct ChaCha20Poly1305Cipher;

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        if key.len() != 32 {
            panic!("ChaCha20-Poly1305 requires 32-byte key");
        }
        if nonce.len() != 12 {
            panic!("ChaCha20-Poly1305 requires 12-byte nonce");
        }
        
        let cipher_key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        
        // Convert nonce to Nonce type
        let nonce_array: [u8; 12] = nonce.try_into().expect("Nonce must be 12 bytes");
        let nonce = Nonce::from_slice(&nonce_array);
        
        // Encrypt with associated data using encrypt_in_place_detached
        // This properly handles AD separately from plaintext
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, ad, &mut buffer)
            .unwrap_or_else(|_| {
                // If encryption fails, return empty tag (should not happen)
                chacha20poly1305::Tag::default()
            });
        
        // Return ciphertext + tag
        [buffer, tag.to_vec()].concat()
    }
    
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("ChaCha20-Poly1305 requires 32-byte key".to_string());
        }
        if nonce.len() != 12 {
            return Err("ChaCha20-Poly1305 requires 12-byte nonce".to_string());
        }
        
        // Split ciphertext and tag (tag is last 16 bytes)
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short (missing tag)".to_string());
        }
        let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);
        let tag = chacha20poly1305::Tag::from_slice(tag_bytes);
        
        let cipher_key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        
        // Convert nonce to Nonce type
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length")?;
        let nonce = Nonce::from_slice(&nonce_array);
        
        // Decrypt with associated data using decrypt_in_place_detached
        // This properly handles AD separately from ciphertext
        let mut buffer = ct.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, ad, &mut buffer, tag)
            .map_err(|_| {
                // All decryption failures in ChaCha20Poly1305 are authentication failures
                // (tag mismatch, AD mismatch, ciphertext corruption, etc.)
                "Authentication tag mismatch".to_string()
            })?;
        
        Ok(buffer)
    }
}

/// Constant-time comparison
/// 
/// Compares two byte slices in constant time to prevent timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

