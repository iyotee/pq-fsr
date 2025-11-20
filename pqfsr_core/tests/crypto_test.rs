/// CRYPTO TESTS: Test cryptographic primitives
/// ===========================================

use pqfsr_core::{hkdf, sha256, ChaCha20Poly1305Cipher, constant_time_eq, Cipher};

#[test]
fn test_hkdf() {
    let salt = b"test_salt";
    let ikm = b"test_input_key_material";
    let info = b"test_info";
    let length = 32;
    
    let derived = hkdf(salt, ikm, info, length);
    assert_eq!(derived.len(), length);
    
    // Deterministic
    let derived2 = hkdf(salt, ikm, info, length);
    assert_eq!(derived, derived2);
    
    // Different inputs produce different outputs
    let derived3 = hkdf(salt, b"different_ikm", info, length);
    assert_ne!(derived, derived3);
}

#[test]
fn test_sha256() {
    let data = b"test_data";
    let hash = sha256(data);
    assert_eq!(hash.len(), 32);
    
    // Deterministic
    let hash2 = sha256(data);
    assert_eq!(hash, hash2);
}

#[test]
fn test_chacha20poly1305_encrypt_decrypt() {
    let cipher = ChaCha20Poly1305Cipher;
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 12];
    let plaintext = b"Hello, World!";
    let ad = b"associated_data";
    
    let ciphertext = cipher.encrypt(&key, &nonce, plaintext, ad);
    assert!(!ciphertext.is_empty());
    assert_ne!(ciphertext, plaintext);
    
    let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, ad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_chacha20poly1305_wrong_key() {
    let cipher = ChaCha20Poly1305Cipher;
    let key = vec![0u8; 32];
    let wrong_key = vec![1u8; 32];
    let nonce = vec![0u8; 12];
    let plaintext = b"Hello, World!";
    let ad = b"associated_data";
    
    let ciphertext = cipher.encrypt(&key, &nonce, plaintext, ad);
    let result = cipher.decrypt(&wrong_key, &nonce, &ciphertext, ad);
    assert!(result.is_err());
}

#[test]
fn test_constant_time_eq() {
    let a = b"test";
    let b = b"test";
    let c = b"diff";
    
    assert!(constant_time_eq(a, b));
    assert!(!constant_time_eq(a, c));
}

