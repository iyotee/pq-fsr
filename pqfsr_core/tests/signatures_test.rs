/// SIGNATURES TESTS: Test Dilithium signature operations
/// ======================================================

use pqfsr_core::{generate_key_pair, sign_message, verify_signature};

#[test]
fn test_generate_key_pair() {
    let (pk, sk) = generate_key_pair();
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
    assert_ne!(pk, sk);
    
    // Generate another pair - should be different
    let (pk2, sk2) = generate_key_pair();
    assert_ne!(pk, pk2);
    assert_ne!(sk, sk2);
}

#[test]
fn test_sign_and_verify() {
    let (pk, sk) = generate_key_pair();
    let message = b"Hello, World!";
    
    let signature = sign_message(message, &sk).unwrap();
    assert!(!signature.is_empty());
    
    let valid = verify_signature(message, &signature, &pk).unwrap();
    assert!(valid);
}

#[test]
fn test_sign_and_verify_wrong_message() {
    let (pk, sk) = generate_key_pair();
    let message = b"Hello, World!";
    let wrong_message = b"Hello, Universe!";
    
    let signature = sign_message(message, &sk).unwrap();
    let valid = verify_signature(wrong_message, &signature, &pk).unwrap();
    assert!(!valid);
}

#[test]
fn test_sign_and_verify_wrong_key() {
    let (_pk1, sk1) = generate_key_pair();
    let (pk2, _sk2) = generate_key_pair();
    let message = b"Hello, World!";
    
    let signature = sign_message(message, &sk1).unwrap();
    let valid = verify_signature(message, &signature, &pk2).unwrap();
    assert!(!valid);
}

