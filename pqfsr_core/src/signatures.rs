/// SIGNATURES MODULE: Post-Quantum Digital Signatures
/// ====================================================
/// This module provides signature generation and verification using Dilithium (ML-DSA).
/// 
/// Dilithium is a NIST PQC standard (FIPS 204) for digital signatures.
/// It provides strong security against both classical and quantum attacks.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::*;

/// Generate a Dilithium key pair
/// 
/// Returns (public_key, secret_key) as byte vectors.
pub fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium3::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Sign a message using Dilithium
/// 
/// # Arguments
/// * `message` - Message to sign
/// * `secret_key` - Dilithium secret key
/// 
/// # Returns
/// Signature bytes
pub fn sign_message(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    let sk = SecretKey::from_bytes(secret_key)
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    
    let signature = dilithium3::sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

/// Verify a message signature using Dilithium
/// 
/// # Arguments
/// * `message` - Message to verify
/// * `signature` - Signature bytes (signed message format)
/// * `public_key` - Dilithium public key
/// 
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String> {
    let pk = PublicKey::from_bytes(public_key)
        .map_err(|e| format!("Invalid public key: {:?}", e))?;
    
    // Dilithium signed message format: signature + message
    // We need to extract the signature part and verify
    let sig = SignedMessage::from_bytes(signature)
        .map_err(|e| format!("Invalid signature: {:?}", e))?;
    
    // Verify the signed message - open() returns the original message
    match dilithium3::open(&sig, &pk) {
        Ok(decoded_message) => {
            // decoded_message is a Vec<u8>, compare directly
            Ok(decoded_message == message)
        },
        Err(_) => Ok(false),
    }
}

