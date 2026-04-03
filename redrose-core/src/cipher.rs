// redrose-core/src/cipher.rs
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, KeyInit, aead::Aead};
use rand::RngCore;
use crate::CipherError;

pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt_xchacha20(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 24]), CipherError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CipherError::Cipher(e.to_string()))?;

    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt_xchacha20(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CipherError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"Hello, RedRose! This is a secret.";
        let (ciphertext, nonce) = encrypt_xchacha20(&key, plaintext).unwrap();
        let decrypted = decrypt_xchacha20(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let key = [0u8; 32];
        let plaintext = b"test data";
        let (ciphertext, _) = encrypt_xchacha20(&key, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext.to_vec());
    }

    #[test]
    fn test_ciphertext_length_is_plaintext_plus_tag() {
        // XChaCha20-Poly1305 adds a 16-byte auth tag
        let key = [1u8; 32];
        let plaintext = b"sixteen bytes!!!";
        let (ct, _) = encrypt_xchacha20(&key, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_wrong_key_returns_authentication_failed() {
        let key = [0u8; 32];
        let wrong_key = [1u8; 32];
        let plaintext = b"secret data";
        let (ct, nonce) = encrypt_xchacha20(&key, plaintext).unwrap();
        let result = decrypt_xchacha20(&wrong_key, &nonce, &ct);
        assert!(matches!(result, Err(crate::CipherError::AuthenticationFailed)));
    }

    #[test]
    fn test_two_encryptions_produce_different_nonces() {
        let key = [0u8; 32];
        let plaintext = b"same data";
        let (_, n1) = encrypt_xchacha20(&key, plaintext).unwrap();
        let (_, n2) = encrypt_xchacha20(&key, plaintext).unwrap();
        assert_ne!(n1, n2);
    }
}
