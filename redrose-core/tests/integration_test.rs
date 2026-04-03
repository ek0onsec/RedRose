// redrose-core/tests/integration_test.rs
use redrose_core;

#[test]
fn test_encrypt_decrypt_roundtrip_small_file() {
    let plaintext = b"classified document content".to_vec();
    let password = "RedRose@2049!";
    let encrypted = redrose_core::encrypt(&plaintext, password, ".txt").unwrap();
    let (decrypted, ext) = redrose_core::decrypt(&encrypted, password).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, ".txt");
}

#[test]
fn test_encrypt_decrypt_roundtrip_binary_file() {
    // Simulate a binary file (e.g., header bytes of a PNG)
    let plaintext: Vec<u8> = (0..2048).map(|i| (i * 7 % 256) as u8).collect();
    let password = "test-password";
    let encrypted = redrose_core::encrypt(&plaintext, password, ".png").unwrap();
    let (decrypted, ext) = redrose_core::decrypt(&encrypted, password).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(ext, ".png");
}

#[test]
fn test_wrong_password_fails() {
    let plaintext = b"secret".to_vec();
    let encrypted = redrose_core::encrypt(&plaintext, "correct", ".bin").unwrap();
    let result = redrose_core::decrypt(&encrypted, "wrong");
    assert!(result.is_err());
}

#[test]
fn test_encrypted_output_differs_from_input() {
    let plaintext: Vec<u8> = vec![0u8; 512];
    let encrypted = redrose_core::encrypt(&plaintext, "password", ".bin").unwrap();
    // Encrypted output must start with RROS magic, not zeros
    assert_eq!(&encrypted[0..4], b"RROS");
    assert_ne!(&encrypted[..plaintext.len()], plaintext.as_slice());
}

#[test]
fn test_two_encryptions_of_same_file_differ() {
    let plaintext = b"same content".to_vec();
    let e1 = redrose_core::encrypt(&plaintext, "pass", ".txt").unwrap();
    let e2 = redrose_core::encrypt(&plaintext, "pass", ".txt").unwrap();
    // Different salts and nonces → different output
    assert_ne!(e1, e2);
}
