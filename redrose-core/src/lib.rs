// redrose-core/src/lib.rs
pub mod error;
pub mod kdf;
pub mod cipher;
pub mod redrose_layer;
pub mod format;

pub use error::CipherError;

/// Encrypts `plaintext` with `password`. Returns the `.rr` file bytes.
/// `original_ext` should include the dot, e.g. `".png"`.
pub fn encrypt(plaintext: &[u8], password: &str, original_ext: &str) -> Result<Vec<u8>, CipherError> {
    let salt = kdf::generate_salt();
    let key = kdf::derive_key(password, &salt)?;

    let (ciphertext, nonce) = cipher::encrypt_xchacha20(&key, plaintext)?;
    let rr_output = redrose_layer::apply(&ciphertext, &key, &salt);

    let data = format::write_rr(
        &salt,
        &nonce,
        original_ext,
        plaintext.len() as u64,
        &rr_output,
    );

    Ok(data)
}

/// Decrypts a `.rr` file with `password`.
/// Returns `(plaintext_bytes, original_extension)`.
pub fn decrypt(data: &[u8], password: &str) -> Result<(Vec<u8>, String), CipherError> {
    let rr = format::read_rr(data)?;
    let key = kdf::derive_key(password, &rr.salt)?;

    let ciphertext = redrose_layer::reverse(
        &rr.scrambled_ciphertext,
        &key,
        &rr.salt,
        &rr.permutation_table,
        rr.block_size,
        rr.ciphertext_len,
    );

    let plaintext = cipher::decrypt_xchacha20(&key, &rr.nonce, &ciphertext)?;

    if plaintext.len() as u64 != rr.original_size {
        return Err(CipherError::CorruptedFile);
    }

    Ok((plaintext, rr.original_ext))
}
