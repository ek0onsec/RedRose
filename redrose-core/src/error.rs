// redrose-core/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("Key derivation failed: {0}")]
    Kdf(String),

    #[error("Encryption failed: {0}")]
    Cipher(String),

    #[error("// AUTHENTICATION FAILED")]
    AuthenticationFailed,

    #[error("// INVALID FORMAT — NOT A REDROSE FILE")]
    InvalidFormat,

    #[error("// CORRUPTED FILE")]
    CorruptedFile,
}
