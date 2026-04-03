// redrose-core/src/kdf.rs
use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use crate::CipherError;

pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn derive_key(password: &str, salt: &[u8; 32]) -> Result<[u8; 32], CipherError> {
    // memory=64MB, iterations=3, parallelism=4, output=32 bytes
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| CipherError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| CipherError::Kdf(e.to_string()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt_is_32_bytes() {
        let salt = generate_salt();
        assert_eq!(salt.len(), 32);
    }

    #[test]
    fn test_generate_salt_unique() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [42u8; 32];
        let k1 = derive_key("hunter2", &salt).unwrap();
        let k2 = derive_key("hunter2", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_different_passwords_produce_different_keys() {
        let salt = [0u8; 32];
        let k1 = derive_key("password1", &salt).unwrap();
        let k2 = derive_key("password2", &salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_key_different_salts_produce_different_keys() {
        let k1 = derive_key("same", &[0u8; 32]).unwrap();
        let k2 = derive_key("same", &[1u8; 32]).unwrap();
        assert_ne!(k1, k2);
    }
}
