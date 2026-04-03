// redrose-core/src/format.rs
use crate::{CipherError, redrose_layer::RedRoseOutput};

const MAGIC: &[u8; 4] = b"RROS";
const VERSION: u16 = 1;
pub const FIXED_HEADER_LEN: usize = 100;

pub struct RrFile {
    pub salt: [u8; 32],
    pub nonce: [u8; 24],
    pub original_ext: String,
    pub original_size: u64,
    pub block_size: u16,
    pub ciphertext_len: u64,
    pub permutation_table: Vec<u32>,
    pub scrambled_ciphertext: Vec<u8>,
}

pub fn write_rr(
    salt: &[u8; 32],
    nonce: &[u8; 24],
    original_ext: &str,
    original_size: u64,
    rr_output: &RedRoseOutput,
) -> Vec<u8> {
    let block_count = rr_output.table.len() as u32;
    let capacity = FIXED_HEADER_LEN + block_count as usize * 4 + rr_output.data.len();
    let mut buf = Vec::with_capacity(capacity);

    buf.extend_from_slice(MAGIC);                                      // 0-3
    buf.extend_from_slice(&VERSION.to_le_bytes());                     // 4-5
    buf.extend_from_slice(salt);                                       // 6-37
    buf.extend_from_slice(nonce);                                      // 38-61

    let mut ext_bytes = [0u8; 16];
    let s = original_ext.as_bytes();
    let n = s.len().min(15);
    ext_bytes[..n].copy_from_slice(&s[..n]);
    buf.extend_from_slice(&ext_bytes);                                 // 62-77

    buf.extend_from_slice(&original_size.to_le_bytes());               // 78-85
    buf.extend_from_slice(&rr_output.block_size.to_le_bytes());        // 86-87
    buf.extend_from_slice(&block_count.to_le_bytes());                 // 88-91
    buf.extend_from_slice(&rr_output.ciphertext_len.to_le_bytes());    // 92-99

    for &idx in &rr_output.table {
        buf.extend_from_slice(&idx.to_le_bytes());
    }

    buf.extend_from_slice(&rr_output.data);
    buf
}

pub fn read_rr(data: &[u8]) -> Result<RrFile, CipherError> {
    if data.len() < FIXED_HEADER_LEN {
        return Err(CipherError::InvalidFormat);
    }
    if &data[0..4] != MAGIC {
        return Err(CipherError::InvalidFormat);
    }

    let salt: [u8; 32] = data[6..38].try_into().unwrap();
    let nonce: [u8; 24] = data[38..62].try_into().unwrap();

    let ext_raw = &data[62..78];
    let null_pos = ext_raw.iter().position(|&b| b == 0).unwrap_or(16);
    let original_ext = String::from_utf8_lossy(&ext_raw[..null_pos]).to_string();

    let original_size = u64::from_le_bytes(data[78..86].try_into().unwrap());
    let block_size    = u16::from_le_bytes(data[86..88].try_into().unwrap());
    let block_count   = u32::from_le_bytes(data[88..92].try_into().unwrap());
    let ciphertext_len = u64::from_le_bytes(data[92..100].try_into().unwrap());

    let table_end = FIXED_HEADER_LEN + block_count as usize * 4;
    if data.len() < table_end {
        return Err(CipherError::InvalidFormat);
    }

    let permutation_table: Vec<u32> = data[FIXED_HEADER_LEN..table_end]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();

    let scrambled_ciphertext = data[table_end..].to_vec();

    Ok(RrFile {
        salt,
        nonce,
        original_ext,
        original_size,
        block_size,
        ciphertext_len,
        permutation_table,
        scrambled_ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redrose_layer::RedRoseOutput;

    fn dummy_rr_output() -> RedRoseOutput {
        RedRoseOutput {
            data: vec![0xFFu8; 256],
            table: vec![1u32, 0u32],
            block_size: 128,
            ciphertext_len: 200,
        }
    }

    #[test]
    fn test_write_starts_with_magic() {
        let salt = [0u8; 32];
        let nonce = [0u8; 24];
        let out = write_rr(&salt, &nonce, ".pdf", 1000, &dummy_rr_output());
        assert_eq!(&out[0..4], b"RROS");
    }

    #[test]
    fn test_write_read_roundtrip() {
        let salt = [1u8; 32];
        let nonce = [2u8; 24];
        let rr = dummy_rr_output();
        let bytes = write_rr(&salt, &nonce, ".mp4", 999_999, &rr);
        let parsed = read_rr(&bytes).unwrap();

        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.original_ext, ".mp4");
        assert_eq!(parsed.original_size, 999_999);
        assert_eq!(parsed.block_size, 128);
        assert_eq!(parsed.ciphertext_len, 200);
        assert_eq!(parsed.permutation_table, vec![1u32, 0u32]);
        assert_eq!(parsed.scrambled_ciphertext, vec![0xFFu8; 256]);
    }

    #[test]
    fn test_read_invalid_magic_returns_error() {
        let mut bytes = vec![0u8; 200];
        bytes[0] = b'X'; // corrupt magic
        assert!(matches!(read_rr(&bytes), Err(CipherError::InvalidFormat)));
    }

    #[test]
    fn test_read_truncated_returns_error() {
        let data = vec![0u8; 10]; // too short
        assert!(matches!(read_rr(&data), Err(CipherError::InvalidFormat)));
    }

    #[test]
    fn test_extension_null_padding() {
        let salt = [0u8; 32];
        let nonce = [0u8; 24];
        let rr = dummy_rr_output();
        let bytes = write_rr(&salt, &nonce, ".png", 100, &rr);
        let parsed = read_rr(&bytes).unwrap();
        assert_eq!(parsed.original_ext, ".png");
    }
}
