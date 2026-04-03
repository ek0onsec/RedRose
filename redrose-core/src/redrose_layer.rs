// redrose-core/src/redrose_layer.rs

pub struct RedRoseOutput {
    pub data: Vec<u8>,
    pub table: Vec<u32>,
    pub block_size: u16,
    pub ciphertext_len: u64,
}

fn compute_block_size(key: &[u8; 32], salt: &[u8; 32]) -> usize {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"redrose-block-size");
    hasher.update(salt);
    let hash = hasher.finalize();
    128usize + hash.as_bytes()[0] as usize // range [128, 383]
}

fn generate_permutation(key: &[u8; 32], salt: &[u8; 32], count: usize) -> Vec<usize> {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"redrose-perm");
    hasher.update(salt);
    let mut reader = hasher.finalize_xof();

    let mut indices: Vec<usize> = (0..count).collect();
    // Fisher-Yates shuffle seeded by BLAKE3 XOF
    for i in (1..count).rev() {
        let mut buf = [0u8; 8];
        reader.fill(&mut buf);
        let j = usize::from_le_bytes(buf) % (i + 1);
        indices.swap(i, j);
    }
    indices // indices[new_pos] = orig_pos
}

fn compute_block_mask(key: &[u8; 32], salt: &[u8; 32], orig_index: u32) -> u8 {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"redrose-mask");
    hasher.update(salt);
    hasher.update(&orig_index.to_le_bytes());
    hasher.finalize().as_bytes()[0]
}

pub fn apply(ciphertext: &[u8], key: &[u8; 32], salt: &[u8; 32]) -> RedRoseOutput {
    let block_size = compute_block_size(key, salt);
    let ciphertext_len = ciphertext.len() as u64;

    // Pad to multiple of block_size
    let padded_len = ((ciphertext.len() + block_size - 1) / block_size) * block_size;
    let mut padded = ciphertext.to_vec();
    padded.resize(padded_len, 0u8);

    let count = padded_len / block_size;
    let perm = generate_permutation(key, salt, count);

    let mut output = vec![0u8; padded_len];
    for (new_pos, &orig_pos) in perm.iter().enumerate() {
        let src_start = orig_pos * block_size;
        let dst_start = new_pos * block_size;
        let mask = compute_block_mask(key, salt, orig_pos as u32);
        for i in 0..block_size {
            output[dst_start + i] = padded[src_start + i] ^ mask;
        }
    }

    let table: Vec<u32> = perm.iter().map(|&i| i as u32).collect();

    RedRoseOutput {
        data: output,
        table,
        block_size: block_size as u16,
        ciphertext_len,
    }
}

pub fn reverse(
    scrambled: &[u8],
    key: &[u8; 32],
    salt: &[u8; 32],
    table: &[u32],
    block_size: u16,
    ciphertext_len: u64,
) -> Vec<u8> {
    let block_size = block_size as usize;
    let count = table.len();
    let mut output = vec![0u8; count * block_size];

    for (new_pos, &orig_pos) in table.iter().enumerate() {
        let src_start = new_pos * block_size;
        let dst_start = orig_pos as usize * block_size;
        let mask = compute_block_mask(key, salt, orig_pos);
        for i in 0..block_size {
            output[dst_start + i] = scrambled[src_start + i] ^ mask;
        }
    }

    output.truncate(ciphertext_len as usize);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_key() -> [u8; 32] { [0xABu8; 32] }
    fn dummy_salt() -> [u8; 32] { [0xCDu8; 32] }

    #[test]
    fn test_apply_reverse_roundtrip_small() {
        let key = dummy_key();
        let salt = dummy_salt();
        let ciphertext = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".to_vec();
        let output = apply(&ciphertext, &key, &salt);
        let recovered = reverse(&output.data, &key, &salt, &output.table, output.block_size, output.ciphertext_len);
        assert_eq!(recovered, ciphertext);
    }

    #[test]
    fn test_apply_reverse_roundtrip_large() {
        let key = dummy_key();
        let salt = dummy_salt();
        let ciphertext: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        let output = apply(&ciphertext, &key, &salt);
        let recovered = reverse(&output.data, &key, &salt, &output.table, output.block_size, output.ciphertext_len);
        assert_eq!(recovered, ciphertext);
    }

    #[test]
    fn test_scrambled_differs_from_original() {
        let key = dummy_key();
        let salt = dummy_salt();
        let ciphertext: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let output = apply(&ciphertext, &key, &salt);
        assert_ne!(output.data[..ciphertext.len()], ciphertext[..]);
    }

    #[test]
    fn test_block_size_in_range() {
        let key = dummy_key();
        let salt = dummy_salt();
        let ciphertext = vec![0u8; 1000];
        let output = apply(&ciphertext, &key, &salt);
        assert!(output.block_size >= 128);
        assert!(output.block_size <= 383);
    }

    #[test]
    fn test_different_keys_produce_different_scrambling() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let salt = dummy_salt();
        let ciphertext: Vec<u8> = (0..500u32).map(|i| (i % 256) as u8).collect();
        let o1 = apply(&ciphertext, &key1, &salt);
        let o2 = apply(&ciphertext, &key2, &salt);
        assert_ne!(o1.data, o2.data);
    }
}
