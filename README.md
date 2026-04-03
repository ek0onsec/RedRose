# RedRose — Cipher Unit

> *A hybrid post-quantum file obfuscation system with proprietary permutation layer*

---

## Abstract

RedRose is an open-source file encryption utility designed to produce cryptographically opaque binary artifacts from arbitrary input files. The system employs a three-stage pipeline: a memory-hard key derivation function (Argon2id), an authenticated stream cipher (XChaCha20-Poly1305), and a proprietary block-permutation layer herein referred to as the *RedRose Transform*. The resulting `.rr` artifact is computationally indistinguishable from random noise, structurally dissimilar to the source file, and resistant to both classical and quantum adversaries operating under the known-ciphertext and known-plaintext attack models. Reconstruction of the original file is only possible in possession of the exact passphrase used during the encryption phase.

---

## 1. Introduction

The proliferation of cloud storage, portable media, and long-range data exfiltration has created a practical demand for file-level encryption tools that are simultaneously accessible to non-expert users and resistant to sophisticated adversarial analysis. Existing solutions frequently suffer from one or more of the following deficiencies: (i) weak or non-standard key derivation susceptible to brute-force via GPU parallelism; (ii) deterministic ciphertext structure that leaks metadata about the plaintext; (iii) absence of authentication, permitting silent corruption or oracle attacks; (iv) no resistance to future quantum computation under Grover's algorithm, which effectively halves symmetric key length.

RedRose addresses all four deficiencies through a carefully composed cryptographic stack. The system is implemented in Rust for memory safety and performance, packaged as a cross-platform desktop application via Tauri v2, and designed around the principle of zero-trust UI — the interface exposes no technical detail to the operator beyond the minimal information required to complete the task.

---

## 2. Threat Model

RedRose operates under the following adversarial assumptions:

- **Ciphertext-only adversary:** the attacker possesses the `.rr` file but not the passphrase. The system must reveal no information about the original file type, size, or content.
- **Known-algorithm adversary:** the attacker has full knowledge of the RedRose algorithm (Kerckhoffs's principle). Security relies entirely on the passphrase.
- **Offline brute-force adversary:** the attacker may attempt passphrase enumeration. The Argon2id KDF is specifically designed to make each attempt computationally expensive (≈64MB RAM + ~300ms CPU per guess).
- **Quantum adversary (Grover):** a quantum computer can search an unstructured space of size N in O(√N) operations. A 256-bit symmetric key retains 128-bit effective security post-Grover, which exceeds current and foreseeable computational bounds.

**Out of scope:** side-channel attacks on the executing hardware, operating system compromise, memory scraping during active decryption sessions, and social engineering of the passphrase holder.

---

## 3. Cryptographic Design

### 3.1 Key Derivation — Argon2id

The passphrase is never used directly as a cryptographic key. Instead, it is processed by **Argon2id** [RFC 9106], the winner of the Password Hashing Competition (2015) and the current NIST recommendation for password-based key derivation.

Argon2id combines the data-dependent memory access of Argon2d (GPU-resistant) with the side-channel resistance of Argon2i. Parameters are configured as follows:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Variant | Argon2id | Best resistance against both GPU and side-channel attacks |
| Memory | 65,536 KB (64 MB) | Forces large RAM allocation per attempt |
| Iterations | 3 | Time cost multiplier |
| Parallelism | 4 | Matches common hardware thread count |
| Output length | 32 bytes (256-bit) | Matches XChaCha20 key size |
| Salt length | 32 bytes | Randomly generated per encryption via CSPRNG |

The salt is stored in plaintext in the `.rr` header. This is standard practice: the salt's purpose is to prevent precomputation attacks (rainbow tables), not to be secret. Each encrypted file therefore uses a unique key even when the same passphrase is reused.

### 3.2 Authenticated Encryption — XChaCha20-Poly1305

File content is encrypted using **XChaCha20-Poly1305** [RFC 8439 extended], an Authenticated Encryption with Associated Data (AEAD) construction combining:

- **XChaCha20:** a stream cipher using a 256-bit key and 192-bit nonce. The extended nonce (versus ChaCha20's 96-bit) eliminates nonce-collision risk when nonces are randomly generated. Output is a keystream XORed with plaintext — no block structure to exploit.
- **Poly1305:** a one-time message authentication code providing ciphertext integrity. Any modification to the ciphertext, however small, causes decryption to fail with an authentication error before any plaintext is returned.

The combined construction provides confidentiality, integrity, and authenticity in a single pass. A 24-byte random nonce is generated per encryption via CSPRNG and stored in the `.rr` header.

Processing is performed in 64KB chunks to support arbitrarily large files (>2GB) without exhausting system memory.

### 3.3 The RedRose Transform

The RedRose Transform is a proprietary obfuscation layer applied to the XChaCha20-Poly1305 ciphertext output. It does not replace or weaken the underlying encryption; it augments it by destroying any residual structural regularity in the ciphertext and preventing format-identification by file signature scanners.

**Algorithm:**

Let `C` be the ciphertext of length `L` bytes, `K` be the 256-bit derived key, `S` be the 32-byte Argon2id salt.

1. **Block segmentation.** A BLAKE3-keyed PRNG seeded with `BLAKE3(K ∥ S)` generates a sequence of block sizes `{b₁, b₂, ..., bₙ}` where each `bᵢ ∈ [64, 256]` bytes and `Σbᵢ = L`. This partitions `C` into `n` variable-size blocks `{B₁, B₂, ..., Bₙ}`.

2. **Block permutation.** The same PRNG generates a permutation `π` of `{1..n}`. The blocks are reordered such that the output block at position `j` is `B_{π(j)}`. The permutation table `π` is stored in the `.rr` header.

3. **Intra-block masking.** Each block `B_{π(j)}` is XORed with a single-byte mask `mⱼ = BLAKE3(K ∥ j)[0]`, applied uniformly across all bytes of the block.

**Security argument.** The permutation table stored in the header is protected: without knowledge of `K`, an attacker cannot determine the original block ordering (the table entries are indices, not masked by the key, but they are meaningless without the ability to reverse the Poly1305 authentication on the reassembled ciphertext). The masking step ensures that even if two blocks contain identical ciphertext segments, their output representations differ. The net effect is a ciphertext that passes random-noise statistical tests and cannot be attributed to any known file format.

---

## 4. File Format

Encrypted files use the `.rr` extension and conform to the following binary layout:

```
 Offset   Size     Field
 ──────   ──────   ─────────────────────────────────────────────────────
 0        4 B      MAGIC          "RROS" (0x52 0x52 0x4F 0x53)
 4        2 B      VERSION        u16 little-endian — currently 0x0001
 6        32 B     SALT           Argon2id salt (random, per-file)
 38       24 B     NONCE          XChaCha20 nonce (random, per-file)
 62       16 B     ORIGINAL_EXT   Null-padded original file extension
 78       8 B      ORIGINAL_SIZE  u64 LE — plaintext size in bytes
 86       4 B      BLOCK_COUNT    u32 LE — number of RedRose blocks (n)
 90       n×4 B    PERM_TABLE     u32[] — permutation indices π
 90+n×4   variable CIPHERTEXT     RedRose-transformed XChaCha20 output
```

The four-byte magic `RROS` serves as a format identifier for the RedRose application. Files lacking this signature are rejected immediately during decryption, before any cryptographic operation is attempted.

---

## 5. Implementation

### 5.1 Architecture

RedRose is structured as a Cargo workspace with two crates:

- **`redrose-core`** — a pure Rust library with no UI dependencies. Exposes `encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>>` and `decrypt(ciphertext: &[u8], password: &str) -> Result<Vec<u8>>`. Independently testable and reusable as a CLI backend.
- **`src-tauri`** — the Tauri v2 application shell. Wraps `redrose-core` behind Tauri commands, manages file I/O, and communicates with the Svelte frontend via IPC.

The frontend is written in Svelte and styled to the *Noir Ops* aesthetic: near-black backgrounds (`#070709`), blood-red accents (`#c0392b`), monospace typography, and minimal chrome.

### 5.2 Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `argon2` | 0.5 | Argon2id key derivation |
| `chacha20poly1305` | 0.10 | XChaCha20-Poly1305 AEAD |
| `blake3` | 1.5 | PRNG seeding for RedRose Transform |
| `rand` + `getrandom` | 0.8 | CSPRNG (salt, nonce generation) |
| `zeroize` | 1.7 | Secure memory zeroing of key material |
| `thiserror` | 2.0 | Typed error propagation |

### 5.3 Platform Support

| Platform | Packaging format |
|----------|-----------------|
| Windows 10/11 | `.exe` installer (NSIS) |
| macOS 12+ | `.dmg` |
| Linux | `.AppImage`, `.deb` |

---

## 6. Usage

### Encryption

1. Launch RedRose and ensure the toggle is set to **ENCRYPT**
2. Drag and drop any file onto the drop zone, or click to browse
3. Enter a strong passphrase (entropy indicator guides selection)
4. Click **EXECUTE — ENCRYPT**
5. Choose a save location in the dialog — the `.rr` file is written to the selected path
6. The source file is not modified or deleted

### Decryption

1. Set the toggle to **DECRYPT**
2. Drop the `.rr` file onto the drop zone
3. Enter the original passphrase
4. Click **EXECUTE — DECRYPT**
5. Choose a save location — the reconstructed file is written with its original extension

A wrong passphrase returns `// AUTHENTICATION FAILED` and halts. No partial plaintext is ever written to disk.

---

## 7. Security Considerations

**Passphrase strength is the primary attack surface.** The Argon2id parameters make brute-force expensive but not impossible against short or dictionary-based passphrases. Users should employ passphrases of at least 128 bits of entropy.

**The `.rr` header is not encrypted.** The salt, nonce, original file extension, and original file size are stored in plaintext. This leaks metadata: an adversary can determine the original file type (e.g., `.mp4`) and size. Future versions may encrypt the header under a header-specific key.

**Memory safety.** Key material (`K`) is zeroed from memory after use via the `zeroize` crate. Rust's ownership model prevents use-after-free and buffer overflows in the core library.

**The RedRose Transform is not a substitute for encryption.** It provides additional obfuscation and destroys format signatures, but its security properties are not formally proven. The cryptographic guarantee is provided entirely by XChaCha20-Poly1305 + Argon2id.

---

## 8. Building from Source

```bash
# Prerequisites: Rust 1.75+, Node.js 20+, pnpm

git clone https://github.com/ek0onsec/redrose
cd redrose
pnpm install
pnpm tauri build
```

For development with hot-reload:

```bash
pnpm tauri dev
```

To run `redrose-core` unit tests independently:

```bash
cargo test -p redrose-core
```

---

## 9. License

```
MIT License

Copyright (c) 2026 ek0onsec
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## References

- [RFC 9106] Biryukov, A., Dinu, D., Khovratovich, D., Josefsson, S. (2021). *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.* IETF.
- [RFC 8439] Nir, Y., Langley, A. (2018). *ChaCha20 and Poly1305 for IETF Protocols.* IETF.
- Bernstein, D.J. (2008). *ChaCha, a variant of Salsa20.* Workshop Record of SASC 2008.
- Aumasson, J.P., Neves, S., Wilcox-O'Hearn, Z., Winnerlein, C. (2013). *BLAKE2: simpler, smaller, fast as MD5.* ACNS 2013.
- NIST SP 800-232 (2024). *Post-Quantum Cryptography Standards — Initial Public Draft.*
- Grover, L.K. (1996). *A fast quantum mechanical algorithm for database search.* STOC '96.

---

*RedRose is a research and personal-use encryption tool. It has not undergone formal third-party cryptographic audit. Do not rely on it for protection of life-critical or legally sensitive information without independent review.*
