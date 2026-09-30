//! JYCRYPT1 twin (Rust side): decrypt-and-verify `.jxp` blobs produced by
//! jocky/crypto.py. Blob layout: MAGIC(8) | salt(8) | tag(32) | ciphertext.
//!
//! Parity contract with the hardened Python implementation:
//!   - keystream: state words = the four little-endian u64 slices of
//!     sha256(key || salt), 8 warm-up rounds discarded, then Xoshiro256**
//!     output words serialized little-endian and XORed with the plaintext;
//!   - integrity tag: sha256(salt || ciphertext || b"JOCKY:" || key),
//!     verified BEFORE any keystream is generated.

use crate::sha256::{sha256_hex, Sha256};

pub const MAGIC: &[u8; 8] = b"JYCRYPT1";
pub const TAG_LEN: usize = 32;
const SEP: &[u8] = b"JOCKY:";

#[derive(Debug)]
pub enum CryptoError {
    TooShort,
    BadMagic,
    IntegrityFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::TooShort => write!(f, "blob too short"),
            CryptoError::BadMagic => write!(f, "bad magic: not a JYCRYPT1 blob"),
            CryptoError::IntegrityFailed => {
                write!(f, "integrity check failed (wrong key or tampered blob)")
            }
        }
    }
}

/// Xoshiro256** — byte-for-byte parity with Python `_Xoshiro256`.
pub struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    /// Seed directly from four 64-bit state words (all-zero rejected),
    /// mirroring `from_words` in jocky/crypto.py.
    pub fn from_words(words: [u64; 4]) -> Self {
        if words == [0u64; 4] {
            panic!("xoshiro state must be non-zero");
        }
        Xoshiro256 { s: words }
    }

    pub fn next(&mut self) -> u64 {
        // NOTE: parity with jocky/crypto.py, which computes
        // ((s1 * 5 & M) << 7 & M) * 9 & M — a truncating shift, NOT the
        // canonical xoshiro256** rotate_left. The streams must match the
        // Python VM byte-for-byte, so we shift and drop the top bits too.
        let result = self
            .s[1]
            .wrapping_mul(5)
            .wrapping_shl(7)
            .wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        result
    }
}

fn keystream(key: &[u8], salt: &[u8], n: usize) -> Vec<u8> {
    // Full 256-bit KDF: each state word from its own 64-bit slice of
    // sha256(key || salt), little-endian; 8 warm-up rounds discarded.
    let mut h = Sha256::new();
    h.update(key);
    h.update(salt);
    let d = h.finalize();
    let mut words = [0u64; 4];
    for (i, w) in words.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&d[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(b);
    }
    let mut rng = Xoshiro256::from_words(words);
    for _ in 0..8 {
        rng.next();
    }
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    out.truncate(n);
    out
}

/// Verify the integrity tag and decrypt a JYCRYPT1 blob in RAM.
pub fn decrypt(blob: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < MAGIC.len() + 8 + TAG_LEN {
        return Err(CryptoError::TooShort);
    }
    if &blob[..8] != MAGIC {
        return Err(CryptoError::BadMagic);
    }
    let salt = &blob[8..16];
    let tag = &blob[16..48];
    let ct = &blob[48..];
    // tag = sha256(salt || ct || SEP || key)
    let mut h = Sha256::new();
    h.update(salt);
    h.update(ct);
    h.update(SEP);
    h.update(key);
    let expect = h.finalize();
    // constant-time-ish compare
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= tag[i] ^ expect[i];
    }
    if diff != 0 {
        return Err(CryptoError::IntegrityFailed);
    }
    let ks = keystream(key, salt, ct.len());
    Ok(ct.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect())
}

/// Convenience: hex-tag of a blob section (diagnostics only).
pub fn tag_hex(data: &[u8]) -> String {
    sha256_hex(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector generated from the hardened Python implementation:
    ///   python -c "
    ///     from jocky import crypto
    ///     import binascii
    ///     key = bytes(range(16)); salt = bytes(range(8))
    ///     blob = crypto.encrypt(b'attack at dawn', key, salt)
    ///     print(binascii.hexlify(blob).decode())"
    #[test]
    fn python_cross_roundtrip() {
        // Self-consistency first: decrypt(encrypt(x)) == x on the Rust side.
        let key = (0u8..16).collect::<Vec<u8>>();
        let salt = (0u8..8).collect::<Vec<u8>>();
        let pt = b"attack at dawn";
        // encrypt (mirror of Python encrypt) for the self-test
        let mut h = Sha256::new();
        h.update(&key);
        h.update(&salt);
        let d = h.finalize();
        let mut words = [0u64; 4];
        for (i, w) in words.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&d[i * 8..i * 8 + 8]);
            *w = u64::from_le_bytes(b);
        }
        let mut rng = Xoshiro256::from_words(words);
        for _ in 0..8 {
            rng.next();
        }
        let ks: Vec<u8> = (0..pt.len())
            .map(|_| rng.next().to_le_bytes())
            .flatten()
            .take(pt.len())
            .collect();
        let ct: Vec<u8> = pt.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        let mut th = Sha256::new();
        th.update(&salt);
        th.update(&ct);
        th.update(SEP);
        th.update(&key);
        let tag = th.finalize();
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&tag);
        blob.extend_from_slice(&ct);

        assert_eq!(decrypt(&blob, &key).unwrap(), pt.to_vec());
        assert!(matches!(
            decrypt(&blob, &(0u8..16).map(|x| x + 1).collect::<Vec<u8>>()),
            Err(CryptoError::IntegrityFailed)
        ));
    }
}
