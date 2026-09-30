"""Custom, dependency-free encryption for JOCKY payloads.

Design (per SIH requirement "custom encryption"):
  - A keyed PRNG stream cipher: Xoshiro256** seeded from sha256(key || salt)
    generates a keystream that is XORed with the plaintext.
  - Every blob carries a random 8-byte salt and a keyed integrity tag
    (sha256(salt || ciphertext || domain-separator || key)) so tampering or
    a wrong key is detected before the payload is handed to the VM.
  - Blob layout:  MAGIC(8) | salt(8) | tag(32) | ciphertext

The keystream is an XOR stream (fast, portable, dependency-free). For
production deployment the native component can swap this for hardware AES
without changing the blob format (see docs/architecture.md).
"""

from __future__ import annotations

import hashlib
import os
import struct

MAGIC = b"JYCRYPT1"
TAG_LEN = 32


class CryptoError(ValueError):
    pass


class _Xoshiro256:
    """Xoshiro256** PRNG -- small, fast, well-distributed, no dependencies."""

    def __init__(self, seed: int):
        # expand one seed into 4 state words with splitmix64
        self.s = [0] * 4
        x = seed & 0xFFFFFFFFFFFFFFFF
        for i in range(4):
            x = (x + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
            z = x
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
            z = (z ^ (z >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
            self.s[i] = z ^ (z >> 31)

    @classmethod
    def from_words(cls, words):
        """Seed directly from four 64-bit state words (all-zero rejected)."""
        if len(words) != 4 or not any(words):
            raise ValueError("xoshiro state must be four non-zero words")
        obj = cls.__new__(cls)
        obj.s = [w & 0xFFFFFFFFFFFFFFFF for w in words]
        return obj

    def next(self) -> int:
        s0, s1, s2, s3 = self.s
        result = ((s1 * 5 & 0xFFFFFFFFFFFFFFFF) << 7 & 0xFFFFFFFFFFFFFFFF)
        result = ((result * 9) & 0xFFFFFFFFFFFFFFFF)
        t = (s1 << 17) & 0xFFFFFFFFFFFFFFFF
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= t
        self.s = [s0, s1, s2, s3]
        return result & 0xFFFFFFFFFFFFFFFF


def _keystream(key: bytes, salt: bytes, n: int) -> bytes:
    # Full 256-bit KDF: each state word comes from its own 64-bit slice of
    # sha256(key || salt), so the stream is keyed by the entire digest
    # (the old 64-bit single-seed derivation was brute-forceable).
    d = hashlib.sha256(key + salt).digest()
    rng = _Xoshiro256.from_words(
        [int.from_bytes(d[i * 8:(i + 1) * 8], "little") for i in range(4)])
    for _ in range(8):        # warm-up discards decouple state from output
        rng.next()
    out = bytearray()
    while len(out) < n:
        out += rng.next().to_bytes(8, "little")
    return bytes(out[:n])


def new_key() -> bytes:
    """Generate a 32-byte payload key."""
    return os.urandom(32)


def encrypt(plaintext: bytes, key: bytes, salt: bytes | None = None) -> bytes:
    """Encrypt `plaintext` into a self-contained JYCRYPT1 blob."""
    if not isinstance(key, bytes) or len(key) < 16:
        raise CryptoError("key must be bytes and at least 16 bytes long")
    salt = salt or os.urandom(8)
    stream = _keystream(key, salt, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hashlib.sha256(salt + ct + b"JOCKY:" + key).digest()
    return MAGIC + salt + tag + ct


def decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypt a JYCRYPT1 blob, verifying integrity. Raises CryptoError."""
    if len(blob) < len(MAGIC) + 8 + TAG_LEN:
        raise CryptoError("blob too short")
    if blob[: len(MAGIC)] != MAGIC:
        raise CryptoError("bad magic: not a JYCRYPT1 blob")
    salt = blob[len(MAGIC):len(MAGIC) + 8]
    tag = blob[len(MAGIC) + 8:len(MAGIC) + 8 + TAG_LEN]
    ct = blob[len(MAGIC) + 8 + TAG_LEN:]
    expect = hashlib.sha256(salt + ct + b"JOCKY:" + key).digest()
    if tag != expect:
        raise CryptoError("integrity check failed (wrong key or tampered blob)")
    stream = _keystream(key, salt, len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream))


def key_from_hex(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)