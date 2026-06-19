"""
Pure-Python implementation of the NIST SP 800-232 Ascon-AEAD128 and
Ascon-Hash256 core used by this educational secure sensor log project.

Important scope note:
- This file is intended for reproducible coursework experiments.
- It is not constant-time Python code and should not be used as a production
  cryptographic library.
- Algorithm structure follows the public reference design of Ascon-AEAD128
  (formerly Ascon-128a) and Ascon-Hash256 (formerly Ascon-Hash).
"""
from __future__ import annotations

import hmac

MASK64 = (1 << 64) - 1

ASCON_AEAD_VARIANT = 1
ASCON_HASH_VARIANT = 2
ASCON_TAG_SIZE = 16
ASCON_HASH_SIZE = 32
ASCON_128A_RATE = 16
ASCON_HASH_RATE = 8
ASCON_PA_ROUNDS = 12
ASCON_128A_PB_ROUNDS = 8
ASCON_HASH_PB_ROUNDS = 12

ASCON_128A_IV = (
    (ASCON_AEAD_VARIANT << 0)
    | (ASCON_PA_ROUNDS << 16)
    | (ASCON_128A_PB_ROUNDS << 20)
    | ((ASCON_TAG_SIZE * 8) << 24)
    | (ASCON_128A_RATE << 40)
)

ASCON_HASH_IV = (
    (ASCON_HASH_VARIANT << 0)
    | (ASCON_PA_ROUNDS << 16)
    | (ASCON_HASH_PB_ROUNDS << 20)
    | ((ASCON_HASH_SIZE * 8) << 24)
    | (ASCON_HASH_RATE << 40)
)

ROUND_CONSTANTS_12 = [0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B]


class AsconAuthenticationError(Exception):
    """Raised when AEAD tag verification fails."""


def _ror(x: int, n: int) -> int:
    x &= MASK64
    return ((x >> n) | ((x << ((-n) & 63)) & MASK64)) & MASK64


def _load_bytes(data: bytes, n: int | None = None) -> int:
    if n is None:
        n = len(data)
    x = 0
    for i in range(n):
        x |= data[i] << (8 * i)
    return x & MASK64


def _store_bytes(x: int, n: int) -> bytes:
    x &= MASK64
    return bytes((x >> (8 * i)) & 0xFF for i in range(n))


def _pad(i: int) -> int:
    return 0x01 << (8 * i)


def _dsep() -> int:
    return 0x80 << (8 * 7)


def _clear_bytes(x: int, n: int) -> int:
    x &= MASK64
    for i in range(n):
        x &= ~(0xFF << (8 * i)) & MASK64
    return x & MASK64


def _round(state: list[int], c: int) -> None:
    x0, x1, x2, x3, x4 = state

    # Addition of round constant.
    x2 ^= c

    # Substitution layer.
    x0 ^= x4
    x4 ^= x3
    x2 ^= x1

    t0 = x0 ^ (((~x1) & MASK64) & x2)
    t1 = x1 ^ (((~x2) & MASK64) & x3)
    t2 = x2 ^ (((~x3) & MASK64) & x4)
    t3 = x3 ^ (((~x4) & MASK64) & x0)
    t4 = x4 ^ (((~x0) & MASK64) & x1)

    t1 ^= t0
    t0 ^= t4
    t3 ^= t2
    t2 = (~t2) & MASK64

    # Linear diffusion layer.
    state[0] = (t0 ^ _ror(t0, 19) ^ _ror(t0, 28)) & MASK64
    state[1] = (t1 ^ _ror(t1, 61) ^ _ror(t1, 39)) & MASK64
    state[2] = (t2 ^ _ror(t2, 1) ^ _ror(t2, 6)) & MASK64
    state[3] = (t3 ^ _ror(t3, 10) ^ _ror(t3, 17)) & MASK64
    state[4] = (t4 ^ _ror(t4, 7) ^ _ror(t4, 41)) & MASK64


def _permute(state: list[int], rounds: int) -> None:
    if rounds not in (6, 8, 12):
        raise ValueError("Ascon permutation rounds must be 6, 8, or 12")
    for c in ROUND_CONSTANTS_12[12 - rounds :]:
        _round(state, c)


def ascon_aead128_encrypt(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Return ciphertext || 16-byte authentication tag."""
    if len(key) != 16:
        raise ValueError("Ascon-AEAD128 key must be 16 bytes")
    if len(nonce) != 16:
        raise ValueError("Ascon-AEAD128 nonce must be 16 bytes")

    k0 = _load_bytes(key[:8])
    k1 = _load_bytes(key[8:])
    n0 = _load_bytes(nonce[:8])
    n1 = _load_bytes(nonce[8:])

    s = [ASCON_128A_IV, k0, k1, n0, n1]
    _permute(s, 12)
    s[3] ^= k0
    s[4] ^= k1

    ad = associated_data
    if len(ad):
        while len(ad) >= ASCON_128A_RATE:
            s[0] ^= _load_bytes(ad[:8])
            s[1] ^= _load_bytes(ad[8:16])
            _permute(s, 8)
            ad = ad[ASCON_128A_RATE:]
        if len(ad) >= 8:
            s[0] ^= _load_bytes(ad[:8])
            s[1] ^= _load_bytes(ad[8:])
            s[1] ^= _pad(len(ad) - 8)
        else:
            s[0] ^= _load_bytes(ad)
            s[0] ^= _pad(len(ad))
        _permute(s, 8)

    s[4] ^= _dsep()

    m = plaintext
    out = bytearray()
    while len(m) >= ASCON_128A_RATE:
        s[0] ^= _load_bytes(m[:8])
        s[1] ^= _load_bytes(m[8:16])
        out.extend(_store_bytes(s[0], 8))
        out.extend(_store_bytes(s[1], 8))
        _permute(s, 8)
        m = m[ASCON_128A_RATE:]

    if len(m) >= 8:
        s[0] ^= _load_bytes(m[:8])
        s[1] ^= _load_bytes(m[8:])
        out.extend(_store_bytes(s[0], 8))
        out.extend(_store_bytes(s[1], len(m) - 8))
        s[1] ^= _pad(len(m) - 8)
    else:
        s[0] ^= _load_bytes(m)
        out.extend(_store_bytes(s[0], len(m)))
        s[0] ^= _pad(len(m))

    s[2] ^= k0
    s[3] ^= k1
    _permute(s, 12)
    s[3] ^= k0
    s[4] ^= k1

    out.extend(_store_bytes(s[3], 8))
    out.extend(_store_bytes(s[4], 8))
    return bytes(out)


def ascon_aead128_decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, associated_data: bytes = b"") -> bytes:
    """Verify tag and return plaintext. Raises AsconAuthenticationError on failure."""
    if len(key) != 16:
        raise ValueError("Ascon-AEAD128 key must be 16 bytes")
    if len(nonce) != 16:
        raise ValueError("Ascon-AEAD128 nonce must be 16 bytes")
    if len(ciphertext_and_tag) < ASCON_TAG_SIZE:
        raise AsconAuthenticationError("ciphertext is shorter than authentication tag")

    c = ciphertext_and_tag[:-ASCON_TAG_SIZE]
    tag = ciphertext_and_tag[-ASCON_TAG_SIZE:]

    k0 = _load_bytes(key[:8])
    k1 = _load_bytes(key[8:])
    n0 = _load_bytes(nonce[:8])
    n1 = _load_bytes(nonce[8:])

    s = [ASCON_128A_IV, k0, k1, n0, n1]
    _permute(s, 12)
    s[3] ^= k0
    s[4] ^= k1

    ad = associated_data
    if len(ad):
        while len(ad) >= ASCON_128A_RATE:
            s[0] ^= _load_bytes(ad[:8])
            s[1] ^= _load_bytes(ad[8:16])
            _permute(s, 8)
            ad = ad[ASCON_128A_RATE:]
        if len(ad) >= 8:
            s[0] ^= _load_bytes(ad[:8])
            s[1] ^= _load_bytes(ad[8:])
            s[1] ^= _pad(len(ad) - 8)
        else:
            s[0] ^= _load_bytes(ad)
            s[0] ^= _pad(len(ad))
        _permute(s, 8)

    s[4] ^= _dsep()

    out = bytearray()
    ct = c
    while len(ct) >= ASCON_128A_RATE:
        c0 = _load_bytes(ct[:8])
        c1 = _load_bytes(ct[8:16])
        out.extend(_store_bytes(s[0] ^ c0, 8))
        out.extend(_store_bytes(s[1] ^ c1, 8))
        s[0] = c0
        s[1] = c1
        _permute(s, 8)
        ct = ct[ASCON_128A_RATE:]

    if len(ct) >= 8:
        c0 = _load_bytes(ct[:8])
        c1 = _load_bytes(ct[8:])
        out.extend(_store_bytes(s[0] ^ c0, 8))
        out.extend(_store_bytes(s[1] ^ c1, len(ct) - 8))
        s[0] = c0
        s[1] = _clear_bytes(s[1], len(ct) - 8)
        s[1] |= c1
        s[1] ^= _pad(len(ct) - 8)
    else:
        c0 = _load_bytes(ct)
        out.extend(_store_bytes(s[0] ^ c0, len(ct)))
        s[0] = _clear_bytes(s[0], len(ct))
        s[0] |= c0
        s[0] ^= _pad(len(ct))

    s[2] ^= k0
    s[3] ^= k1
    _permute(s, 12)
    s[3] ^= k0
    s[4] ^= k1

    expected_tag = _store_bytes(s[3], 8) + _store_bytes(s[4], 8)
    if not hmac.compare_digest(tag, expected_tag):
        raise AsconAuthenticationError("authentication tag verification failed")
    return bytes(out)


def ascon_hash256(message: bytes) -> bytes:
    """Return 32-byte Ascon-Hash256 digest."""
    s = [ASCON_HASH_IV, 0, 0, 0, 0]
    _permute(s, 12)

    m = message
    while len(m) >= ASCON_HASH_RATE:
        s[0] ^= _load_bytes(m[:8])
        _permute(s, 12)
        m = m[ASCON_HASH_RATE:]

    s[0] ^= _load_bytes(m)
    s[0] ^= _pad(len(m))
    _permute(s, 12)

    out = bytearray()
    remaining = ASCON_HASH_SIZE
    while remaining > ASCON_HASH_RATE:
        out.extend(_store_bytes(s[0], 8))
        _permute(s, 12)
        remaining -= ASCON_HASH_RATE
    out.extend(_store_bytes(s[0], remaining))
    return bytes(out)


__all__ = [
    "AsconAuthenticationError",
    "ascon_aead128_encrypt",
    "ascon_aead128_decrypt",
    "ascon_hash256",
]
