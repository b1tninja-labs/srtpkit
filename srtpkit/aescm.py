"""AES in segmented integer counter mode, the SRTP default cipher (RFC 3711 sec. 4.1.1, RFC 6188).

The block cipher is ``cryptography``'s AES; its CTR mode increments the whole 128-bit counter,
which is the ``E(k, IV + i mod 2^128)`` of the RFC. The same code serves AES-128, AES-192 and
AES-256 (RFC 6188 sec. 2): the key length chooses the cipher. Everything around the block cipher,
the IV layout and the segment limit, is ours.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ["MAX_BLOCKS", "crypt", "iv", "keystream"]

MAX_BLOCKS = 1 << 16  # RFC 3711 sec. 4.1.1 paragraph 9: at most 2^16 blocks per IV
_KEY_SIZES = (16, 24, 32)


def keystream(key: bytes, counter: bytes, length: int) -> bytes:
    """The first ``length`` octets of ``E(k, IV) || E(k, IV+1) || ...`` for a 16-octet ``IV``."""
    if len(key) not in _KEY_SIZES:
        raise ValueError("AES key must be 16, 24 or 32 octets")
    if len(counter) != 16:
        raise ValueError("the counter block is 16 octets")
    if not 0 <= length <= MAX_BLOCKS * 16:
        raise ValueError("a keystream segment is at most 2^16 blocks (RFC 3711 sec. 4.1.1)")
    encryptor = Cipher(algorithms.AES(key), modes.CTR(counter)).encryptor()
    return encryptor.update(bytes(length)) + encryptor.finalize()


def iv(salt: bytes, ssrc: int, index: int) -> bytes:
    """``IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)``, RFC 3711 sec. 4.1.1 paragraph 5.

    ``salt`` is the 14-octet session salting key; ``index`` is the 48-bit SRTP index or the
    31-bit SRTCP index. Each term is zero-extended to 128 bits.
    """
    if len(salt) != 14:
        raise ValueError("the AES-CM session salt is 14 octets (112 bits)")
    if not 0 <= ssrc < 1 << 32 or not 0 <= index < 1 << 48:
        raise ValueError("SSRC is 32 bits and the packet index 48 bits")
    value = (int.from_bytes(salt, "big") << 16) ^ (ssrc << 64) ^ (index << 16)
    return value.to_bytes(16, "big")


def crypt(session_key: bytes, session_salt: bytes, ssrc: int, index: int, data: bytes) -> bytes:
    """Encrypt or decrypt ``data`` with the AES-CM keystream for ``(ssrc, index)``.

    XOR with the keystream is its own inverse, so one function does both (RFC 3711 sec. 4.1
    paragraph 4); excess keystream bits are discarded. For SRTCP pass the SSRC of the first
    header of the compound packet and the 31-bit SRTCP index (sec. 4.1.1 paragraph 8).
    """
    stream = keystream(session_key, iv(session_salt, ssrc, index), len(data))
    return bytes(a ^ b for a, b in zip(data, stream, strict=True))
