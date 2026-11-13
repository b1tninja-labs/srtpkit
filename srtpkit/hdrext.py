"""Encryption of selected RTP header extension elements in SRTP (RFC 6904).

Only the bodies of the elements the signalling names are encrypted. The element headers, the
padding, the other elements and the "defined by profile" and "length" fields stay in the clear
(sec. 3 paragraph 1, paragraph 7 to 10). The keystream is the one the payload cipher would produce
for the same packet index, run with two extra session values: ``k_he`` (label 0x06) and ``k_hs``
(label 0x07), derived from the same master key and salt (sec. 3 paragraph 2 to 5). The mask of
all-ones and all-zero octets selects which keystream octets apply, and the extension is
XORed with the masked keystream, so the operation is its own inverse.

* AES-CM profiles only. RFC 7714 sec. 8.3 says the AES-GCM profiles take their keystream "in the
  manner defined in RFC 6904, using the AES Counter Mode transform", but an AES-CM IV needs a
  112-bit salt and the derived AEAD salt (``n_s``) is 96 bits; neither document says how the two
  fit, so those profiles raise ``NotImplementedError`` instead of guessing. Cryptex (RFC 9335)
  covers them completely and is implemented.
* The element grammar is RFC 8285 sec. 4.1.2, sec. 4.2 and sec. 4.3: padding is a zero octet, the
  one-byte form has a 4-bit ID and a length that is the body size less one, ID 15 stops the
  parse, the two-byte form has an 8-bit ID and an 8-bit length. A malformed extension raises
  :class:`SrtpError`; nothing is half-encrypted.
* RFC 9335 sec. 5 forbids a packet that uses both Cryptex and RFC 6904.
* RFC 6904 Appendix A.2 says its mask selects "header extensions 1, 2, and 4" in the prose, but the
  mask it prints, and the sentence before it, select elements 1, 3 and 4 (element 2 is the
  plaintext transmission time offset of sec. 3.1). The tests follow the printed mask.
"""

from __future__ import annotations

from collections.abc import Collection

from . import aescm
from .errors import SrtpError
from .kdf import SessionKeys, derive, widen_aead_salt
from .params import Profile

__all__ = ["apply", "derive_header_keys", "encryption_mask", "extension_span"]

LABEL_HEADER_ENCRYPTION = 0x06  # RFC 6904 sec. 3 paragraph 3
LABEL_HEADER_SALT = 0x07  # RFC 6904 sec. 3 paragraph 4


def derive_header_keys(
    profile: Profile, master_key: bytes, master_salt: bytes, *, index: int = 0, kdr: int = 0
) -> SessionKeys:
    """``k_he`` and ``k_hs`` for ``profile`` (RFC 6904 sec. 3); the authentication key is empty.

    The sizes are the profile's own ``n_e`` and ``n_s`` (sec. 3 paragraph 5), and the index and
    key derivation rate are those of the payload keys. Raises ``NotImplementedError`` for a profile
    that is not AES-CM (see the module docstring).
    """
    if profile.cipher != "AES_CM":
        raise NotImplementedError(
            "RFC 6904 header extension encryption is implemented for AES-CM profiles only"
        )
    if len(master_key) * 8 != profile.key_bits or len(master_salt) * 8 != profile.salt_bits:
        raise ValueError("master key or salt length does not match the profile")
    salt = widen_aead_salt(master_salt) if profile.salt_bits == 96 else master_salt
    key = derive(
        master_key, salt, LABEL_HEADER_ENCRYPTION, profile.key_bits // 8, index=index, kdr=kdr
    )
    session_salt = derive(
        master_key, salt, LABEL_HEADER_SALT, profile.salt_bits // 8, index=index, kdr=kdr
    )
    return SessionKeys(key, b"", session_salt)


def encryption_mask(extension: bytes, encrypted: Collection[int], *, two_byte: bool) -> bytes:
    """The 0xFF/0x00 mask over ``extension`` (the octets after the 4-octet extension header).

    ``encrypted`` is the set of element IDs the signalling (sec. 4) marks as encrypted. Raises
    :class:`SrtpError` if an element runs past the end of the extension.
    """
    mask = bytearray(len(extension))
    position = 0
    while position < len(extension):
        first = extension[position]
        if first == 0:  # padding (RFC 8285 sec. 4.1.2 paragraph 5)
            position += 1
            continue
        if two_byte:
            if position + 2 > len(extension):
                raise SrtpError("header extension ends inside a two-byte element header")
            element_id, length, start = first, extension[position + 1], position + 2
        else:
            element_id, length, start = first >> 4, (first & 0x0F) + 1, position + 1
            if element_id == 15:  # reserved: processing terminates (sec. 4.2 paragraph 5)
                break
        if start + length > len(extension):
            raise SrtpError("header extension element runs past the end of the extension")
        if element_id in encrypted:
            mask[start : start + length] = b"\xff" * length
        position = start + length
    return bytes(mask)


def extension_span(head: bytes) -> tuple[int, int, bool]:
    """``(start, end, two_byte)`` of the extension proper in an RTP header, or raise ``SrtpError``.

    ``start`` follows the 4-octet extension header. A header without the X bit, or with a
    profile that is neither RFC 8285 framing, has no extension to encrypt.
    """
    if len(head) < 12 or not head[0] & 0x10:
        raise SrtpError("the packet has no header extension")
    base = 12 + 4 * (head[0] & 0x0F)
    profile = int.from_bytes(head[base : base + 2], "big")
    words = int.from_bytes(head[base + 2 : base + 4], "big")
    if profile == 0xBEDE:
        two_byte = False
    elif profile & 0xFFF0 == 0x1000:
        two_byte = True
    else:
        raise SrtpError("the header extension is not RFC 8285 one-byte or two-byte framing")
    start = base + 4
    if len(head) < start + 4 * words:
        raise SrtpError("RTP packet ends inside the header extension")
    return start, start + 4 * words, two_byte


def apply(
    head: bytes,
    keys: SessionKeys,
    ssrc: int,
    index: int,
    encrypted: Collection[int],
) -> bytes:
    """Encrypt or decrypt the marked elements of the RTP header ``head`` (RFC 6904 sec. 3).

    ``head`` is the header through the extension, ``index`` the 48-bit packet index the payload
    cipher uses (``ROC || SEQ``). The result is the header with those element bodies XORed with the
    masked keystream; applying it twice returns the input. A header with no extension is
    returned unchanged when ``encrypted`` is empty and refused otherwise.
    """
    if not encrypted:
        return head
    start, end, two_byte = extension_span(head)
    extension = head[start:end]
    mask = encryption_mask(extension, encrypted, two_byte=two_byte)
    stream = aescm.crypt(keys.encryption_key, keys.salt, ssrc, index, bytes(len(extension)))
    masked = bytes(s & m for s, m in zip(stream, mask, strict=True))
    changed = bytes(a ^ b for a, b in zip(extension, masked, strict=True))
    return head[:start] + changed + head[end:]
