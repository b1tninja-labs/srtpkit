"""the SRTP key derivation function (RFC 3711 sec. 4.3, RFC 6188 sec. 3, RFC 7714 sec. 11).

``derive`` is PRF_n of RFC 3711 sec. 4.3.1 with the AES-CM PRF of sec. 4.3.3. The master key's
length selects AES_128_CM_PRF, AES_192_CM_PRF or AES_256_CM_PRF (RFC 6188 sec. 3). It insists on a
112-bit master salt, because the AEAD profiles' 96-bit salt must first be widened by 2^16
(RFC 7714 erratum 4938) and a KDF that silently accepted 12 octets would derive wrong keys that
only another implementation could notice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import aescm
from .params import Profile

__all__ = ["SessionKeys", "derive", "derive_session_keys", "widen_aead_salt"]

# RFC 3711 sec. 4.3.1 and 4.3.2 labels.
LABEL_SRTP_ENCRYPTION = 0x00
LABEL_SRTP_AUTHENTICATION = 0x01
LABEL_SRTP_SALT = 0x02
LABEL_SRTCP_ENCRYPTION = 0x03
LABEL_SRTCP_AUTHENTICATION = 0x04
LABEL_SRTCP_SALT = 0x05


def widen_aead_salt(salt: bytes) -> bytes:
    """Widen a 96-bit master salt to the 112 bits the KDF expects, RFC 7714 erratum 4938.

    "the 96-bit master salt ... must be multiplied by 2^16": two zero octets on the right.
    """
    if len(salt) != 12:
        raise ValueError("an AEAD master salt is 96 bits (12 octets)")
    return salt + b"\x00\x00"


def derive(
    master_key: bytes,
    master_salt: bytes,
    label: int,
    length: int,
    *,
    index: int = 0,
    kdr: int = 0,
) -> bytes:
    """Derive ``length`` octets of the key with ``label``, RFC 3711 sec. 4.3.1.

    ``x = (label || (index DIV kdr)) XOR master_salt`` right-aligned, and the output is
    ``AES-CM(master_key, IV = x * 2^16)`` truncated to ``length`` octets. ``kdr`` zero means the
    derivation happens once and ``index DIV 0 = 0``. For SRTCP pass the SRTCP index as ``index``
    with labels 0x03 to 0x05; it is a 48-bit quantity, the reading of RFC 3711 erratum 3712 (held
    for document update) that libsrtp implements, which only matters when ``kdr`` is non-zero.
    """
    if len(master_salt) != 14:
        raise ValueError(
            "the KDF master salt is 112 bits; widen a 96-bit AEAD salt with widen_aead_salt()"
        )
    if not 0 <= label <= 0xFF:
        raise ValueError("label is 8 bits")
    if not 0 <= index < 1 << 48 or kdr < 0:
        raise ValueError("index is 48 bits and the key derivation rate is not negative")
    r = index // kdr if kdr else 0
    x = ((label << 48) | r) ^ int.from_bytes(master_salt, "big")
    return aescm.keystream(master_key, (x << 16).to_bytes(16, "big"), length)


@dataclass(frozen=True)
class SessionKeys:
    """The three session values for one direction and one protocol (SRTP or SRTCP)."""

    encryption_key: bytes = field(repr=False)
    authentication_key: bytes = field(repr=False)
    salt: bytes = field(repr=False)


def derive_session_keys(
    profile: Profile,
    master_key: bytes,
    master_salt: bytes,
    *,
    srtcp: bool = False,
    index: int = 0,
    kdr: int = 0,
) -> SessionKeys:
    """Derive the session keys of ``profile`` from a master key and salt, RFC 3711 sec. 4.3.

    ``master_salt`` has the profile's own width (14 octets for AES-CM, 12 for AES-GCM, widened
    here). The SRTCP labels 0x03 to 0x05 are used when ``srtcp`` is true (sec. 4.3.2). The
    NULL-cipher profiles raise ``NotImplementedError``: RFC 5764 gives them a zero-length cipher
    key, so there is no AES key to run the PRF with.
    """
    if profile.cipher == "NULL":
        raise NotImplementedError("NULL-cipher profiles: no master key to run the PRF (RFC 5764)")
    if len(master_key) * 8 != profile.key_bits or len(master_salt) * 8 != profile.salt_bits:
        raise ValueError("master key or salt length does not match the profile")
    kdf_salt = widen_aead_salt(master_salt) if profile.salt_bits == 96 else master_salt
    labels = (
        (LABEL_SRTCP_ENCRYPTION, LABEL_SRTCP_AUTHENTICATION, LABEL_SRTCP_SALT)
        if srtcp
        else (LABEL_SRTP_ENCRYPTION, LABEL_SRTP_AUTHENTICATION, LABEL_SRTP_SALT)
    )

    def one(label: int, bits: int) -> bytes:
        if not bits:
            return b""
        return derive(master_key, kdf_salt, label, bits // 8, index=index, kdr=kdr)

    return SessionKeys(
        one(labels[0], profile.key_bits),
        one(labels[1], profile.auth_key_bits),
        one(labels[2], profile.salt_bits),
    )
