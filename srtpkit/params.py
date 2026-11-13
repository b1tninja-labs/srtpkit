"""session parameters: cipher, auth, key and salt lengths (RFC 3711, RFC 5764, RFC 7714).

The table is the DTLS-SRTP protection profiles of RFC 5764 sec. 4.1.2 and RFC 7714 sec. 14.2.
``select_profile`` applies this library's negotiation policy, which is a convention and not a
document: the AES-CM profile with an 80-bit tag and the two AES-GCM profiles are negotiable by
default; the 32-bit-tag profile needs ``allow_legacy`` and the NULL-cipher profiles need
``allow_null``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

__all__ = [
    "PROFILES",
    "NoCommonProfileError",
    "Profile",
    "UnknownProfileError",
    "profile",
    "select_profile",
]


class UnknownProfileError(KeyError):
    """A protection profile identifier that is not in the table."""


class NoCommonProfileError(ValueError):
    """No offered profile is both known and allowed by the policy."""


@dataclass(frozen=True)
class Profile:
    """The transform parameters of one DTLS-SRTP protection profile.

    Lengths are in bits except ``aead_tag_bytes``. ``kdf_salt_bits`` is the width of the master
    salt the RFC 3711 KDF consumes: 112 for every profile, which for the 96-bit AEAD salts means
    widening by 2^16 (RFC 7714 erratum 4938).
    """

    dtls_id: int
    name: str
    cipher: Literal["AES_CM", "AES_GCM", "NULL"]
    key_bits: int
    salt_bits: int
    kdf_salt_bits: int
    auth_function: Literal["HMAC-SHA1", "NULL"]
    auth_key_bits: int
    srtp_tag_bits: int
    srtcp_tag_bits: int
    aead_tag_bytes: int
    max_srtp_packets: int
    max_srtcp_packets: int
    legacy: bool = False
    null_cipher: bool = False


def _hmac(
    dtls_id: int,
    name: str,
    cipher: Literal["AES_CM", "NULL"],
    srtp_tag_bits: int,
    *,
    legacy: bool,
) -> Profile:
    # RFC 5764 sec. 4.1.2: HMAC-SHA1 with a 160-bit key, maximum_lifetime 2^31, and the 32-bit-tag
    # profiles list "RTCP auth_tag_length: 80".
    aes = cipher == "AES_CM"
    return Profile(
        dtls_id,
        name,
        cipher,
        key_bits=128 if aes else 0,
        salt_bits=112 if aes else 0,
        kdf_salt_bits=112,
        auth_function="HMAC-SHA1",
        auth_key_bits=160,
        srtp_tag_bits=srtp_tag_bits,
        srtcp_tag_bits=80,
        aead_tag_bytes=0,
        max_srtp_packets=2**31,
        max_srtcp_packets=2**31,
        legacy=legacy,
        null_cipher=not aes,
    )


def _gcm(dtls_id: int, name: str, key_bits: int) -> Profile:
    # RFC 7714 sec. 14.2: 96-bit salt, 16-octet AEAD tag, no auth function, at most 2^31 SRTCP and
    # 2^48 SRTP packets. The KDF still takes a 112-bit salt (erratum 4938).
    return Profile(
        dtls_id,
        name,
        "AES_GCM",
        key_bits=key_bits,
        salt_bits=96,
        kdf_salt_bits=112,
        auth_function="NULL",
        auth_key_bits=0,
        srtp_tag_bits=0,
        srtcp_tag_bits=0,
        aead_tag_bytes=16,
        max_srtp_packets=2**48,
        max_srtcp_packets=2**31,
    )


PROFILES: Mapping[int, Profile] = {
    p.dtls_id: p
    for p in (
        _hmac(0x0001, "SRTP_AES128_CM_HMAC_SHA1_80", "AES_CM", 80, legacy=False),
        _hmac(0x0002, "SRTP_AES128_CM_HMAC_SHA1_32", "AES_CM", 32, legacy=True),
        _hmac(0x0005, "SRTP_NULL_HMAC_SHA1_80", "NULL", 80, legacy=True),
        _hmac(0x0006, "SRTP_NULL_HMAC_SHA1_32", "NULL", 32, legacy=True),
        _gcm(0x0007, "SRTP_AEAD_AES_128_GCM", 128),
        _gcm(0x0008, "SRTP_AEAD_AES_256_GCM", 256),
    )
}


def profile(dtls_id: int) -> Profile:
    """Return the profile registered under ``dtls_id`` or raise ``UnknownProfileError``."""
    try:
        return PROFILES[dtls_id]
    except KeyError:
        raise UnknownProfileError(f"SRTP protection profile {dtls_id:#06x}") from None


def select_profile(
    offered: Sequence[int], *, allow_legacy: bool = False, allow_null: bool = False
) -> Profile:
    """Pick the first of ``offered`` that is known and allowed, RFC 3711, RFC 7714.

    The identifiers and the 80- and 32-bit tag profiles are RFC 5764 sec. 4.1.2.

    ``offered`` is in the caller's own order of preference, so a policy that wants AES-GCM first
    lists 0x0007 and 0x0008 first. Unknown identifiers are skipped, not fatal, and duplicates
    change nothing. A NULL-cipher profile is refused unless ``allow_null`` is set, and the
    32-bit-tag AES-CM profile is refused unless ``allow_legacy`` is set.
    """
    for dtls_id in offered:
        found = PROFILES.get(dtls_id)
        if found is None:
            continue
        if found.null_cipher:
            if not allow_null:
                continue
        elif found.legacy and not allow_legacy:
            continue
        return found
    raise NoCommonProfileError("no offered SRTP protection profile is allowed by the policy")
