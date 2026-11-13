"""AES-GCM initialisation vectors for SRTP and SRTCP (RFC 7714 sec. 8.1 and sec. 9.1).

Only the IV formation is here; protecting and unprotecting whole packets is the ``transform``
row that is still open.
"""

from __future__ import annotations

__all__ = ["srtcp_iv", "srtp_iv"]


def _check_salt(salt: bytes) -> None:
    if len(salt) != 12:
        raise ValueError("the AEAD session salt is 96 bits (12 octets)")


def srtp_iv(salt: bytes, ssrc: int, roc: int, seq: int) -> bytes:
    """``(0x0000 || SSRC || ROC || SEQ) XOR salt``, 12 octets (RFC 7714 sec. 8.1)."""
    _check_salt(salt)
    if not (0 <= ssrc < 1 << 32 and 0 <= roc < 1 << 32 and 0 <= seq < 1 << 16):
        raise ValueError("SSRC and ROC are 32 bits and SEQ is 16 bits")
    block = (ssrc << 48) | (roc << 16) | seq
    return (block ^ int.from_bytes(salt, "big")).to_bytes(12, "big")


def srtcp_iv(salt: bytes, ssrc: int, srtcp_index: int) -> bytes:
    """``(0x0000 || SSRC || 0x0000 || 0 || SRTCP index) XOR salt`` (RFC 7714 sec. 9.1).

    The index is the 31-bit SRTCP index, right-justified in a 32-bit field with a zero bit
    prepended; the E-flag is not part of the IV.
    """
    _check_salt(salt)
    if not (0 <= ssrc < 1 << 32 and 0 <= srtcp_index < 1 << 31):
        raise ValueError("SSRC is 32 bits and the SRTCP index 31 bits")
    block = (ssrc << 48) | srtcp_index
    return (block ^ int.from_bytes(salt, "big")).to_bytes(12, "big")
