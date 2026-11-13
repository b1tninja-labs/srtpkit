"""SRTCP packet protection (RFC 3711 sec. 3.4, RFC 7714 sec. 9).

An SRTCP packet is the compound RTCP packet with its payload (from the ninth octet) encrypted, then
the 32-bit E-flag and 31-bit SRTCP index, then, for AES-CM, an authentication tag. The first eight
octets, the header and the SSRC of the first packet, are never encrypted.

* AES-CM: encrypted portion ``packet[8:]`` with the AES-CM keystream for ``(SSRC, SRTCP index)``;
  tag over ``packet[:8] || encrypted || E+index``, 80 bits for every profile (RFC 5764 sec. 4.1.2
  lists "RTCP auth_tag_length: 80" for the 32-bit-tag profiles). No ROC is appended (sec. 4.2).
* AES-GCM (RFC 7714 sec. 9.2, sec. 9.3): with E=1 the associated data is ``packet[:8] || E+index``
  and the plaintext ``packet[8:]``; with E=0 there is no plaintext and the associated data is the
  whole packet and ``E+index``, the lone 16-octet tag following the packet. In both forms the
  output is ``packet[:8] || ciphertext-with-tag || E+index``, the index last (sec. 9.2 para 8).

The sender uses ``ctx.srtcp_index`` and increments it modulo 2^31 after each packet (sec. 3.4
paragraph 8); the receiver reads the index from the packet and keeps its own replay window.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import aescm, gcm
from .context import StreamContext
from .errors import AuthenticationError, KeyLifetimeError, ReplayError, SrtpError

__all__ = ["protect_rtcp", "unprotect_rtcp"]

_E_FLAG = 1 << 31
_TAG_BYTES = 10  # 80 bits, sec. 4.2.1 truncation, RFC 5764 sec. 4.1.2
_HEADER = 8


def _ssrc(packet: bytes) -> int:
    if len(packet) < _HEADER:
        raise SrtpError("RTCP packet is shorter than its 8-octet header and SSRC")
    if packet[0] >> 6 != 2:
        raise SrtpError(f"RTCP version {packet[0] >> 6} is not 2")
    return int(struct.unpack_from(">I", packet, 4)[0])


def _tag(ctx: StreamContext, portion: bytes) -> bytes:
    key = ctx.keys.srtcp.authentication_key
    return hmac.new(key, portion, hashlib.sha1).digest()[:_TAG_BYTES]


def _crypt(ctx: StreamContext, index: int, data: bytes) -> bytes:
    if ctx.keys.profile.cipher == "NULL":
        return data
    keys = ctx.keys.srtcp
    return aescm.crypt(keys.encryption_key, keys.salt, ctx.ssrc, index, data)


def protect_rtcp(packet: bytes, ctx: StreamContext, *, encrypt: bool = True) -> bytes:
    """Protect one RTCP compound packet, returning the SRTCP packet (RFC 3711 sec. 3.4).

    ``encrypt=False`` sets the E-flag to 0 and sends the payload in the clear, still
    authenticated. The SSRC of the first RTCP packet must be the context's.
    """
    profile = ctx.keys.profile
    if _ssrc(packet) != ctx.ssrc:
        raise SrtpError("the packet's SSRC is not the context's")
    if ctx.srtcp_packets >= profile.max_srtcp_packets:
        raise KeyLifetimeError("the key has protected its maximum number of SRTCP packets")
    index = ctx.srtcp_index
    word = struct.pack(">I", (_E_FLAG if encrypt else 0) | index)
    head, body = packet[:_HEADER], packet[_HEADER:]
    if profile.cipher == "AES_GCM":
        iv = gcm.srtcp_iv(ctx.keys.srtcp.salt, ctx.ssrc, index)
        aead = AESGCM(ctx.keys.srtcp.encryption_key)
        if encrypt:
            out = head + aead.encrypt(iv, body, head + word) + word
        else:
            out = packet + aead.encrypt(iv, b"", packet + word) + word
    else:
        sealed = head + (_crypt(ctx, index, body) if encrypt else body) + word
        out = sealed + _tag(ctx, sealed)
    ctx.srtcp_index = (index + 1) % (1 << 31)
    ctx.srtcp_packets += 1
    return out


def unprotect_rtcp(packet: bytes, ctx: StreamContext) -> bytes:
    """Verify and decrypt one SRTCP packet, returning the RTCP packet (RFC 3711 sec. 3.4).

    Raises ``ReplayError``, ``AuthenticationError`` or ``SrtpError`` as ``transform.unprotect``
    does; the replay window moves only after the tag verified.
    """
    profile = ctx.keys.profile
    gcm_mode = profile.cipher == "AES_GCM"
    trailer = profile.aead_tag_bytes + 4 if gcm_mode else 4 + _TAG_BYTES
    if len(packet) < _HEADER + trailer:
        raise SrtpError("SRTCP packet is shorter than its header, index and tag")
    if _ssrc(packet) != ctx.ssrc:
        raise SrtpError("the packet's SSRC is not the context's")
    word_at = len(packet) - 4 if gcm_mode else len(packet) - _TAG_BYTES - 4
    (word,) = struct.unpack_from(">I", packet, word_at)
    encrypted, index = bool(word & _E_FLAG), word & ~_E_FLAG
    if not ctx.srtcp_replay.check(index):
        raise ReplayError("SRTCP index was already received or is too old")
    head, word_bytes = packet[:_HEADER], packet[word_at : word_at + 4]
    if gcm_mode:
        iv = gcm.srtcp_iv(ctx.keys.srtcp.salt, ctx.ssrc, index)
        aead = AESGCM(ctx.keys.srtcp.encryption_key)
        try:
            if encrypted:
                body = aead.decrypt(iv, packet[_HEADER:word_at], head + word_bytes)
                out = head + body
            else:
                tag = packet[word_at - profile.aead_tag_bytes : word_at]
                clear = packet[: word_at - profile.aead_tag_bytes]
                aead.decrypt(iv, tag, clear + word_bytes)
                out = clear
        except InvalidTag:
            raise AuthenticationError("AES-GCM authentication failure") from None
    else:
        sealed, tag = packet[:-_TAG_BYTES], packet[-_TAG_BYTES:]
        if not hmac.compare_digest(tag, _tag(ctx, sealed)):
            raise AuthenticationError("SRTCP authentication failure")
        body = sealed[_HEADER:word_at]
        out = head + (_crypt(ctx, index, body) if encrypted else body)
    ctx.srtcp_replay.accept(index)
    return out
