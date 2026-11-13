"""SRTP packet protection: AES-CM with HMAC-SHA1 and AES-GCM (RFC 3711 sec. 3.3, RFC 7714 sec. 8).

``protect`` follows the sender steps of RFC 3711 sec. 3.3 and ``unprotect`` the receiver steps, in
that order: estimate the index, check the replay window, verify the tag, decrypt, and only then
update ROC, s_l and the replay list, so a forged packet changes nothing.

* AES-CM profiles (RFC 3711 sec. 4.1.1, sec. 4.2.1): the payload (everything after the RTP header,
  padding included) is XORed with the AES-CM keystream for ``(SSRC, index)``; the tag is
  HMAC-SHA1 over the header, the encrypted payload and the 32-bit ROC, cut to the profile's tag
  length (80 or 32 bits) and appended.
* AES-GCM profiles (RFC 7714 sec. 8): the header, with CSRC list and extension, is the associated
  data, the rest is the plaintext, and the 16-octet tag is part of the ciphertext at the end. There
  is no separate authentication tag (sec. 8.2 says one is NOT RECOMMENDED; it is not offered).
* NULL-cipher profiles copy the payload and authenticate it (RFC 3711 sec. 4.1.3). Their keys
  cannot be derived (see ROADMAP.md), so a context for one needs explicit session keys.

Not supported: the MKI, header extension encryption (RFC 6904), Cryptex (RFC 9335) and key
derivation rates above zero.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import aescm, gcm
from .context import StreamContext
from .errors import AuthenticationError, KeyLifetimeError, ReplayError, SrtpError
from .index import estimate, update
from .params import Profile
from .rtp import parse_header

__all__ = ["protect", "unprotect"]


def _auth_tag(profile: Profile, key: bytes, portion: bytes, roc: int) -> bytes:
    material = portion + roc.to_bytes(4, "big")  # M = Authenticated Portion || ROC (sec. 4.2)
    return hmac.new(key, material, hashlib.sha1).digest()[: profile.srtp_tag_bits // 8]


def _crypt(profile: Profile, ctx: StreamContext, index: int, data: bytes) -> bytes:
    if profile.cipher == "NULL":
        return data
    keys = ctx.keys.srtp
    return aescm.crypt(keys.encryption_key, keys.salt, ctx.ssrc, index, data)


def protect(packet: bytes, ctx: StreamContext) -> bytes:
    """Protect one RTP packet, returning the SRTP packet (RFC 3711 sec. 3.3, RFC 7714 sec. 8).

    The packet's SSRC must be the context's. Raises ``KeyLifetimeError`` once the key has
    protected the profile's maximum number of packets (sec. 3.3.1 paragraph 10).
    """
    profile = ctx.keys.profile
    header = parse_header(packet)
    if header.ssrc != ctx.ssrc:
        raise SrtpError("the packet's SSRC is not the context's")
    if ctx.srtp_packets >= profile.max_srtp_packets:
        raise KeyLifetimeError("the key has protected its maximum number of SRTP packets")
    roc, index = estimate(ctx.index, header.sequence)
    head, payload = packet[: header.header_length], packet[header.header_length :]
    if profile.cipher == "AES_GCM":
        iv = gcm.srtp_iv(ctx.keys.srtp.salt, ctx.ssrc, roc, header.sequence)
        out = head + AESGCM(ctx.keys.srtp.encryption_key).encrypt(iv, payload, head)
    else:
        sealed = head + _crypt(profile, ctx, index, payload)
        out = sealed + _auth_tag(profile, ctx.keys.srtp.authentication_key, sealed, roc)
    update(ctx.index, roc, header.sequence)
    ctx.srtp_packets += 1
    return out


def unprotect(packet: bytes, ctx: StreamContext) -> bytes:
    """Verify and decrypt one SRTP packet, returning the RTP packet (RFC 3711 sec. 3.3, RFC 7714 sec. 8).

    Raises ``ReplayError`` for a repeated or too-old index, ``AuthenticationError`` for a bad tag,
    and ``SrtpError`` for a malformed packet or another SSRC. The context changes only on success.
    """
    profile = ctx.keys.profile
    header = parse_header(packet)
    if header.ssrc != ctx.ssrc:
        raise SrtpError("the packet's SSRC is not the context's")
    roc, index = estimate(ctx.index, header.sequence)
    if not ctx.replay.check(index):
        raise ReplayError("SRTP packet index was already received or is too old")
    head = packet[: header.header_length]
    if profile.cipher == "AES_GCM":
        if len(packet) < header.header_length + profile.aead_tag_bytes:
            raise SrtpError("SRTP packet is shorter than its header and AEAD tag")
        iv = gcm.srtp_iv(ctx.keys.srtp.salt, ctx.ssrc, roc, header.sequence)
        try:
            payload = AESGCM(ctx.keys.srtp.encryption_key).decrypt(
                iv, packet[header.header_length :], head
            )
        except InvalidTag:
            raise AuthenticationError("AES-GCM authentication failure") from None
    else:
        tag_length = profile.srtp_tag_bits // 8
        if len(packet) < header.header_length + tag_length:
            raise SrtpError("SRTP packet is shorter than its header and tag")
        sealed, tag = packet[:-tag_length], packet[-tag_length:]
        expected = _auth_tag(profile, ctx.keys.srtp.authentication_key, sealed, roc)
        if not hmac.compare_digest(tag, expected):
            raise AuthenticationError("SRTP authentication failure")
        payload = _crypt(profile, ctx, index, sealed[header.header_length :])
    ctx.replay.accept(index)
    update(ctx.index, roc, header.sequence)
    return head + payload
