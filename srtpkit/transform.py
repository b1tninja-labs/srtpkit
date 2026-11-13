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

Cryptex (RFC 9335) is opt-in: ``protect(..., cryptex=True)`` encrypts the CSRC list and the
header extension data, and ``unprotect(..., cryptex="accept")`` recognises the 0xC0DE and 0xC2DE
tags. The layout is in :mod:`srtpkit.cryptex`; the cipher, the IV and the tag are unchanged.

Header extension encryption (RFC 6904) is opt-in for the AES-CM profiles: pass
``encrypted_extensions`` (the element IDs the signalling marks) to ``protect`` and ``unprotect``
and derive the context's keys with ``header_extension=True``. The extension is encrypted before
the tag is computed and decrypted only after it verifies (RFC 6904 sec. 3 paragraph 14).

Not supported: the MKI and key derivation rates above zero.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Collection
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import aescm, gcm, hdrext
from . import cryptex as cx
from .context import StreamContext
from .errors import AuthenticationError, KeyLifetimeError, ReplayError, SrtpError
from .index import estimate, update
from .kdf import SessionKeys
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


def _header_keys(
    ctx: StreamContext, encrypted_extensions: Collection[int], cryptex: bool
) -> SessionKeys | None:
    """The RFC 6904 keys when header extension encryption is asked for, else ``None``."""
    if not encrypted_extensions:
        return None
    if cryptex:
        raise SrtpError("a packet cannot use both Cryptex and RFC 6904 (RFC 9335 sec. 5)")
    if ctx.keys.profile.cipher != "AES_CM":
        raise NotImplementedError("RFC 6904 header extension encryption: AES-CM profiles only")
    if ctx.keys.header is None:
        raise SrtpError(
            "the context has no header encryption keys: derive with header_extension=True"
        )
    return ctx.keys.header


def _protect_cryptex(packet: bytes, ctx: StreamContext, roc: int, index: int, seq: int) -> bytes:
    """RFC 9335 sec. 6.2: encrypt ``CSRCs || extension data || payload``; header and tag stay."""
    profile = ctx.keys.profile
    layout = cx.split(packet)
    plaintext = layout.csrc + layout.rest
    count = len(layout.csrc)
    if profile.cipher == "AES_GCM":
        iv = gcm.srtp_iv(ctx.keys.srtp.salt, ctx.ssrc, roc, seq)
        aad = layout.fixed + layout.ext_header  # sec. 6.2 paragraph 6
        sealed = AESGCM(ctx.keys.srtp.encryption_key).encrypt(iv, plaintext, aad)
        return cx.join(layout, sealed[:count], sealed[count:])
    encrypted = _crypt(profile, ctx, index, plaintext)
    body = cx.join(layout, encrypted[:count], encrypted[count:])
    return body + _auth_tag(profile, ctx.keys.srtp.authentication_key, body, roc)


def _unprotect_cryptex(packet: bytes, ctx: StreamContext, roc: int, index: int, seq: int) -> bytes:
    """RFC 9335 sec. 6.3, the reverse of :func:`_protect_cryptex`; restores the RFC 8285 tag."""
    profile = ctx.keys.profile
    tag_length = (
        profile.aead_tag_bytes if profile.cipher == "AES_GCM" else profile.srtp_tag_bits // 8
    )
    if len(packet) < 16 + tag_length:
        raise SrtpError("SRTP packet is shorter than its header and tag")
    if profile.cipher == "AES_GCM":
        layout = cx.split(packet)
        count = len(layout.csrc)
        iv = gcm.srtp_iv(ctx.keys.srtp.salt, ctx.ssrc, roc, seq)
        try:
            plaintext = AESGCM(ctx.keys.srtp.encryption_key).decrypt(
                iv, layout.csrc + layout.rest, layout.fixed + layout.ext_header
            )
        except InvalidTag:
            raise AuthenticationError("AES-GCM authentication failure") from None
    else:
        sealed, tag = packet[:-tag_length], packet[-tag_length:]
        expected = _auth_tag(profile, ctx.keys.srtp.authentication_key, sealed, roc)
        if not hmac.compare_digest(tag, expected):
            raise AuthenticationError("SRTP authentication failure")
        layout = cx.split(sealed)
        count = len(layout.csrc)
        plaintext = _crypt(profile, ctx, index, layout.csrc + layout.rest)
    restored = layout._replace(ext_header=cx.restore_profile(layout.ext_header))
    return cx.join(restored, plaintext[:count], plaintext[count:])


def protect(
    packet: bytes,
    ctx: StreamContext,
    *,
    cryptex: bool = False,
    encrypted_extensions: Collection[int] = (),
) -> bytes:
    """Protect one RTP packet, returning the SRTP packet (RFC 3711 sec. 3.3, RFC 7714 sec. 8).

    The packet's SSRC must be the context's. Raises ``KeyLifetimeError`` once the key has
    protected the profile's maximum number of packets (sec. 3.3.1 paragraph 10).

    ``cryptex=True`` applies RFC 9335 to a packet that has CSRC identifiers or a header
    extension: both are encrypted and the extension tag becomes 0xC0DE or 0xC2DE. A packet with
    neither is protected as ordinary SRTP. Use it only after both ends negotiated ``a=cryptex``.

    ``encrypted_extensions`` names the RFC 8285 element IDs whose bodies RFC 6904 encrypts; the
    context needs ``header`` keys, and the profile must be AES-CM. It cannot be combined with
    ``cryptex`` (RFC 9335 sec. 5 paragraph 5).
    """
    profile = ctx.keys.profile
    header_keys = _header_keys(ctx, encrypted_extensions, cryptex)
    if cryptex:
        packet = cx.prepare(packet)
    header = parse_header(packet)
    if header.ssrc != ctx.ssrc:
        raise SrtpError("the packet's SSRC is not the context's")
    if ctx.srtp_packets >= profile.max_srtp_packets:
        raise KeyLifetimeError("the key has protected its maximum number of SRTP packets")
    roc, index = estimate(ctx.index, header.sequence)
    head, payload = packet[: header.header_length], packet[header.header_length :]
    if header_keys is not None:
        head = hdrext.apply(head, header_keys, ctx.ssrc, index, encrypted_extensions)
    if cryptex and cx.is_cryptex(packet):
        out = _protect_cryptex(packet, ctx, roc, index, header.sequence)
    elif profile.cipher == "AES_GCM":
        iv = gcm.srtp_iv(ctx.keys.srtp.salt, ctx.ssrc, roc, header.sequence)
        out = head + AESGCM(ctx.keys.srtp.encryption_key).encrypt(iv, payload, head)
    else:
        sealed = head + _crypt(profile, ctx, index, payload)
        out = sealed + _auth_tag(profile, ctx.keys.srtp.authentication_key, sealed, roc)
    update(ctx.index, roc, header.sequence)
    ctx.srtp_packets += 1
    return out


def unprotect(
    packet: bytes,
    ctx: StreamContext,
    *,
    cryptex: Literal["off", "accept", "require"] = "off",
    encrypted_extensions: Collection[int] = (),
) -> bytes:
    """Verify and decrypt one SRTP packet, returning the RTP packet (RFC 3711 sec. 3.3, RFC 7714 sec. 8).

    Raises ``ReplayError`` for a repeated or too-old index, ``AuthenticationError`` for a bad tag,
    and ``SrtpError`` for a malformed packet or another SSRC. The context changes only on success.

    ``cryptex`` is the RFC 9335 sec. 5.2 choice. ``"off"`` (the default) refuses a packet whose
    extension tag is 0xC0DE or 0xC2DE rather than decrypt it wrongly. ``"accept"`` handles both
    kinds: the decrypted packet has its RFC 8285 tag back (0xBEDE, or 0x1000 for two-byte). In
    ``"require"`` mode a packet that has CSRC identifiers or an extension but no Cryptex tag
    raises ``SrtpError``, as sec. 5.2 paragraph 2 says to stop on a mismatch.

    ``encrypted_extensions`` is as for :func:`protect`; the extension is decrypted after the tag
    verifies and never before.
    """
    profile = ctx.keys.profile
    header_keys = _header_keys(ctx, encrypted_extensions, cryptex != "off")
    header = parse_header(packet)
    if header.ssrc != ctx.ssrc:
        raise SrtpError("the packet's SSRC is not the context's")
    marked = cx.is_cryptex(packet)
    if marked and cryptex == "off":
        raise SrtpError("the packet is Cryptex-protected (RFC 9335) and Cryptex is not enabled")
    if cryptex == "require" and not marked and (packet[0] & 0x1F):
        raise SrtpError("Cryptex is required but the packet has CSRCs or an extension in the clear")
    roc, index = estimate(ctx.index, header.sequence)
    if not ctx.replay.check(index):
        raise ReplayError("SRTP packet index was already received or is too old")
    head = packet[: header.header_length]
    if marked:
        result = _unprotect_cryptex(packet, ctx, roc, index, header.sequence)
        ctx.replay.accept(index)
        update(ctx.index, roc, header.sequence)
        return result
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
        if header_keys is not None:
            head = hdrext.apply(head, header_keys, ctx.ssrc, index, encrypted_extensions)
    ctx.replay.accept(index)
    update(ctx.index, roc, header.sequence)
    return head + payload
