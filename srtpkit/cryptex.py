"""Cryptex: encrypting the CSRC list and every header extension (RFC 9335).

SRTP leaves the RTP header, the CSRC list and the header extension in the clear (RFC 3711
sec. 3.1). Cryptex moves the CSRC identifiers and the extension data into the encrypted portion,
which is then ``CSRC identifiers || header extension data || payload || padding`` (RFC 9335
sec. 6.2). Everything else about the transform is RFC 3711 or RFC 7714 unchanged; this module is
only the packet layout.

* The first twelve octets and the four-octet extension header (the "defined by profile" field
  and the length) stay in the clear. For AES-GCM those sixteen octets are the associated data,
  fixed header first, then the extension header, although a CSRC list sits between them on the
  wire (sec. 6.2 paragraph 5 to 8).
* The "defined by profile" field says which framing is in use: 0xBEDE becomes 0xC0DE and the
  two-byte framing (0x100 in the top twelve bits) becomes 0xC2DE (sec. 5). The four "appbits" of
  the two-byte framing cannot survive the change, so a decrypted packet gets 0x1000 back, and
  sec. 5 forbids negotiating extension identifier 256, which those bits would stand for.
* A packet with CSRC identifiers and no extension gets an empty one: the tag 0xC0DE, length 0,
  and the X bit set, so the receiver can tell the CSRC list is encrypted (sec. 5.1).
* A packet with neither CSRC identifiers nor an extension has nothing to encrypt and is sent as
  ordinary SRTP (sec. 5.1 starts "sending an RTP packet that has any CSRCs or contains any header
  extensions"); the receiver recognises it by its profile field being absent.
* An extension that is not RFC 8285 one-byte or two-byte framing is refused (sec. 5.1: "MUST NOT
  be used with header extensions other than the variety described in RFC 8285").
* RFC 6904 and Cryptex on one packet are forbidden (sec. 5 paragraph 5); this library has no
  RFC 6904 yet, so nothing can combine them.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

from .errors import SrtpError

__all__ = [
    "ONE_BYTE",
    "ONE_BYTE_CRYPTEX",
    "TWO_BYTE",
    "TWO_BYTE_CRYPTEX",
    "Layout",
    "is_cryptex",
    "join",
    "prepare",
    "restore_profile",
    "split",
]

ONE_BYTE = 0xBEDE  # RFC 8285 sec. 4.2
TWO_BYTE = 0x1000  # RFC 8285 sec. 4.3: 0x100 and four appbits; Cryptex needs the appbits zero
ONE_BYTE_CRYPTEX = 0xC0DE  # RFC 9335 sec. 5
TWO_BYTE_CRYPTEX = 0xC2DE


class Layout(NamedTuple):
    """A Cryptex packet cut at the four places that matter."""

    fixed: bytes  # the 12-octet fixed header
    csrc: bytes  # 4 * CC octets, plaintext before encryption and ciphertext after
    ext_header: bytes  # profile field and length, always in the clear
    rest: bytes  # extension data and everything after it


def _profile(packet: bytes) -> int | None:
    """The "defined by profile" field of ``packet``, or ``None`` when X is clear."""
    if len(packet) < 12 or not packet[0] & 0x10:
        return None
    start = 12 + 4 * (packet[0] & 0x0F)
    if len(packet) < start + 4:
        raise SrtpError("RTP packet ends inside the extension header")
    return int.from_bytes(packet[start : start + 2], "big")


def is_cryptex(packet: bytes) -> bool:
    """True if the packet's extension tag is 0xC0DE or 0xC2DE (RFC 9335 sec. 5.2)."""
    return _profile(packet) in (ONE_BYTE_CRYPTEX, TWO_BYTE_CRYPTEX)


def prepare(packet: bytes) -> bytes:
    """Return ``packet`` with the Cryptex tag in place, ready to protect (RFC 9335 sec. 5.1).

    A packet with no CSRC identifiers and no extension is returned unchanged: it has nothing
    to encrypt. A packet that already carries a Cryptex tag, or an extension that is not RFC 8285
    framing, raises :class:`SrtpError`.
    """
    csrc_count = packet[0] & 0x0F if packet else 0
    profile = _profile(packet)
    if profile is None:
        if csrc_count == 0:
            return packet
        if len(packet) < 12 + 4 * csrc_count:
            raise SrtpError("RTP packet ends inside the CSRC list")
        start = 12 + 4 * csrc_count
        empty = struct.pack(">HH", ONE_BYTE_CRYPTEX, 0)
        return bytes([packet[0] | 0x10]) + packet[1:start] + empty + packet[start:]
    start = 12 + 4 * csrc_count
    if profile in (ONE_BYTE_CRYPTEX, TWO_BYTE_CRYPTEX):
        raise SrtpError("the packet already carries a Cryptex header extension tag")
    if profile == ONE_BYTE:
        tag = ONE_BYTE_CRYPTEX
    elif profile & 0xFFF0 == TWO_BYTE:
        tag = TWO_BYTE_CRYPTEX
    else:
        raise SrtpError("Cryptex applies only to RFC 8285 one-byte and two-byte header extensions")
    return packet[:start] + struct.pack(">H", tag) + packet[start + 2 :]


def split(packet: bytes) -> Layout:
    """Cut a packet whose extension tag is a Cryptex tag into its four parts."""
    if not is_cryptex(packet):
        raise SrtpError("not a Cryptex packet")
    start = 12 + 4 * (packet[0] & 0x0F)
    return Layout(packet[:12], packet[12:start], packet[start : start + 4], packet[start + 4 :])


def join(layout: Layout, csrc: bytes, rest: bytes) -> bytes:
    """Reassemble a packet with ``csrc`` and ``rest`` (the transformed parts) in place."""
    return layout.fixed + csrc + layout.ext_header + rest


def restore_profile(ext_header: bytes) -> bytes:
    """The extension header with the RFC 8285 tag back: 0xC0DE to 0xBEDE, 0xC2DE to 0x1000."""
    tag = int.from_bytes(ext_header[:2], "big")
    original = ONE_BYTE if tag == ONE_BYTE_CRYPTEX else TWO_BYTE
    return original.to_bytes(2, "big") + ext_header[2:]
