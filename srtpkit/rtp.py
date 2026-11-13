"""The RTP fixed header, CSRC list and header extension: where the authenticated portion starts.

SRTP needs only to find the end of the header, because the header (with any CSRC list and
extension) is what AES-CM leaves in the clear and what AES-GCM takes as associated data. The
layout is RFC 3550 sec. 5.1 (12 fixed octets, CC CSRC identifiers of 4 octets) and sec. 5.3.1
(when X is set, a 4-octet extension header whose 16-bit length counts 32-bit words after it).

Not checked here: the padding count (P) and the payload type, which are the application's.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import SrtpError

__all__ = ["RtpHeader", "parse_header"]

_FIXED = 12


@dataclass(frozen=True)
class RtpHeader:
    """The parsed fixed header; ``header_length`` is the octet count up to the payload."""

    version: int
    padding: bool
    extension: bool
    marker: bool
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    csrc: tuple[int, ...]
    header_length: int


def parse_header(packet: bytes) -> RtpHeader:
    """Parse the RTP header of ``packet`` (RFC 3550 sec. 5.1, sec. 5.3.1); raise ``SrtpError``.

    Refuses a version other than 2, a packet that ends inside the fixed header, the CSRC list or
    the extension, and nothing else: a packet with no payload is valid.
    """
    if len(packet) < _FIXED:
        raise SrtpError("RTP packet is shorter than the 12-octet fixed header")
    first, second, sequence, timestamp, ssrc = struct.unpack_from(">BBHII", packet)
    if first >> 6 != 2:
        raise SrtpError(f"RTP version {first >> 6} is not 2")
    count = first & 0x0F
    length = _FIXED + 4 * count
    if len(packet) < length:
        raise SrtpError("RTP packet ends inside the CSRC list")
    csrc = struct.unpack_from(f">{count}I", packet, _FIXED) if count else ()
    extension = bool(first & 0x10)
    if extension:
        if len(packet) < length + 4:
            raise SrtpError("RTP packet ends inside the extension header")
        words = struct.unpack_from(">H", packet, length + 2)[0]
        length += 4 + 4 * words
        if len(packet) < length:
            raise SrtpError("RTP packet ends inside the header extension")
    return RtpHeader(
        2,
        bool(first & 0x20),
        extension,
        bool(second & 0x80),
        second & 0x7F,
        sequence,
        timestamp,
        ssrc,
        tuple(csrc),
        length,
    )
