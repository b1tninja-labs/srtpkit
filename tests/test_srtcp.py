"""Reduced-size RTCP (RFC 5506 sec. 3.4.3) through SRTCP."""

from __future__ import annotations

import pytest

from srtpkit.context import StreamKeys, for_stream
from srtpkit.errors import SrtpError
from srtpkit.kdf import SessionKeys
from srtpkit.params import profile
from srtpkit.srtcp import protect_rtcp, unprotect_rtcp

H = bytes.fromhex

SSRC = 0x4D617273
# A Generic NACK (RFC 4585 sec. 6.2.1, PT 205, FMT 1) on its own: no SR or RR in front, which
# RFC 3711 sec. 3.4 forbade and RFC 5506 sec. 3.4.3 says SRTP has no real dependency on. The
# bytes are written from the packet layout, not taken from a document: V=2 P=0 FMT=1, PT=205,
# length 3 words, sender SSRC, media SSRC, one PID/BLP pair.
NACK = H("81cd0003" + "4d617273" + "cafebabe" + "03e80005")
# A Receiver Reference Time XR block alone would do as well; an RTCP BYE shows a third type.
BYE = H("81cb0001" + "4d617273")


def keys(profile_id: int, key_bytes: int) -> StreamKeys:
    salt = H("517569642070726f2071756f")
    session = SessionKeys(bytes(range(key_bytes)), bytes(20), salt)
    return StreamKeys(profile(profile_id), session, session)


@pytest.mark.parametrize("profile_id", [0x0007, 0x0008])
@pytest.mark.parametrize("packet", [NACK, BYE])
def test_reduced_size_rtcp(profile_id, packet):
    key_bytes = 16 if profile_id == 0x0007 else 32
    sender = for_stream(SSRC, keys(profile_id, key_bytes))
    sealed = protect_rtcp(packet, sender)
    # the header and SSRC of the first packet stay in the clear, as for a compound packet
    assert sealed[:8] == packet[:8]
    assert sealed[8:-4] != packet[8:]
    assert sealed[-4:] == H("80000000")  # E-flag set, SRTCP index 0, last (RFC 7714 sec. 9.2)
    receiver = for_stream(SSRC, keys(profile_id, key_bytes))
    assert unprotect_rtcp(sealed, receiver) == packet


def test_reduced_size_rtcp_with_aes_cm_and_the_refusals_that_remain():
    session = SessionKeys(bytes(16), bytes(20), bytes(14))
    cm_keys = StreamKeys(profile(0x0001), session, session)
    sender = for_stream(SSRC, cm_keys)
    sealed = protect_rtcp(NACK, sender)
    assert sealed[:8] == NACK[:8]
    assert len(sealed) == len(NACK) + 4 + 10
    assert unprotect_rtcp(sealed, for_stream(SSRC, cm_keys)) == NACK
    # what SRTCP still needs is the common header with a source SSRC (RFC 5506 sec. 3.4.3)
    with pytest.raises(SrtpError):
        protect_rtcp(NACK[:7], for_stream(SSRC, cm_keys))
    with pytest.raises(SrtpError):
        protect_rtcp(H("41cd0003") + NACK[4:], for_stream(SSRC, cm_keys))  # version 1
