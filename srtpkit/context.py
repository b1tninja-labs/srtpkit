"""Stream and session context: the keys, the rollover state and the replay lists (RFC 3711 sec. 3.2).

One :class:`StreamContext` is one SSRC in one direction. It holds the SRTP and SRTCP session keys
(:class:`StreamKeys`), the receiver's ROC and s_l (:mod:`srtpkit.index`), the SRTP replay window,
and for SRTCP the next index to send and its own replay window (sec. 3.4: a separate Replay List).

Policy decisions, each pinned by a test:

* ``derive_stream_keys`` runs the key derivation once, with a key derivation rate of zero, which is
  the only rate RFC 5764 sec. 4.1.2 allows for DTLS-SRTP. A re-derivation rate and the MKI are not
  supported.
* The sender and the receiver use the same object: ``protect`` estimates the index from the same
  ``(ROC, s_l)`` pair the receiver would, and updates it after every packet, which gives the
  sender-side rule of sec. 3.3.1 paragraph 2 (ROC increments when SEQ wraps).
* Re-keying keeps the ROC and the SRTCP index (sec. 3.3.1 paragraph 9, sec. 3.4 paragraph 8):
  :meth:`StreamContext.rekey` replaces only the keys. The packet counters that bound a key's life
  restart, because they count packets under one key.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hdrext import derive_header_keys
from .index import IndexState
from .kdf import SessionKeys, derive_session_keys
from .params import Profile
from .replay import ReplayWindow

__all__ = ["StreamContext", "StreamKeys", "derive_stream_keys", "for_stream"]


@dataclass(frozen=True)
class StreamKeys:
    """A profile with its SRTP and SRTCP session keys for one direction."""

    profile: Profile
    srtp: SessionKeys
    srtcp: SessionKeys
    header: SessionKeys | None = None  # k_he and k_hs of RFC 6904, when asked for


def derive_stream_keys(
    profile: Profile, master_key: bytes, master_salt: bytes, *, header_extension: bool = False
) -> StreamKeys:
    """Derive the SRTP and SRTCP session keys from one master key and salt (RFC 3711 sec. 4.3).

    A NULL-cipher profile raises ``NotImplementedError`` from the KDF: see
    ``kdf.derive_session_keys`` and the open question in ROADMAP.md. ``header_extension=True`` also
    derives the RFC 6904 header encryption key and salt (AES-CM profiles only).
    """
    header = derive_header_keys(profile, master_key, master_salt) if header_extension else None
    return StreamKeys(
        profile,
        derive_session_keys(profile, master_key, master_salt),
        derive_session_keys(profile, master_key, master_salt, srtcp=True),
        header,
    )


@dataclass
class StreamContext:
    """The cryptographic context of one SSRC in one direction (RFC 3711 sec. 3.2)."""

    ssrc: int
    keys: StreamKeys
    index: IndexState = field(default_factory=IndexState)
    replay: ReplayWindow = field(default_factory=ReplayWindow)
    srtcp_index: int = 0
    srtcp_replay: ReplayWindow = field(default_factory=ReplayWindow)
    srtp_packets: int = 0
    srtcp_packets: int = 0

    def rekey(self, keys: StreamKeys) -> None:
        """Switch to new keys, keeping the ROC, s_l, replay lists and SRTCP index."""
        self.keys = keys
        self.srtp_packets = 0
        self.srtcp_packets = 0


def for_stream(ssrc: int, keys: StreamKeys, *, window: int = 128) -> StreamContext:
    """Make the context of stream ``ssrc`` under ``keys``, ROC 0 (RFC 3711 sec. 3.2, sec. 3.3.1).

    ``window`` is the replay window size, at least 64 (sec. 3.3.2). A receiver joining a session
    in progress sets ``ctx.index.roc`` to the current value it was given out of band.
    """
    if not 0 <= ssrc < 1 << 32:
        raise ValueError("an SSRC is 32 bits")
    return StreamContext(ssrc, keys, replay=ReplayWindow(window), srtcp_replay=ReplayWindow(window))
