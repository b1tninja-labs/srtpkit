"""master key identifier handling (RFC 3711 sec. 3.1, sec. 3.2.1, sec. 8.1).

The MKI is the recommended way to tell a receiver which master key a packet was protected with
(sec. 8.1). The cryptographic context holds an MKI indicator, a fixed MKI length in octets and, per
master key, an MKI value (sec. 3.2.1). This module is the lookup: a :class:`MasterKeys` table with
one fixed identifier length, and :func:`select_key`, which takes the identifier read from a packet
and derives that master key's session keys.

What this module does not do: carry the MKI on the wire. :mod:`srtpkit.transform` still writes and
reads packets with no MKI field (see ROADMAP.md, row ``mki.wire``), and the <From, To> alternative
of sec. 8.1.1 is not supported. The MKI is not integrity protected by itself (sec. 3.1), so a
caller learns the identifier from an unauthenticated packet: an unknown identifier is refused, and
an identifier that selects a key still has to pass the authentication tag check under that key.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .context import StreamKeys, derive_stream_keys
from .errors import SrtpError
from .params import Profile

__all__ = ["MasterKey", "MasterKeys", "UnknownMkiError", "select_key"]


class UnknownMkiError(SrtpError):
    """The identifier names no master key in the table (RFC 3711 sec. 8.1)."""


@dataclass(frozen=True)
class MasterKey:
    """One master key with the MKI that names it (RFC 3711 sec. 3.2.1)."""

    mki: bytes
    master_key: bytes = field(repr=False)
    master_salt: bytes = field(repr=False)


class MasterKeys:
    """The master keys of one context, all named by an MKI of one fixed length.

    RFC 3711 sec. 3.2.1: the MKI indicator and the MKI length "MUST be kept fixed for the lifetime
    of the context". The length is therefore set once, from the first entry or from ``mki_length``,
    and every entry and every lookup must match it. An identifier is a non-empty octet string (an
    empty one would be the MKI indicator set to zero, which is no MKI at all) and appears once.
    """

    def __init__(
        self, profile: Profile, entries: Iterable[MasterKey] = (), *, mki_length: int | None = None
    ) -> None:
        self.profile = profile
        self._keys: dict[bytes, MasterKey] = {}
        self._length = mki_length
        if mki_length is not None and mki_length < 1:
            raise ValueError("the MKI length is at least one octet when the MKI is in use")
        for entry in entries:
            self.add(entry)

    @property
    def mki_length(self) -> int | None:
        """The fixed identifier length in octets, or ``None`` until the first key is added."""
        return self._length

    def add(self, entry: MasterKey) -> None:
        """Add a master key; its identifier must be new and as long as the others."""
        if not entry.mki:
            raise ValueError("an MKI is at least one octet")
        if self._length is not None and len(entry.mki) != self._length:
            raise ValueError(f"the MKI length is fixed at {self._length} octets for the context")
        if entry.mki in self._keys:
            raise ValueError("this MKI names a master key already")
        if (
            len(entry.master_key) * 8 != self.profile.key_bits
            or len(entry.master_salt) * 8 != self.profile.salt_bits
        ):
            raise ValueError("master key or salt length does not match the profile")
        self._length = len(entry.mki)
        self._keys[entry.mki] = entry

    def remove(self, mki: bytes) -> None:
        """Retire a master key once no packet under it can arrive any more."""
        try:
            del self._keys[mki]
        except KeyError:
            raise UnknownMkiError("no master key has this MKI") from None

    def __contains__(self, mki: object) -> bool:
        return mki in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def get(self, mki: bytes) -> MasterKey:
        """The entry for ``mki``; refuses a wrong length before looking, then an unknown value."""
        if self._length is not None and len(mki) != self._length:
            raise UnknownMkiError(f"an MKI here is {self._length} octets, not {len(mki)}")
        try:
            return self._keys[mki]
        except KeyError:
            raise UnknownMkiError("no master key has this MKI") from None


def select_key(
    identifier: bytes, keys: MasterKeys, *, header_extension: bool = False
) -> StreamKeys:
    """Find the master key an MKI names and derive its session keys, RFC 3711 sec. 8.1.

    Sec. 8.1 recommends associating each master key of a context with an MKI so that the receiver
    can retrieve the key from the packet, and sec. 3.3 step 3 says to use "the MKI in the SRTP
    packet" to determine the master key and salt when the context's MKI indicator is set. The
    session keys then follow sec. 4.3 with key derivation rate zero, as everywhere in this
    package. ``identifier`` is the MKI field as received; one of the wrong length or with no entry
    raises :class:`UnknownMkiError`, and nothing is derived. Selecting a key is not
    authenticating the packet: the tag still has to verify under the keys this returns.
    """
    entry = keys.get(identifier)
    return derive_stream_keys(
        keys.profile, entry.master_key, entry.master_salt, header_extension=header_extension
    )
