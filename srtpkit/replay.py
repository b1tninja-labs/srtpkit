"""window and bit vector, index based variant (RFC 3711 sec. 3.3.2).

``ReplayWindow`` is a sliding window over 48-bit packet indices held as a bitmap in a Python
integer. ``check`` never mutates; ``accept`` is called only after the packet authenticated
(RFC 3711 sec. 3.3.2 paragraphs 3 and 4), so a forged packet cannot advance the window.

Distances are measured modulo 2^48 in the signed sense. That matters at the start of a session:
a late packet from just before the first one seen is estimated with v = ROC-1 = 2^32-1, an index
near 2^48, and is a small negative distance rather than a leap forward.
"""

from __future__ import annotations

__all__ = ["INDEX_BITS", "MIN_WINDOW_SIZE", "ReplayWindow", "check"]

INDEX_BITS = 48
MIN_WINDOW_SIZE = 64  # RFC 3711 sec. 3.3.2: SRTP-WINDOW-SIZE "MUST be at least 64"
_MODULUS = 1 << INDEX_BITS


class ReplayWindow:
    """The Replay List of RFC 3711 sec. 3.3.2 as a sliding window of ``size`` indices.

    An index is acceptable if it is ahead of the highest seen, or within ``size - 1`` behind it
    and not yet received. An index ``size`` or more behind is treated as already received.
    """

    def __init__(self, size: int = 128) -> None:
        if size < MIN_WINDOW_SIZE:
            raise ValueError(f"replay window size must be at least {MIN_WINDOW_SIZE}")
        self.size = size
        self.highest: int | None = None
        self._bitmap = 0  # bit k set: index (highest - k) was received

    @staticmethod
    def _delta(index: int, highest: int) -> int:
        if not 0 <= index < _MODULUS:
            raise ValueError("packet index is a 48-bit value")
        return ((index - highest + (_MODULUS >> 1)) % _MODULUS) - (_MODULUS >> 1)

    def check(self, index: int) -> bool:
        """True if ``index`` may be accepted. Does not change the window."""
        if self.highest is None:
            if not 0 <= index < _MODULUS:
                raise ValueError("packet index is a 48-bit value")
            return True
        delta = self._delta(index, self.highest)
        if delta > 0:
            return True
        behind = -delta
        return behind < self.size and not (self._bitmap >> behind) & 1

    def accept(self, index: int) -> None:
        """Record ``index`` as received; call only after the packet authenticated."""
        if not self.check(index):
            raise ValueError("replayed or too-old packet index")
        if self.highest is None:
            self.highest = index
            self._bitmap = 1
            return
        delta = self._delta(index, self.highest)
        if delta > 0:
            self._bitmap = ((self._bitmap << delta) | 1) & ((1 << self.size) - 1)
            self.highest = index
        else:
            self._bitmap |= 1 << -delta


def check(window: ReplayWindow, index: int) -> bool:
    """Replay check for ``index`` against ``window``, RFC 3711 sec. 3.3.2; no side effects."""
    return window.check(index)
