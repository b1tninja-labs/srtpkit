"""packet index estimation and the rollover counter (RFC 3711 sec. 3.3.1, Appendix A).

A receiver keeps ``(ROC, s_l)`` and, for each packet, estimates the 48-bit index from the 16-bit
sequence number. State changes only through ``update``, which the caller invokes after the packet
has authenticated, because an unauthenticated packet must never move the rollover counter.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ROC_MODULUS", "IndexState", "estimate", "update"]

ROC_MODULUS = 1 << 32
_HALF = 1 << 15


@dataclass
class IndexState:
    """Receiver state: the rollover counter and the highest sequence number, ``s_l``.

    ``s_l`` is ``None`` until the first packet, which initialises it (RFC 3711 sec. 3.3.1
    paragraph 5), unless key management supplies a starting value. A receiver joining a session in
    progress must be given the current ``roc`` out of band. Re-keying never resets ``roc``
    (paragraph 9), so carry the object across a re-key rather than creating a new one.
    """

    roc: int = 0
    s_l: int | None = None


def estimate(state: IndexState, seq: int) -> tuple[int, int]:
    """Return ``(v, index)`` for a packet with sequence number ``seq``, RFC 3711 Appendix A.

    ``index = 2^16 * v + seq`` where ``v`` is ROC-1, ROC or ROC+1 modulo 2^32. Nothing is
    mutated. Until ``s_l`` is set the first packet is taken to be in the current ROC.
    """
    if not 0 <= seq <= 0xFFFF:
        raise ValueError("RTP sequence number is 16 bits")
    s_l = state.s_l
    if s_l is None:
        v = state.roc
    elif s_l < _HALF:
        v = (state.roc - 1) % ROC_MODULUS if seq - s_l > _HALF else state.roc
    else:
        v = (state.roc + 1) % ROC_MODULUS if s_l - _HALF > seq else state.roc
    return v, (v << 16) | seq


def update(state: IndexState, v: int, seq: int) -> None:
    """Apply the post-authentication update of RFC 3711 sec. 3.3.1 paragraph 8.

    ``v`` is the value ``estimate`` returned for this packet. ROC-1: no change. ROC: ``s_l``
    moves to ``seq`` only if ``seq`` is larger. ROC+1: ``s_l`` is ``seq`` and ROC becomes ``v``.
    """
    if state.s_l is None:
        state.s_l = seq
        state.roc = v
        return
    if v == state.roc:
        if seq > state.s_l:
            state.s_l = seq
    elif v == (state.roc + 1) % ROC_MODULUS:
        state.s_l = seq
        state.roc = v
    elif v != (state.roc - 1) % ROC_MODULUS:
        raise ValueError("v must be one of ROC-1, ROC, ROC+1 modulo 2^32")
