"""Index estimation and the ROC update, RFC 3711 sec. 3.3.1 and the Appendix A pseudocode."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from srtpkit.index import ROC_MODULUS, IndexState, estimate, update


def test_estimate_boundaries():
    # ROC 0, s_l 65535, seq 0: the sequence number wrapped, so v = ROC + 1.
    assert estimate(IndexState(0, 65535), 0) == (1, 1 << 16)
    # ROC 1, s_l 0, seq 65535: a late packet from before the wrap, v = ROC - 1.
    assert estimate(IndexState(1, 0), 65535) == (0, 65535)
    # ROC 0, s_l 0, seq 65535: v = (ROC - 1) mod 2^32.
    v, index = estimate(IndexState(0, 0), 65535)
    assert v == ROC_MODULUS - 1
    assert index == (ROC_MODULUS - 1) * 65536 + 65535
    # Exactly half a window away is not a wrap (strict comparisons in Appendix A).
    assert estimate(IndexState(5, 100), 100 + 32768)[0] == 5
    assert estimate(IndexState(5, 100), 100 + 32769)[0] == 4
    assert estimate(IndexState(5, 40000), 40000 - 32768)[0] == 5
    assert estimate(IndexState(5, 40000), 40000 - 32769)[0] == 6


def test_first_packet_initialises_s_l():
    state = IndexState()
    v, index = estimate(state, 65000)
    assert (v, index) == (0, 65000)
    assert state.s_l is None  # estimating never mutates
    update(state, v, 65000)
    assert state.s_l == 65000
    # a joining receiver is given the ROC out of band
    joining = IndexState(roc=7)
    assert estimate(joining, 10) == (7, (7 << 16) | 10)
    update(joining, 7, 10)
    assert (joining.roc, joining.s_l) == (7, 10)


def test_update_rules_three_cases():
    state = IndexState(3, 1000)
    update(state, 2, 65000)  # ROC - 1: nothing
    assert (state.roc, state.s_l) == (3, 1000)
    update(state, 3, 900)  # ROC, not larger: s_l stays
    assert (state.roc, state.s_l) == (3, 1000)
    update(state, 3, 1500)  # ROC, larger: s_l moves
    assert (state.roc, state.s_l) == (3, 1500)
    update(state, 4, 7)  # ROC + 1: both move
    assert (state.roc, state.s_l) == (4, 7)
    with pytest.raises(ValueError, match="ROC-1"):
        update(state, 9, 7)


def test_roc_wraps_mod_2_32():
    state = IndexState(ROC_MODULUS - 1, 65535)
    v, index = estimate(state, 0)
    assert v == 0
    assert index == 0  # 2^48 wraps to index 0, the 48-bit sense of the RFC
    update(state, v, 0)
    assert (state.roc, state.s_l) == (0, 0)
    low = IndexState(0, 0)
    assert estimate(low, 65535)[0] == ROC_MODULUS - 1


def test_rekey_does_not_reset_roc():
    # RFC 3711 sec. 3.3.1 paragraph 9: the state object is carried across a re-key untouched.
    state = IndexState(5, 100)
    update(state, 5, 200)
    assert state.roc == 5


def test_sequence_number_must_be_16_bits():
    with pytest.raises(ValueError, match="16 bits"):
        estimate(IndexState(), 65536)


@given(
    roc=st.integers(0, ROC_MODULUS - 1),
    s_l=st.integers(0, 65535),
    delta=st.integers(-32767, 32767),
)
def test_estimate_closest_within_half_window(roc, s_l, delta):
    """A packet within 2^15 of the reference gets the index nearest to it, modulo 2^48."""
    reference = ((roc << 16) | s_l) % (1 << 48)
    true_index = (reference + delta) % (1 << 48)
    state = IndexState(roc, s_l)
    _, index = estimate(state, true_index & 0xFFFF)
    assert index == true_index
