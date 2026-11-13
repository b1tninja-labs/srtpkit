"""The replay window, RFC 3711 sec. 3.3.2."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from srtpkit.index import IndexState, estimate, update
from srtpkit.replay import ReplayWindow, check


def test_window_accepts_in_order_and_reorder_inside_window():
    window = ReplayWindow(64)
    for index in (10, 11, 12, 14):
        assert check(window, index)
        window.accept(index)
    assert check(window, 13)  # reordered, inside the window, not yet received
    window.accept(13)
    assert not check(window, 13)


def test_window_refuses_duplicate():
    window = ReplayWindow()
    window.accept(100)
    assert not check(window, 100)
    window.accept(101)
    assert not check(window, 100)
    assert not check(window, 101)
    with pytest.raises(ValueError, match="replayed"):
        window.accept(101)


def test_window_refuses_too_old():
    window = ReplayWindow(64)
    window.accept(1000)
    assert check(window, 1000 - 63)  # last slot inside the window
    assert not check(window, 1000 - 64)  # size or more behind is treated as received
    assert not check(window, 5)


def test_window_size_below_64_refused():
    with pytest.raises(ValueError, match="at least 64"):
        ReplayWindow(63)
    ReplayWindow(64)


def test_check_does_not_mutate():
    window = ReplayWindow(64)
    window.accept(50)
    for _ in range(3):
        assert check(window, 5000)  # a forged packet that then fails authentication
    assert window.highest == 50
    assert check(window, 49)
    window.accept(51)  # a genuine packet; the forged one never moved the window
    assert window.highest == 51
    assert check(window, 49)


def test_large_jump_slides_window():
    window = ReplayWindow(64)
    for index in range(10):
        window.accept(index)
    window.accept(10_000)
    assert not check(window, 9)  # fell out of the window
    assert check(window, 9_999)
    assert not check(window, 10_000)
    window.accept(9_999)
    assert not check(window, 9_999)


def test_index_range_enforced():
    window = ReplayWindow()
    with pytest.raises(ValueError, match="48-bit"):
        check(window, 1 << 48)
    window.accept((1 << 48) - 1)
    with pytest.raises(ValueError, match="48-bit"):
        window.accept(-1)


def test_session_start_late_packet_before_first_one_seen():
    """The first packet seen is seq 5. A late seq 65530 is index 2^48-6: six behind, not a leap."""
    state = IndexState()
    window = ReplayWindow()
    v, index = estimate(state, 5)
    update(state, v, 5)
    window.accept(index)
    v, late = estimate(state, 65530)
    assert late == (1 << 48) - 6
    assert check(window, late)
    window.accept(late)
    assert window.highest == 5
    assert not check(window, late)


def test_wrap_of_the_48_bit_index_is_a_small_forward_step():
    window = ReplayWindow()
    window.accept((1 << 48) - 1)
    assert check(window, 0)
    window.accept(0)
    assert window.highest == 0
    assert not check(window, (1 << 48) - 1)  # already received


@given(st.lists(st.integers(0, 400), max_size=80), st.sampled_from([64, 100, 128]))
def test_window_agrees_with_a_naive_set_oracle(indices, size):
    window = ReplayWindow(size)
    seen: set[int] = set()
    highest = None
    for index in indices:
        if highest is None or index > highest:
            expected = True
        else:
            expected = highest - index < size and index not in seen
        assert check(window, index) is expected
        if expected:
            window.accept(index)
            seen.add(index)
            highest = index if highest is None else max(highest, index)
