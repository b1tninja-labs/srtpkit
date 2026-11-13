"""The DTLS-SRTP protection profile table (RFC 5764 sec. 4.1.2, RFC 7714 sec. 14.2) and the policy."""

from __future__ import annotations

import pytest

from srtpkit.params import (
    PROFILES,
    NoCommonProfileError,
    UnknownProfileError,
    profile,
    select_profile,
)


def test_profile_table():
    cm80 = profile(0x0001)
    assert cm80.name == "SRTP_AES128_CM_HMAC_SHA1_80"
    assert (cm80.cipher, cm80.key_bits, cm80.salt_bits) == ("AES_CM", 128, 112)
    assert (cm80.auth_function, cm80.auth_key_bits) == ("HMAC-SHA1", 160)
    assert (cm80.srtp_tag_bits, cm80.srtcp_tag_bits) == (80, 80)
    assert cm80.max_srtp_packets == cm80.max_srtcp_packets == 2**31

    null80 = profile(0x0005)
    assert (null80.cipher, null80.key_bits, null80.salt_bits) == ("NULL", 0, 0)
    assert profile(0x0006).srtp_tag_bits == 32

    gcm128, gcm256 = profile(0x0007), profile(0x0008)
    assert (gcm128.cipher, gcm128.key_bits, gcm128.salt_bits) == ("AES_GCM", 128, 96)
    assert (gcm256.cipher, gcm256.key_bits, gcm256.salt_bits) == ("AES_GCM", 256, 96)
    for gcm in (gcm128, gcm256):
        assert gcm.aead_tag_bytes == 16
        assert (gcm.auth_function, gcm.auth_key_bits, gcm.srtp_tag_bits) == ("NULL", 0, 0)
        assert gcm.max_srtp_packets == 2**48
        assert gcm.max_srtcp_packets == 2**31
        # RFC 7714 erratum 4938: the KDF consumes 112 bits, so the 96-bit salt is widened.
        assert gcm.kdf_salt_bits == 112
    assert sorted(PROFILES) == [1, 2, 5, 6, 7, 8]
    with pytest.raises(UnknownProfileError):
        profile(0x0099)


def test_sha1_32_has_rtcp_tag_80():
    for dtls_id in (0x0002, 0x0006):
        assert profile(dtls_id).srtp_tag_bits == 32
        assert profile(dtls_id).srtcp_tag_bits == 80


def test_null_profiles_never_default():
    assert select_profile([0x0005, 0x0006, 0x0001]).dtls_id == 0x0001
    with pytest.raises(NoCommonProfileError):
        select_profile([0x0005, 0x0006])
    with pytest.raises(NoCommonProfileError):
        select_profile([0x0005], allow_legacy=True)  # legacy does not imply null
    assert select_profile([0x0005], allow_null=True).dtls_id == 0x0005


def test_short_tag_needs_allow_legacy():
    with pytest.raises(NoCommonProfileError):
        select_profile([0x0002])
    assert select_profile([0x0002], allow_legacy=True).dtls_id == 0x0002


def test_policy_prefers_gcm_by_local_order():
    assert select_profile([0x0007, 0x0001]).dtls_id == 0x0007
    assert select_profile([0x0001, 0x0007]).dtls_id == 0x0001
    assert select_profile([0x0008, 0x0007, 0x0001]).dtls_id == 0x0008


def test_no_common_profile_raises():
    with pytest.raises(NoCommonProfileError):
        select_profile([])
    with pytest.raises(NoCommonProfileError):
        select_profile([0x0099, 0xFFFF])


def test_duplicates_in_offer_ignored():
    assert select_profile([0x0005, 0x0005, 0x0007, 0x0007]).dtls_id == 0x0007


def test_unknown_ids_skipped_not_fatal():
    assert select_profile([0x0099, 0x0007]).dtls_id == 0x0007
