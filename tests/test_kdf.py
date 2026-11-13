"""Key derivation and AES-CM against RFC 3711 App. B.2 and B.3, RFC 6188 sec. 7, RFC 7714 errata."""

from __future__ import annotations

import pytest

from srtpkit import aescm, kdf
from srtpkit.params import profile

H = bytes.fromhex

# RFC 3711 B.3.
MK = H("E1F97A0D3E018BE0D64FA32C06DE4139")
MS = H("0EC675AD498AFEEBB6960B3AABE6")
AUTH_94 = H(
    "CEBE321F6FF7716B6FD4AB49AF256A15"
    "6D38BAA48F0A0ACF3C34E2359E6CDBCE"
    "E049646C43D9327AD175578EF7227098"
    "6371C10C9A369AC2F94A8C5FBCDDDC25"
    "6D6E919A48B610EF17C2041E47403576"
    "6B68642C59BBFC2F34DB60DBDFB2"
)


def test_appendix_b3_vectors():
    assert kdf.derive(MK, MS, kdf.LABEL_SRTP_ENCRYPTION, 16) == H(
        "C61E7A93744F39EE10734AFE3FF7A087"
    )
    assert kdf.derive(MK, MS, kdf.LABEL_SRTP_SALT, 14) == H("30CBBC08863D8C85D49DB34A9AE1")
    # B.3 derives 94 octets of "auth key" blocks; rejected erratum 7606 notes the profile needs 20.
    assert kdf.derive(MK, MS, kdf.LABEL_SRTP_AUTHENTICATION, 94) == AUTH_94
    assert kdf.derive(MK, MS, kdf.LABEL_SRTP_AUTHENTICATION, 20) == AUTH_94[:20]


def test_aes_256_cm_prf_vectors_rfc6188():
    mk = H("f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6")
    ms = H("3b04803de51ee7c96423ab5b78d2")
    assert kdf.derive(mk, ms, 0x00, 32) == H(
        "5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4"
    )
    assert kdf.derive(mk, ms, 0x02, 14) == H("fa31791685ca444a9e07c6c64e93")
    assert kdf.derive(mk, ms, 0x01, 20) == H("fd9c32d39ed5fbb5a9dc96b30818454d1313dc05")


def test_derive_session_keys_follows_the_profile():
    keys = kdf.derive_session_keys(profile(0x0001), MK, MS)
    assert keys.encryption_key == H("C61E7A93744F39EE10734AFE3FF7A087")
    assert keys.salt == H("30CBBC08863D8C85D49DB34A9AE1")
    assert keys.authentication_key == AUTH_94[:20]
    assert "C61E" not in repr(keys).upper()


def test_label_for_srtcp():
    srtcp = kdf.derive_session_keys(profile(0x0001), MK, MS, srtcp=True)
    assert srtcp.encryption_key == kdf.derive(MK, MS, 0x03, 16)
    assert srtcp.authentication_key == kdf.derive(MK, MS, 0x04, 20)
    assert srtcp.salt == kdf.derive(MK, MS, 0x05, 14)
    assert srtcp.encryption_key != kdf.derive_session_keys(profile(0x0001), MK, MS).encryption_key


def test_gcm_salt_widened_by_2_16():
    """RFC 7714 erratum 4938: the 96-bit salt times 2^16 is the 112-bit KDF salt."""
    salt96 = H("000102030405060708090a0b")
    assert kdf.widen_aead_salt(salt96) == salt96 + b"\x00\x00"
    assert int.from_bytes(kdf.widen_aead_salt(salt96), "big") == int.from_bytes(salt96, "big") << 16
    # Using the 12 octets unwidened and right-aligned would derive different keys; the KDF
    # refuses the short salt rather than guess.
    with pytest.raises(ValueError, match="112 bits"):
        kdf.derive(MK, salt96, 0, 16)
    keys = kdf.derive_session_keys(profile(0x0007), MK, salt96)
    assert keys.encryption_key == kdf.derive(MK, salt96 + b"\x00\x00", 0x00, 16)
    assert keys.salt == kdf.derive(MK, salt96 + b"\x00\x00", 0x02, 12)
    assert keys.authentication_key == b""
    assert keys.encryption_key != kdf.derive(MK, b"\x00\x00" + salt96, 0x00, 16)


def test_gcm_256_uses_the_aes_256_prf():
    mk = bytes(range(32))
    keys = kdf.derive_session_keys(profile(0x0008), mk, bytes(12))
    assert len(keys.encryption_key) == 32
    assert keys.encryption_key == kdf.derive(mk, bytes(14), 0x00, 32)
    with pytest.raises(ValueError, match="profile"):
        kdf.derive_session_keys(profile(0x0008), MK, bytes(12))  # a 128-bit key for AES-256-GCM


def test_kdr_zero_means_derive_once():
    assert kdf.derive(MK, MS, 0, 16, index=12345, kdr=0) == kdf.derive(MK, MS, 0, 16)


def test_kdr_nonzero_changes_keys_on_each_period():
    first = kdf.derive(MK, MS, 0, 16, index=0, kdr=1 << 16)
    assert kdf.derive(MK, MS, 0, 16, index=(1 << 16) - 1, kdr=1 << 16) == first
    assert kdf.derive(MK, MS, 0, 16, index=1 << 16, kdr=1 << 16) != first


def test_output_length_not_multiple_of_16():
    full = kdf.derive(MK, MS, 1, 48)
    for length in (1, 15, 17, 33):
        assert kdf.derive(MK, MS, 1, length) == full[:length]


def test_null_profile_is_refused_loudly():
    with pytest.raises(NotImplementedError):
        kdf.derive_session_keys(profile(0x0005), b"", b"")


def test_aes_cm_keystream_vectors_rfc3711_b2():
    key = H("2B7E151628AED2A6ABF7158809CF4F3C")
    ctr = H("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000")
    stream = aescm.keystream(key, ctr, 65282 * 16)
    assert stream[:16] == H("E03EAD0935C95E80E166B16DD92B4EB4")
    assert stream[16:32] == H("D23513162B02D0F72A43A2FE4A5F97AB")
    assert stream[32:48] == H("41E95B3BB0A2E8DD477901E4FCA894C0")
    assert stream[0xFEFF * 16 : 0xFF00 * 16] == H("EC8CDF7398607CB0F2D21675EA9EA1E4")
    assert stream[0xFF00 * 16 : 0xFF01 * 16] == H("362B7C3C6773516318A077D7FC5073AE")
    assert stream[0xFF01 * 16 : 0xFF02 * 16] == H("6A2CC3787889374FBEB4C81B17BA6C44")
    # the session salt is "already shifted" and the SSRC and index are zero
    assert aescm.iv(H("F0F1F2F3F4F5F6F7F8F9FAFBFCFD"), 0, 0) == ctr


def test_aes_256_cm_keystream_vectors_rfc6188():
    key = H("57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98")
    stream = aescm.keystream(key, H("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000"), 65282 * 16)
    assert stream[:16] == H("92bdd28a93c3f52511c677d08b5515a4")
    assert stream[0xFEFF * 16 : 0xFF00 * 16] == H("cea518c90fd91ced9cbb18c078a54711")
    assert stream[0xFF01 * 16 : 0xFF02 * 16] == H("6eb246913062a16891433e97dd01a57f")


def test_aes_192_cm_keystream_vectors_rfc6188():
    key = H("eab234764e517b2d3d160d587d8c86219740f65f99b6bcf7")
    stream = aescm.keystream(key, H("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000"), 65282 * 16)
    assert stream[:16] == H("35096cba4610028dc1b57503804ce37c")
    assert stream[0xFF01 * 16 : 0xFF02 * 16] == H("a5dab625811034e8cebdfeb6dc158dd3")


def test_crypt_roundtrip_and_iv_layout():
    key, salt = bytes(range(16)), bytes(range(14))
    data = b"payload of 21 octets.."
    sealed = aescm.crypt(key, salt, 0xDEADBEEF, 0x0001_0002_0003, data)
    assert sealed != data
    assert aescm.crypt(key, salt, 0xDEADBEEF, 0x0001_0002_0003, sealed) == data
    assert aescm.crypt(key, salt, 0xDEADBEEF, 0x0001_0002_0004, data) != sealed
    # (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
    expected = (int.from_bytes(salt, "big") << 16) ^ (0xDEADBEEF << 64) ^ (0x0001_0002_0003 << 16)
    assert aescm.iv(salt, 0xDEADBEEF, 0x0001_0002_0003) == expected.to_bytes(16, "big")


def test_keystream_limits():
    with pytest.raises(ValueError, match="2\\^16"):
        aescm.keystream(MK, bytes(16), 65537 * 16)
    with pytest.raises(ValueError, match="16, 24 or 32"):
        aescm.keystream(bytes(15), bytes(16), 16)
