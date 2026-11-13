"""SRTP and SRTCP packet protection against RFC 7714 sec. 16 and 17, and an independent AES-CM oracle."""

from __future__ import annotations

import hashlib
import hmac
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from srtpkit.context import StreamKeys, derive_stream_keys, for_stream
from srtpkit.errors import AuthenticationError, KeyLifetimeError, ReplayError, SrtpError
from srtpkit.kdf import SessionKeys
from srtpkit.params import profile
from srtpkit.rtp import parse_header
from srtpkit.srtcp import protect_rtcp, unprotect_rtcp
from srtpkit.transform import protect, unprotect

H = bytes.fromhex

# RFC 7714 sec. 16: the packet, the salt "Quid pro quo" and the keys 00..0f and 00..1f.
RTP = H(
    "8040f17b8041f8d35501a0b247616c6c69612065 7374206f6d6e697320646976"
    "69736120696e20706172746573207472 6573".replace(" ", "")
)
SSRC = 0x5501A0B2
SALT = H("517569642070726f2071756f")
KEY128 = bytes(range(16))
KEY256 = bytes(range(32))
SRTP_128 = H(
    "8040f17b8041f8d35501a0b2f24de3a3fb34de6cacba861c9d7e4bcabe633bd5"
    "0d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce"
)
SRTP_256 = H(
    "8040f17b8041f8d35501a0b232b1de78a822fe12ef9f78fa332e33aab18012389a58e2f3"
    "b50b2a0276ffae0f1ba63799b87b7aa3db36dfffd6b0f9bb7878d7a76c13"
)


def explicit(profile_id, key, salt=SALT):
    """A context whose session keys are given, as RFC 7714 sec. 16 gives them (no KDF)."""
    session = SessionKeys(key, b"", salt)
    return StreamKeys(profile(profile_id), session, session)


def test_rfc7714_section16_protect():
    for profile_id, key, expected in ((0x0007, KEY128, SRTP_128), (0x0008, KEY256, SRTP_256)):
        ctx = for_stream(SSRC, explicit(profile_id, key))
        assert protect(RTP, ctx) == expected  # sec. 16.1.1 and sec. 16.2.1 "Encrypted and tagged"
        assert ctx.index.s_l == 0xF17B
        assert ctx.srtp_packets == 1


def test_rfc7714_section16_unprotect():
    for profile_id, key, sealed in ((0x0007, KEY128, SRTP_128), (0x0008, KEY256, SRTP_256)):
        ctx = for_stream(SSRC, explicit(profile_id, key))
        assert unprotect(sealed, ctx) == RTP  # sec. 16.1.2 and sec. 16.2.2
        assert ctx.index.s_l == 0xF17B
        with pytest.raises(ReplayError):
            unprotect(sealed, ctx)  # the same packet again


def test_gcm_tamper_and_failure_leave_the_context_unchanged():
    ctx = for_stream(SSRC, explicit(0x0007, KEY128))
    for position in (0, 5, 11, 12, 30, len(SRTP_128) - 1):  # header, SSRC, payload and tag
        bad = bytearray(SRTP_128)
        bad[position] ^= 0x01
        with pytest.raises((AuthenticationError, SrtpError)):
            unprotect(bytes(bad), ctx)
        assert ctx.index.s_l is None
        assert ctx.replay.highest is None
    assert unprotect(SRTP_128, ctx) == RTP  # the genuine packet still works afterwards
    with pytest.raises(SrtpError, match="shorter"):
        unprotect(SRTP_128[:20], for_stream(SSRC, explicit(0x0007, KEY128)))


# --- AES-CM with HMAC-SHA1, against an oracle written straight from the RFC text -----------

MASTER_KEY = H("E1F97A0D3E018BE0D64FA32C06DE4139")  # RFC 3711 appendix B.3
MASTER_SALT = H("0EC675AD498AFEEBB6960B3AABE6")
K_E = H("C61E7A93744F39EE10734AFE3FF7A087")  # B.3 session keys
K_S = H("30CBBC08863D8C85D49DB34A9AE1")


def oracle_protect(packet, roc, tag_bytes, k_a):
    """RFC 3711 sec. 3.3, 4.1.1 and 4.2.1 written out with no srtpkit code."""
    seq = struct.unpack_from(">H", packet, 2)[0]
    ssrc = struct.unpack_from(">I", packet, 8)[0]
    index = (roc << 16) | seq
    iv = ((int.from_bytes(K_S, "big") << 16) ^ (ssrc << 64) ^ (index << 16)).to_bytes(16, "big")
    stream = Cipher(algorithms.AES(K_E), modes.CTR(iv)).encryptor()
    body = stream.update(packet[12:]) + stream.finalize()
    sealed = packet[:12] + body
    return (
        sealed + hmac.new(k_a, sealed + roc.to_bytes(4, "big"), hashlib.sha1).digest()[:tag_bytes]
    )


def rtp_packet(seq, payload=b"hello srtp", ssrc=0xDEADBEEF):
    return struct.pack(">BBHII", 0x80, 96, seq, 1000 + seq, ssrc) + payload


def cm_pair(profile_id=0x0001, ssrc=0xDEADBEEF):
    keys = derive_stream_keys(profile(profile_id), MASTER_KEY, MASTER_SALT)
    return for_stream(ssrc, keys), for_stream(ssrc, keys), keys


def test_srtp_aes_cm_matches_the_oracle_and_roundtrips():
    for profile_id, tag_bytes in ((0x0001, 10), (0x0002, 4)):
        sender, receiver, keys = cm_pair(profile_id)
        assert keys.srtp.encryption_key == K_E  # the appendix B.3 session keys
        packet = rtp_packet(7)
        sealed = protect(packet, sender)
        assert sealed == oracle_protect(packet, 0, tag_bytes, keys.srtp.authentication_key)
        assert len(sealed) == len(packet) + tag_bytes
        assert sealed[:12] == packet[:12]  # the header stays in the clear
        assert unprotect(sealed, receiver) == packet


def test_rollover_counter_is_in_the_tag_and_both_sides_agree():
    sender, receiver, keys = cm_pair()
    sender.index.s_l = 0xFFFE  # a stream near the end of its sequence space
    receiver.index.s_l = 0xFFFE
    sent = [protect(rtp_packet(seq), sender) for seq in (0xFFFF, 0, 1)]
    assert sender.index.roc == 1
    assert sent[1] == oracle_protect(rtp_packet(0), 1, 10, keys.srtp.authentication_key)
    for seq, sealed in zip((0xFFFF, 0, 1), sent, strict=True):
        assert unprotect(sealed, receiver) == rtp_packet(seq)
    assert receiver.index.roc == 1
    # a receiver that was told the wrong ROC cannot authenticate the packet
    wrong = for_stream(0xDEADBEEF, keys)
    wrong.index.roc = 5
    wrong.index.s_l = 0xFFFE
    with pytest.raises(AuthenticationError):
        unprotect(sent[0], wrong)


def test_replay_reorder_and_forgery_for_aes_cm():
    sender, receiver, _ = cm_pair()
    packets = [protect(rtp_packet(s), sender) for s in range(10, 16)]
    for sealed in (packets[0], packets[3], packets[2]):  # out of order, inside the window
        unprotect(sealed, receiver)
    with pytest.raises(ReplayError):
        unprotect(packets[3], receiver)
    forged = bytearray(packets[1])
    forged[14] ^= 1
    with pytest.raises(AuthenticationError):
        unprotect(bytes(forged), receiver)
    assert receiver.replay.check(11)  # the failed packet did not enter the window
    assert unprotect(packets[1], receiver) == rtp_packet(11)  # the forgery did not burn it
    with pytest.raises(SrtpError, match="SSRC"):
        unprotect(protect(rtp_packet(1, ssrc=7), for_stream(7, cm_pair()[2])), receiver)


def test_csrc_list_and_header_extension_are_authenticated_not_encrypted():
    sender, receiver, keys = cm_pair()
    first = 0x80 | 0x10 | 2  # V=2, X, CC=2
    header = struct.pack(">BBHII", first, 96, 5, 9, 0xDEADBEEF)
    header += struct.pack(">II", 1, 2)  # CSRC list
    header += struct.pack(">HH", 0xBEDE, 1) + b"\x11\x22\x33\x44"  # one extension word
    packet = header + b"payload"
    parsed = parse_header(packet)
    assert (parsed.csrc, parsed.extension, parsed.header_length) == ((1, 2), True, len(header))
    sealed = protect(packet, sender)
    assert sealed[: len(header)] == header
    assert sealed[len(header) : -10] != b"payload"
    assert unprotect(sealed, receiver) == packet
    tampered = bytearray(sealed)
    tampered[14] ^= 1  # a CSRC octet
    with pytest.raises(AuthenticationError):
        unprotect(bytes(tampered), for_stream(0xDEADBEEF, keys))
    # AES-GCM takes the same header as associated data
    gcm_ctx = for_stream(0xDEADBEEF, explicit(0x0007, KEY128))
    sealed_gcm = protect(packet, gcm_ctx)
    assert sealed_gcm[: len(header)] == header
    tampered = bytearray(sealed_gcm)
    tampered[len(header) - 2] ^= 1  # inside the extension
    with pytest.raises(AuthenticationError):
        unprotect(bytes(tampered), for_stream(0xDEADBEEF, explicit(0x0007, KEY128)))


def test_header_parse_lengths():
    assert parse_header(rtp_packet(3)).header_length == 12
    assert parse_header(rtp_packet(3)).sequence == 3
    with pytest.raises(SrtpError, match="12-octet"):
        parse_header(b"\x80" * 11)
    with pytest.raises(SrtpError, match="version"):
        parse_header(b"\x40" + bytes(11))
    with pytest.raises(SrtpError, match="CSRC"):
        parse_header(b"\x83" + bytes(11))
    with pytest.raises(SrtpError, match="extension header"):
        parse_header(b"\x90" + bytes(11))
    with pytest.raises(SrtpError, match="header extension"):
        parse_header(b"\x90" + bytes(11) + struct.pack(">HH", 0, 2) + bytes(4))
    assert parse_header(b"\x90" + bytes(11) + struct.pack(">HH", 0, 0)).header_length == 16


def test_packet_limits_and_rekey_keeps_the_rollover_counter():
    sender, _, keys = cm_pair()
    sender.srtp_packets = keys.profile.max_srtp_packets
    with pytest.raises(KeyLifetimeError):
        protect(rtp_packet(1), sender)
    protect_ok = for_stream(0xDEADBEEF, keys)
    protect_ok.index.roc = 3
    protect_ok.index.s_l = 100
    protect_ok.srtcp_index = 42
    new_keys = derive_stream_keys(profile(0x0001), bytes(16), bytes(14))
    protect_ok.rekey(new_keys)
    assert (protect_ok.index.roc, protect_ok.srtcp_index) == (
        3,
        42,
    )  # sec. 3.3.1 para 9, sec. 3.4 para 8
    assert protect_ok.keys is new_keys
    assert protect_ok.srtp_packets == 0


def test_a_packet_for_another_ssrc_is_refused_on_protect():
    sender, _, _ = cm_pair()
    with pytest.raises(SrtpError, match="SSRC"):
        protect(rtp_packet(1, ssrc=1), sender)
    with pytest.raises(ValueError, match="32 bits"):
        for_stream(1 << 32, sender.keys)


def test_null_cipher_authenticates_without_encrypting():
    session = SessionKeys(b"", bytes(range(20)), b"")
    keys = StreamKeys(profile(0x0005), session, session)
    sender, receiver = for_stream(0xDEADBEEF, keys), for_stream(0xDEADBEEF, keys)
    packet = rtp_packet(9)
    sealed = protect(packet, sender)
    assert sealed[:-10] == packet  # RFC 3711 sec. 4.1.3: the payload is copied
    assert unprotect(sealed, receiver) == packet
    bad = bytearray(sealed)
    bad[13] ^= 1
    with pytest.raises(AuthenticationError):
        unprotect(bytes(bad), for_stream(0xDEADBEEF, keys))


# --- SRTCP ------------------------------------------------------------------------------------

RTCP_CORRECTED = H(
    "81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61" + "deadbeef" * 5
)  # RFC 7714 sec. 17 as corrected by erratum 7858
SRTCP_CIPHER = H(
    "63e94885dcdab67ca727d7662f6b7e997ff5c0f76c06f32dc676a5f1730d6fda"
    "4ce09b4686303ded0bb9275bc84aa45896cf4d2fc5abf87245d9eade"
)


def test_rfc7714_section17_protect():
    ctx = for_stream(0x4D617273, explicit(0x0007, KEY128))
    ctx.srtcp_index = 0x5D4
    sealed = protect_rtcp(RTCP_CORRECTED, ctx)
    assert sealed == RTCP_CORRECTED[:8] + SRTCP_CIPHER + H("800005d4")  # E-flag and index last
    assert ctx.srtcp_index == 0x5D5


def test_rfc7714_section17_unprotect():
    sealed = RTCP_CORRECTED[:8] + SRTCP_CIPHER + H("800005d4")
    ctx = for_stream(0x4D617273, explicit(0x0007, KEY128))
    assert unprotect_rtcp(sealed, ctx) == RTCP_CORRECTED
    with pytest.raises(ReplayError):
        unprotect_rtcp(sealed, ctx)
    bad = bytearray(sealed)
    bad[10] ^= 1
    with pytest.raises(AuthenticationError):
        unprotect_rtcp(bytes(bad), for_stream(0x4D617273, explicit(0x0007, KEY128)))
    flipped_e = bytearray(sealed)
    flipped_e[-4] = 0x00  # clearing the E-flag changes the associated data too
    with pytest.raises(AuthenticationError):
        unprotect_rtcp(bytes(flipped_e), for_stream(0x4D617273, explicit(0x0007, KEY128)))


def test_srtcp_gcm_without_encryption_and_aes_cm_both_ways():
    for ctx_keys in (
        explicit(0x0007, KEY128),
        derive_stream_keys(profile(0x0001), MASTER_KEY, MASTER_SALT),
    ):
        sender, receiver = for_stream(0x4D617273, ctx_keys), for_stream(0x4D617273, ctx_keys)
        for encrypt in (True, False):
            sealed = protect_rtcp(RTCP_CORRECTED, sender, encrypt=encrypt)
            (word,) = struct.unpack_from(
                ">I", sealed, len(sealed) - (4 if ctx_keys.profile.cipher == "AES_GCM" else 14)
            )
            assert bool(word >> 31) == encrypt
            assert (RTCP_CORRECTED[8:] in sealed) == (not encrypt)  # clear payload only when E=0
            assert unprotect_rtcp(sealed, receiver) == RTCP_CORRECTED
        assert sender.srtcp_index == 2


def test_srtcp_aes_cm_tag_is_80_bits_even_for_the_32_bit_profile_and_covers_the_index():
    keys = derive_stream_keys(profile(0x0002), MASTER_KEY, MASTER_SALT)
    sender, receiver = for_stream(0x4D617273, keys), for_stream(0x4D617273, keys)
    sealed = protect_rtcp(RTCP_CORRECTED, sender)
    assert len(sealed) == len(RTCP_CORRECTED) + 4 + 10
    bad = bytearray(sealed)
    bad[-11] ^= 1  # the low bit of the index
    with pytest.raises(AuthenticationError):
        unprotect_rtcp(bytes(bad), receiver)
    assert unprotect_rtcp(sealed, receiver) == RTCP_CORRECTED


def test_srtcp_index_wraps_and_limits_and_errors():
    keys = explicit(0x0007, KEY128)
    ctx = for_stream(0x4D617273, keys)
    ctx.srtcp_index = (1 << 31) - 1
    protect_rtcp(RTCP_CORRECTED, ctx)
    assert ctx.srtcp_index == 0  # modulo 2^31, sec. 3.4 paragraph 8
    ctx.srtcp_packets = keys.profile.max_srtcp_packets
    with pytest.raises(KeyLifetimeError):
        protect_rtcp(RTCP_CORRECTED, ctx)
    fresh = for_stream(0x4D617273, keys)
    with pytest.raises(SrtpError, match="SSRC"):
        protect_rtcp(RTCP_CORRECTED[:4] + bytes(4) + RTCP_CORRECTED[8:], fresh)
    with pytest.raises(SrtpError, match="shorter"):
        protect_rtcp(b"\x81\xc8", fresh)
    with pytest.raises(SrtpError, match="shorter"):
        unprotect_rtcp(b"\x81" * 20, fresh)
    with pytest.raises(SrtpError, match="version"):
        protect_rtcp(b"\x01" + RTCP_CORRECTED[1:], fresh)


def test_srtcp_aes_cm_matches_an_oracle_from_the_rfc_text():
    # RFC 3711 sec. 3.4: encrypted portion from octet 9, E+index appended, HMAC over all of it
    keys = derive_stream_keys(profile(0x0001), MASTER_KEY, MASTER_SALT)
    ctx = for_stream(0x4D617273, keys)
    ctx.srtcp_index = 0x1234
    sealed = protect_rtcp(RTCP_CORRECTED, ctx)
    iv = (
        (int.from_bytes(keys.srtcp.salt, "big") << 16) ^ (0x4D617273 << 64) ^ (0x1234 << 16)
    ).to_bytes(16, "big")
    stream = Cipher(algorithms.AES(keys.srtcp.encryption_key), modes.CTR(iv)).encryptor()
    body = stream.update(RTCP_CORRECTED[8:]) + stream.finalize()
    word = struct.pack(">I", (1 << 31) | 0x1234)
    sealed_part = RTCP_CORRECTED[:8] + body + word
    tag = hmac.new(keys.srtcp.authentication_key, sealed_part, hashlib.sha1).digest()[:10]
    assert sealed == sealed_part + tag
    # the SRTCP keys are the label 3, 4 and 5 keys, not the SRTP ones
    assert keys.srtcp.encryption_key != keys.srtp.encryption_key


def test_split_keying_material_order_and_lengths():
    from srtpkit.dtls import split_keying_material

    material = (
        bytes(range(16)) + bytes(range(16, 32)) + bytes(range(100, 114)) + bytes(range(200, 214))
    )
    client, server = split_keying_material(profile(0x0001), material)
    assert client.master_key == bytes(range(16))  # RFC 5764 sec. 4.2: client key first,
    assert server.master_key == bytes(range(16, 32))  # then server key,
    assert client.master_salt == bytes(range(100, 114))  # then client salt,
    assert server.master_salt == bytes(range(200, 214))  # then server salt
    gcm_client, _ = split_keying_material(profile(0x0007), bytes(2 * (16 + 12)))
    assert (len(gcm_client.master_key), len(gcm_client.master_salt)) == (16, 12)
    big, _ = split_keying_material(profile(0x0008), bytes(2 * (32 + 12)))
    assert len(big.master_key) == 32
    with pytest.raises(ValueError, match="needs 60 octets"):
        split_keying_material(profile(0x0001), material[:-1])
    # RFC 5764 sec. 4.1.2: the NULL profiles have no key or salt, so there is nothing to export
    empty_client, empty_server = split_keying_material(profile(0x0005), b"")
    assert (empty_client.master_key, empty_client.master_salt) == (b"", b"")
    assert empty_server == empty_client
