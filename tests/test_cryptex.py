"""Cryptex (RFC 9335) against the RFC's own Appendix A vectors."""

from __future__ import annotations

import pytest

from srtpkit import cryptex
from srtpkit.context import derive_stream_keys, for_stream
from srtpkit.errors import AuthenticationError, ReplayError, SrtpError
from srtpkit.params import profile
from srtpkit.transform import protect, unprotect

H = bytes.fromhex
SSRC = 0xCAFEBABE
FILL = "abababab" * 4

# RFC 9335 appendix A: the six plain packets (A.1.1 to A.1.6, the same for AES-GCM) ...
PLAIN = {
    "one-byte": H("900f1235decafbadcafebabebede000151000200" + FILL),
    "two-byte": H("900f1236decafbadcafebabe1000000105020002" + FILL),
    "one-byte+csrc": H("920f1238decafbadcafebabe0001e2400000b26ebede000151000200" + FILL),
    "two-byte+csrc": H("920f1239decafbadcafebabe0001e2400000b26e1000000105020002" + FILL),
    "empty-one-byte+csrc": H("920f123adecafbadcafebabe0001e2400000b26ebede0000" + FILL),
    "empty-two-byte+csrc": H("920f123bdecafbadcafebabe0001e2400000b26e10000000" + FILL),
}
# ... and their encrypted forms with AES_CM_128_HMAC_SHA1_80 (A.1) ...
AES_CM = {
    "one-byte": H(
        "900f1235decafbadcafebabe"
        "c0de0001"
        "eb923652"
        "51c3e036"
        "f8de27e9"
        "c27ee3e0"
        "b4651d9f"
        "bc4218a7"
        "0244522f"
        "34a5"
    ),
    "two-byte": H(
        "900f1236decafbadcafebabe"
        "c2de0001"
        "4ed9cc4e"
        "6a712b30"
        "96c5ca77"
        "339d4204"
        "ce0d7739"
        "6cab6958"
        "5fbce381"
        "94a5"
    ),
    "one-byte+csrc": H(
        "920f1238decafbadcafebabe"
        "8bb6e12b"
        "5cff16dd"
        "c0de0001"
        "92838c8c"
        "09e58393"
        "e1de3a9a"
        "74734d67"
        "45671338"
        "c3acf11d"
        "a2df8423"
        "bee0"
    ),
    "two-byte+csrc": H(
        "920f1239decafbadcafebabe"
        "f70e513e"
        "b90b9b25"
        "c2de0001"
        "bbed4848"
        "faa64466"
        "5f3d7f34"
        "125914e9"
        "f4d0ae92"
        "3c6f479b"
        "95a0f7b5"
        "3133"
    ),
    "empty-one-byte+csrc": H(
        "920f123adecafbadcafebabe"
        "7130b6ab"
        "fe2ab0e3"
        "c0de0000"
        "e3d9f64b"
        "25c9e74c"
        "b4cf8e43"
        "fb92e378"
        "1c2c0cea"
        "b6b3a499"
        "a14c"
    ),
    "empty-two-byte+csrc": H(
        "920f123bdecafbadcafebabe"
        "cbf24c12"
        "4330e1c8"
        "c2de0000"
        "599dd45b"
        "c9d687b6"
        "03e8b59d"
        "771fd38e"
        "88b170e0"
        "cd31e125"
        "eabe"
    ),
}
# ... and with AEAD_AES_128_GCM (A.2).
AES_GCM = {
    "one-byte": H(
        "900f1235decafbadcafebabe"
        "c0de0001"
        "39972dc9"
        "572c4d99"
        "e8fc355d"
        "e743fb2e"
        "94f9d8ff"
        "54e72f41"
        "93bbc5c7"
        "4ffab0fa"
        "9fa0fbeb"
    ),
    "two-byte": H(
        "900f1236decafbadcafebabe"
        "c2de0001"
        "bb75a4c5"
        "45cd1f41"
        "3bdb7daa"
        "2b1e3263"
        "de313667"
        "c9632490"
        "81b35a65"
        "f5cb6c88"
        "b394235f"
    ),
    "one-byte+csrc": H(
        "920f1238decafbadcafebabe"
        "63bbccc4"
        "a7f695c4"
        "c0de0001"
        "8ad7c71f"
        "ac70a80c"
        "92866b4c"
        "6ba98546"
        "ef913586"
        "e95ffaaf"
        "fe956885"
        "bb0647a8"
        "bc094ac8"
    ),
    "two-byte+csrc": H(
        "920f1239decafbadcafebabe"
        "3680524f"
        "8d312b00"
        "c2de0001"
        "c78d1200"
        "38422bc1"
        "11a7187a"
        "18246f98"
        "0c059cc6"
        "bc9df8b6"
        "26394eca"
        "344e4b05"
        "d80fea83"
    ),
    "empty-one-byte+csrc": H(
        "920f123adecafbadcafebabe"
        "15b6bb43"
        "37906fff"
        "c0de0000"
        "b7b96453"
        "7a2b03ab"
        "7ba5389c"
        "e9331712"
        "6b5d974d"
        "f30c6884"
        "dcb651c5"
        "e120c1da"
    ),
    "empty-two-byte+csrc": H(
        "920f123bdecafbadcafebabe"
        "dcb38c9e"
        "48bf95f4"
        "c2de0000"
        "61ee432c"
        "f9203170"
        "76613258"
        "d3ce4236"
        "c06ac429"
        "681ad084"
        "13512dc9"
        "8b5207d8"
    ),
}


def cm_context():
    keys = derive_stream_keys(
        profile(0x0001), H("e1f97a0d3e018be0d64fa32c06de4139"), H("0ec675ad498afeebb6960b3aabe6")
    )
    return keys, for_stream(SSRC, keys)


def gcm_context():
    keys = derive_stream_keys(
        profile(0x0007), H("000102030405060708090a0b0c0d0e0f"), H("a0a1a2a3a4a5a6a7a8a9aaab")
    )
    return keys, for_stream(SSRC, keys)


def test_the_rfc_session_keys_are_what_the_kdf_derives():
    keys, _ = cm_context()
    assert keys.srtp.encryption_key == H("c61e7a93744f39ee10734afe3ff7a087")
    assert keys.srtp.salt == H("30cbbc08863d8c85d49db34a9ae1")
    assert keys.srtp.authentication_key == H("cebe321f6ff7716b6fd4ab49af256a156d38baa4")
    keys, _ = gcm_context()
    assert keys.srtp.encryption_key == H("077c6143cb221bc355ff23d5f984a16e")
    assert keys.srtp.salt == H("9af3e95364ebac9c99c5a7c4")


@pytest.mark.parametrize("name", list(PLAIN))
def test_rfc9335_vectors_aes_cm(name):
    _, ctx = cm_context()
    assert protect(PLAIN[name], ctx, cryptex=True) == AES_CM[name]
    _, receiver = cm_context()
    plain = unprotect(AES_CM[name], receiver, cryptex="accept")
    # the receiver gets the RFC 8285 tag back; a two-byte tag returns with zero appbits, which
    # is what the vectors carry. An empty extension added for CSRCs only is left as is (sec. 5.2).
    assert plain == PLAIN[name]


@pytest.mark.parametrize("name", list(PLAIN))
def test_rfc9335_vectors_aes_gcm(name):
    _, ctx = gcm_context()
    assert protect(PLAIN[name], ctx, cryptex=True) == AES_GCM[name]
    _, receiver = gcm_context()
    assert unprotect(AES_GCM[name], receiver, cryptex="accept") == PLAIN[name]


def test_rfc9335_vectors():
    # the umbrella row: every vector in both appendices in both directions
    for make, vectors in ((cm_context, AES_CM), (gcm_context, AES_GCM)):
        for name, plain in PLAIN.items():
            assert protect(plain, make()[1], cryptex=True) == vectors[name]
            assert unprotect(vectors[name], make()[1], cryptex="accept") == plain


def test_csrcs_without_an_extension_get_an_empty_one():
    # RFC 9335 sec. 5.1 paragraph 3: tag 0xC0DE, length zero, X set
    csrc_only = H("820f1238decafbadcafebabe0001e2400000b26e" + FILL)
    prepared = cryptex.prepare(csrc_only)
    assert prepared[0] == 0x82 | 0x10
    assert prepared[20:24] == H("c0de0000")
    assert prepared[24:] == csrc_only[20:]
    _, ctx = gcm_context()
    sealed = protect(csrc_only, ctx, cryptex=True)
    assert cryptex.is_cryptex(sealed)
    _, receiver = gcm_context()
    opened = unprotect(sealed, receiver, cryptex="accept")
    assert opened[12:20] == csrc_only[12:20]  # the CSRC identifiers come back
    assert opened[20:24] == H("bede0000")  # the empty extension is left in place, tag restored
    assert opened[24:] == csrc_only[20:]


def test_a_packet_with_nothing_to_hide_is_ordinary_srtp():
    plain = H("800f1235decafbadcafebabe" + FILL)
    assert cryptex.prepare(plain) == plain
    _, with_flag = cm_context()
    _, without = cm_context()
    assert protect(plain, with_flag, cryptex=True) == protect(plain, without)
    _, receiver = cm_context()
    assert unprotect(protect(plain, cm_context()[1]), receiver, cryptex="require") == plain


def test_refusals():
    _, ctx = cm_context()
    with pytest.raises(SrtpError, match="RFC 8285"):  # a profile that is neither framing
        protect(H("900f1235decafbadcafebabe1234000151000200" + FILL), ctx, cryptex=True)
    with pytest.raises(SrtpError, match="already"):
        protect(AES_CM["one-byte"], ctx, cryptex=True)
    # without the option a Cryptex packet is refused, not decrypted wrongly
    _, receiver = gcm_context()
    with pytest.raises(SrtpError, match="not enabled"):
        unprotect(AES_GCM["one-byte"], receiver)
    # "require" refuses a clear extension; "accept" takes ordinary packets too
    _, sender = gcm_context()
    ordinary = protect(PLAIN["one-byte"], sender)
    _, receiver = gcm_context()
    with pytest.raises(SrtpError, match="required"):
        unprotect(ordinary, receiver, cryptex="require")
    assert unprotect(ordinary, receiver, cryptex="accept") == PLAIN["one-byte"]


def test_tampering_with_the_encrypted_csrcs_or_the_clear_header_fails():
    for vectors, make in ((AES_CM, cm_context), (AES_GCM, gcm_context)):
        sealed = bytearray(vectors["one-byte+csrc"])
        for position in (13, 21, 30, len(sealed) - 1):  # encrypted CSRC, ext header, body, tag
            forged = bytearray(sealed)
            forged[position] ^= 1
            _, receiver = make()
            with pytest.raises(AuthenticationError):
                unprotect(bytes(forged), receiver, cryptex="accept")
            assert receiver.index.roc == 0
            assert receiver.replay.check(0x1238)  # nothing was recorded


def test_replay_and_failed_packets_leave_the_context_alone():
    _, receiver = gcm_context()
    assert unprotect(AES_GCM["one-byte+csrc"], receiver, cryptex="accept") == PLAIN["one-byte+csrc"]
    with pytest.raises(ReplayError):
        unprotect(AES_GCM["one-byte+csrc"], receiver, cryptex="accept")
    with pytest.raises(SrtpError):
        unprotect(AES_GCM["one-byte+csrc"][:20], receiver, cryptex="accept")
