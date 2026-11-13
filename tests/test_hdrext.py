"""RTP header extension encryption (RFC 6904) against its Appendix A vectors."""

from __future__ import annotations

import pytest

from srtpkit import aescm, hdrext
from srtpkit.context import derive_stream_keys, for_stream
from srtpkit.errors import AuthenticationError, SrtpError
from srtpkit.kdf import SessionKeys
from srtpkit.params import profile
from srtpkit.transform import protect, unprotect

H = bytes.fromhex

# Appendix A.1: the master key and salt of RFC 3711 Appendix B.3.
MASTER_KEY = H("E1F97A0D3E018BE0D64FA32C06DE4139")
MASTER_SALT = H("0EC675AD498AFEEBB6960B3AABE6")
HEADER_KEY = H("549752054D6FB708622C4A2E596A1B93")
HEADER_SALT = H("AB01818174C40D39A3781F7C2D27")

# Appendix A.2: SSRC 0xCAFEBABE, sequence number 0x1234, rollover counter 0.
SSRC = 0xCAFEBABE
INDEX = 0x1234
PLAINTEXT = H("17414273A475262748220000C8308E4655996386B395FB00")
MASK = H("00FFFFFFFFFFFFFFFF0000000000FF00FFFFFFFFFFFFFF00")
CIPHERTEXT = H("17588A9270F4E15E1C220000C8309546A994F0BC54789700")
KEYSTREAM = H("1E19C8E1D481C779549ED1617AAA1B7AFC0D933AE7ED6CC8")
ENCRYPTED_IDS = {1, 3, 4}  # the printed mask selects these; the RFC's prose says "1, 2, and 4"


def test_appendix_a1_key_derivation():
    keys = hdrext.derive_header_keys(profile(0x0001), MASTER_KEY, MASTER_SALT)
    assert keys.encryption_key == HEADER_KEY
    assert keys.salt == HEADER_SALT
    assert keys.authentication_key == b""


def test_appendix_a2_init_counter_keystream_mask_and_ciphertext():
    assert aescm.iv(HEADER_SALT, SSRC, INDEX) == H("AB018181BE3AB787A3781F7C3F130000")
    assert aescm.crypt(HEADER_KEY, HEADER_SALT, SSRC, INDEX, bytes(24)) == KEYSTREAM
    mask = hdrext.encryption_mask(PLAINTEXT, ENCRYPTED_IDS, two_byte=False)
    assert mask == MASK
    keys = SessionKeys(HEADER_KEY, b"", HEADER_SALT)
    head = H("900f1234decafbadcafebabebede0006") + PLAINTEXT
    sealed = hdrext.apply(head, keys, SSRC, INDEX, ENCRYPTED_IDS)
    assert sealed == H("900f1234decafbadcafebabebede0006") + CIPHERTEXT
    # the operation is its own inverse (RFC 6904 sec. 3 paragraph 9)
    assert hdrext.apply(sealed, keys, SSRC, INDEX, ENCRYPTED_IDS) == head


def test_rfc6904_vectors():
    # the umbrella row: A.1 and A.2 end to end from the master key
    keys = hdrext.derive_header_keys(profile(0x0001), MASTER_KEY, MASTER_SALT)
    head = H("900f1234decafbadcafebabebede0006") + PLAINTEXT
    sealed = hdrext.apply(head, keys, SSRC, INDEX, ENCRYPTED_IDS)
    assert sealed[16:] == CIPHERTEXT
    assert sealed[:16] == head[:16]  # profile and length stay in the clear (sec. 3 paragraph 10)


def test_the_mask_follows_rfc_8285_framing():
    # two-byte elements: ID 5 length 2, a padding octet, ID 9 length 1
    two_byte = H("0502aabb000901cc00")
    assert hdrext.encryption_mask(two_byte, {9}, two_byte=True) == H("00000000000000ff00")
    assert hdrext.encryption_mask(two_byte, {5, 9}, two_byte=True) == H("0000ffff000000ff00")
    # one-byte: ID 15 stops the parse, so what follows is never selected
    one_byte = H("10aaf01001")
    assert hdrext.encryption_mask(one_byte, {1}, two_byte=False) == H("00ff000000")
    for bad in (H("17aa"), H("10")):  # an element running past the end
        with pytest.raises(SrtpError):
            hdrext.encryption_mask(bad, {1}, two_byte=False)
    with pytest.raises(SrtpError):
        hdrext.encryption_mask(H("05"), {5}, two_byte=True)


def _rtp(extension: bytes) -> bytes:
    words = len(extension) // 4
    return (
        H("900f1234decafbadcafebabe")
        + H("bede")
        + words.to_bytes(2, "big")
        + extension
        + b"payload!"
    )


def contexts():
    keys = derive_stream_keys(profile(0x0001), MASTER_KEY, MASTER_SALT, header_extension=True)
    return for_stream(SSRC, keys), for_stream(SSRC, keys)


def test_protect_and_unprotect_encrypt_the_extension_before_the_tag():
    sender, receiver = contexts()
    packet = _rtp(PLAINTEXT)
    sealed = protect(packet, sender, encrypted_extensions=ENCRYPTED_IDS)
    assert sealed[16:40] == CIPHERTEXT  # the Appendix A.2 ciphertext sits in the SRTP packet
    assert sealed[:16] == packet[:16]
    # the tag is over the encrypted extension: it equals protecting with the extension pre-encrypted
    pre = packet[:16] + CIPHERTEXT + packet[40:]
    other, _ = contexts()
    assert protect(pre, other) == sealed[:40] + sealed[40:]  # same payload keystream and tag
    assert unprotect(sealed, receiver, encrypted_extensions=ENCRYPTED_IDS) == packet


def test_a_forged_extension_fails_before_it_is_decrypted():
    sender, receiver = contexts()
    sealed = bytearray(protect(_rtp(PLAINTEXT), sender, encrypted_extensions=ENCRYPTED_IDS))
    sealed[20] ^= 1  # inside an encrypted element body
    with pytest.raises(AuthenticationError):
        unprotect(bytes(sealed), receiver, encrypted_extensions=ENCRYPTED_IDS)
    assert receiver.replay.check(INDEX)  # nothing was recorded


def test_refusals():
    sender, _ = contexts()
    packet = _rtp(PLAINTEXT)
    with pytest.raises(SrtpError, match="Cryptex"):
        protect(packet, sender, cryptex=True, encrypted_extensions={1})
    keys = derive_stream_keys(profile(0x0001), MASTER_KEY, MASTER_SALT)  # no header keys
    with pytest.raises(SrtpError, match="header_extension"):
        protect(packet, for_stream(SSRC, keys), encrypted_extensions={1})
    with pytest.raises(SrtpError, match="no header extension"):
        protect(H("800f1234decafbadcafebabe") + b"x", sender, encrypted_extensions={1})
    gcm_keys = derive_stream_keys(profile(0x0007), bytes(16), bytes(12))
    with pytest.raises(NotImplementedError, match="AES-CM"):
        protect(packet, for_stream(SSRC, gcm_keys), encrypted_extensions={1})
    with pytest.raises(NotImplementedError, match="AES-CM"):
        derive_stream_keys(profile(0x0007), bytes(16), bytes(12), header_extension=True)
