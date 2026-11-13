"""AES-GCM IV formation (RFC 7714 sec. 8.1, 9.1) and the corrected SRTCP example of erratum 7858.

The AEAD itself is ``cryptography``'s AESGCM, so these tests pin the part that is ours (the IV and
which octets are authenticated) and show that the RFC 7714 sec. 16.1.1 and sec. 17.1 ciphertexts
come out only from the corrected packet of erratum 7858.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from srtpkit.gcm import srtcp_iv, srtp_iv

H = bytes.fromhex
SALT = H("51756964207072 6f2071756f".replace(" ", ""))
KEY = bytes(range(16))

# RFC 7714 sec. 17 prints this packet, then every example uses the corrected one (erratum 7858).
MISPRINTED = H(
    "81c8000e4d617273 4e5450314e545031 525450200000042a 0000eb984c756e61".replace(" ", "")
    + "deadbeef" * 5
)
CORRECTED = H(
    "81c8000d4d6172734e5450314e545032 52545020 0000042a 0000e9304c756e61".replace(" ", "")
    + "deadbeef" * 5
)
SRTCP_ENCRYPTED_WITH_TAG = H(
    "63e94885dcdab67ca727d7662f6b7e99"
    "7ff5c0f76c06f32dc676a5f1730d6fda"
    "4ce09b4686303ded0bb9275bc84aa458"
    "96cf4d2fc5abf87245d9eade"
)


def test_srtp_iv_rfc7714_16():
    assert srtp_iv(SALT, 0x5501A0B2, 0, 0xF17B) == H("51753c6580c2726f20718414")


def test_srtcp_iv_rfc7714_17():
    assert srtcp_iv(SALT, 0x4D617273, 0x5D4) == H("517524055203726f207170bb")


def test_srtp_gcm_encryption_rfc7714_16_1_1():
    packet = H(
        "8040f17b8041f8d35501a0b247616c6c69612065 7374206f6d6e697320646976"
        "69736120696e20706172746573207472 6573".replace(" ", "")
    )
    header, payload = packet[:12], packet[12:]
    sealed = AESGCM(KEY).encrypt(srtp_iv(SALT, 0x5501A0B2, 0, 0xF17B), payload, header)
    assert sealed == H(
        "f24de3a3fb34de6cacba861c9d7e4bca"
        "be633bd50d294e6f42a5f47a51c7d19b"
        "36de3adf8833899d7f27beb16a9152cf765ee4390cce"
    )


def test_srtcp_gcm_encryption_of_the_corrected_packet_rfc7714_17_1():
    esrtcp = H("800005d4")  # E-flag set, index 0x5d4: part of the AAD
    aad = CORRECTED[:8] + esrtcp
    sealed = AESGCM(KEY).encrypt(srtcp_iv(SALT, 0x4D617273, 0x5D4), CORRECTED[8:], aad)
    assert sealed == SRTCP_ENCRYPTED_WITH_TAG


def test_the_misprinted_packet_does_not_reproduce_the_example():
    # Erratum 7858: the packet printed at the top of sec. 17 differs from the one the examples use.
    assert MISPRINTED != CORRECTED
    aad = MISPRINTED[:8] + H("800005d4")
    sealed = AESGCM(KEY).encrypt(srtcp_iv(SALT, 0x4D617273, 0x5D4), MISPRINTED[8:], aad)
    assert sealed != SRTCP_ENCRYPTED_WITH_TAG
