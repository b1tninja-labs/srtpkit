"""Master key selection by MKI (RFC 3711 sec. 3.2.1, sec. 3.3 step 3, sec. 8.1)."""

from __future__ import annotations

import pytest

from srtpkit.context import derive_stream_keys
from srtpkit.errors import SrtpError
from srtpkit.mki import MasterKey, MasterKeys, UnknownMkiError, select_key
from srtpkit.params import profile

H = bytes.fromhex

# RFC 3711 Appendix B.3: the master key and salt, with the session keys it derives.
MK = H("E1F97A0D3E018BE0D64FA32C06DE4139")
MS = H("0EC675AD498AFEEBB6960B3AABE6")
B3_ENCRYPTION_KEY = H("C61E7A93744F39EE10734AFE3FF7A087")
B3_SALT = H("30CBBC08863D8C85D49DB34A9AE1")

OTHER_MK = bytes(range(16))
OTHER_MS = bytes(range(14))


def table() -> MasterKeys:
    return MasterKeys(
        profile(0x0001),
        [MasterKey(b"\x00\x01", MK, MS), MasterKey(b"\x00\x02", OTHER_MK, OTHER_MS)],
    )


def test_select_key():
    keys = table()
    first = select_key(b"\x00\x01", keys)
    # the key the MKI names is the Appendix B.3 master key, so its derived keys are the B.3 vectors
    assert first.srtp.encryption_key == B3_ENCRYPTION_KEY
    assert first.srtp.salt == B3_SALT
    assert first == derive_stream_keys(profile(0x0001), MK, MS)
    # the other identifier selects the other master key, and nothing leaks between them
    second = select_key(b"\x00\x02", keys)
    assert second == derive_stream_keys(profile(0x0001), OTHER_MK, OTHER_MS)
    assert second.srtp.encryption_key != first.srtp.encryption_key
    assert second.srtcp.encryption_key != second.srtp.encryption_key


def test_select_key_refuses_an_unknown_or_misfitting_identifier():
    keys = table()
    with pytest.raises(UnknownMkiError):
        select_key(b"\x00\x03", keys)
    # a wrong length is refused before any lookup: the length is fixed for the context
    for wrong in (b"", b"\x01", b"\x00\x00\x01"):
        with pytest.raises(UnknownMkiError, match="octets"):
            select_key(wrong, keys)
    assert issubclass(UnknownMkiError, SrtpError)


def test_select_key_header_extension_keys_follow_the_selected_master():
    keys = table()
    chosen = select_key(b"\x00\x02", keys, header_extension=True)
    assert chosen.header is not None
    assert chosen == derive_stream_keys(profile(0x0001), OTHER_MK, OTHER_MS, header_extension=True)


def test_mki_length_is_fixed_and_identifiers_are_unique():
    keys = table()
    assert keys.mki_length == 2
    with pytest.raises(ValueError, match="fixed at 2"):
        keys.add(MasterKey(b"\x01", MK, MS))
    with pytest.raises(ValueError, match="already"):
        keys.add(MasterKey(b"\x00\x01", OTHER_MK, OTHER_MS))
    with pytest.raises(ValueError, match="at least one octet"):
        keys.add(MasterKey(b"", MK, MS))
    with pytest.raises(ValueError, match="does not match the profile"):
        keys.add(MasterKey(b"\x00\x09", MK[:8], MS))
    # a rejected add changes nothing
    assert len(keys) == 2
    assert MasterKeys(profile(0x0001), mki_length=4).mki_length == 4
    with pytest.raises(ValueError, match="at least one octet"):
        MasterKeys(profile(0x0001), mki_length=0)


def test_retiring_a_master_key_removes_it():
    keys = table()
    keys.remove(b"\x00\x01")
    assert b"\x00\x01" not in keys
    with pytest.raises(UnknownMkiError):
        select_key(b"\x00\x01", keys)
    with pytest.raises(UnknownMkiError):
        keys.remove(b"\x00\x01")
    # the length stays fixed for the lifetime of the context even when the table empties
    keys.remove(b"\x00\x02")
    assert keys.mki_length == 2
    with pytest.raises(ValueError, match="fixed at 2"):
        keys.add(MasterKey(b"\x01", MK, MS))
