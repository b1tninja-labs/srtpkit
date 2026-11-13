# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 3711 | Proposed Standard | 2004-03 | 2026-11-05 |
| RFC 7714 | Proposed Standard | 2015-12 | 2026-11-05 |
| RFC 5764 | Proposed Standard | 2010-05 | 2026-11-05 |
| RFC 5506 | Proposed Standard | 2009-04 | 2026-11-05 |
| RFC 6904 | Proposed Standard | 2013-04 | 2026-11-05 |
| RFC 9335 | Proposed Standard | 2023-01 | 2026-11-05 |
| RFC 6188 | Proposed Standard | 2011-03 | 2026-11-13 |
| RFC 3550 | Internet Standard (STD 64), current; sec. 5.1 and sec. 5.3.1 (the header, CSRC list and header extension) are what `srtpkit/rtp.py` implements | 2003-07 | 2026-11-13 |
| RFC 5705 | Proposed Standard, updated by RFC 8446, RFC 8447, RFC 9846 | 2010-03 | 2026-11-13 |

Reads of 2026-11-13 for the packet transform: RFC 3711 sec. 3.3 (with 3.3.1 and 3.3.2), sec. 3.4, sec. 4.1.3, sec. 4.2, sec. 4.3; RFC 7714 sec. 8, sec. 9 and sec. 16 (the vectors); RFC 5764 sec. 4.1.2 (profile table) and sec. 4.2 (exporter layout, erratum 4788). Finding: RFC 5764 sec. 4.1.2 gives the NULL profiles a zero-length key and salt, which leaves the HMAC key derivation without a master key (see ROADMAP.md, open questions). RFC 7714 sec. 9.2 and sec. 9.3 put the encrypted ciphertext with its tag before the E-flag and index, and for E=0 the tag alone, which `srtcp` follows.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.

## Errata, read through rfclib on 2026-11-13

| Document | Errata | Effect here |
|---|---|---|
| RFC 3711 | 5 held, 1 rejected. Technical: 3712 (held), 7606 (rejected), 3420 (held, the encrypted portion includes the pad count) | 3712: SRTCP key derivation uses a 48-bit index (zero-padded SRTCP index), as libsrtp does; `kdf.derive` takes a 48-bit index. 7606: B.3 prints 94 octets of auth key where the profile needs 20; as rejected the printed vector stands, and `test_appendix_b3_vectors` checks all 94 and the first 20. Editorial: 1958, 4425, 4514. |
| RFC 7714 | 2 verified. 4938 (technical, sec. 11), 7858 (technical, sec. 17) | 4938: a 96-bit master salt is multiplied by 2^16 to form the 112-bit KDF salt, and AEAD_AES_256_GCM uses the RFC 6188 AES_256_CM_PRF. Applied in `kdf.widen_aead_salt` and `kdf.derive_session_keys`, pinned by `test_gcm_salt_widened_by_2_16`. No published vector derives GCM session keys, so no test pins the widened output against the RFC itself. 7858: the example packet at the head of sec. 17 is misprinted; every example is built on the corrected packet, pinned in `tests/test_gcm.py`. |
| RFC 5764 | 3 verified (3971 alert name, 4788 no per-association exporter context, 4873 editorial), 1 held (3913, demultiplexing; superseded in effect by RFC 7983) | 4788 matters only to the exporter call, which is cut. |
| RFC 6188 | 1 reported (8394): the key lifetime table should read 2^48 SRTP and 2^31 SRTCP | Not applied; RFC 7714 sec. 14.2 and RFC 3711 sec. 3.3.1 paragraph 10 say the same as the erratum. |
| RFC 5705 | 1 verified (4395, notation `[0..length-1]`) | Exporter is cut. |

RFC 6188 sec. 3.1 says AES_128_CM_PRF MUST NOT be used with AES-192 or AES-256 encryption.
`kdf.derive` chooses the PRF from the master key's length, so a 256-bit master key always runs
AES-256, and `derive_session_keys` checks the key length against the profile.

## Where the cryptographic primitives come from

The AES block cipher (counter mode) and AES-GCM come from the `cryptography` package, the owner's
rule for primitives. Everything else in `srtpkit/` is written here.
