# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation srtpkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `params.select_profile()` | RFC 3711, RFC 5764 sec. 4.1.2, RFC 7714 sec. 14.2 | `[ok]` | `tests/test_params.py::test_profile_table`, `tests/test_params.py::test_null_profiles_never_default`, `tests/test_params.py::test_policy_prefers_gcm_by_local_order` | M1 |
| `kdf.derive()` | RFC 3711 sec. 4.3.1, Appendix B.3, RFC 6188 sec. 7.2 | `[ok]` | `tests/test_kdf.py::test_appendix_b3_vectors`, `tests/test_kdf.py::test_aes_256_cm_prf_vectors_rfc6188` | M1 |
| `kdf.derive_session_keys()` | RFC 3711 sec. 4.3.1, sec. 4.3.2, RFC 7714 sec. 11 (erratum 4938) | `[part]` | `tests/test_kdf.py::test_gcm_salt_widened_by_2_16`, `tests/test_kdf.py::test_label_for_srtcp` | M1 |
| `kdf.widen_aead_salt()` | RFC 7714 sec. 11, erratum 4938 | `[part]` | `tests/test_kdf.py::test_gcm_salt_widened_by_2_16` | M1 |
| `aescm.crypt()` | RFC 3711 sec. 4.1.1, RFC 6188 sec. 2 | `[ok]` | `tests/test_kdf.py::test_aes_cm_keystream_vectors_rfc3711_b2`, `tests/test_kdf.py::test_aes_256_cm_keystream_vectors_rfc6188` | M1 |
| `aescm.keystream()` | RFC 3711 sec. 4.1.1, Appendix B.2, RFC 6188 sec. 7.1, sec. 7.3 | `[ok]` | `tests/test_kdf.py::test_aes_cm_keystream_vectors_rfc3711_b2`, `tests/test_kdf.py::test_aes_192_cm_keystream_vectors_rfc6188` | M1 |
| `gcm.srtp_iv()` | RFC 7714 sec. 8.1 | `[ok]` | `tests/test_gcm.py::test_srtp_iv_rfc7714_16`, `tests/test_gcm.py::test_srtp_gcm_encryption_rfc7714_16_1_1` | M2 |
| `gcm.srtcp_iv()` | RFC 7714 sec. 9.1, erratum 7858 | `[ok]` | `tests/test_gcm.py::test_srtcp_iv_rfc7714_17`, `tests/test_gcm.py::test_srtcp_gcm_encryption_of_the_corrected_packet_rfc7714_17_1` | M2 |
| `index.estimate()` | RFC 3711 sec. 3.3.1, Appendix A | `[ok]` | `tests/test_index.py::test_estimate_boundaries`, `tests/test_index.py::test_estimate_closest_within_half_window` | M3 |
| `index.update()` | RFC 3711 sec. 3.3.1 paragraph 8 | `[ok]` | `tests/test_index.py::test_update_rules_three_cases`, `tests/test_index.py::test_roc_wraps_mod_2_32` | M3 |
| `replay.check()` | RFC 3711 sec. 3.3.2 | `[ok]` | `tests/test_replay.py::test_window_refuses_duplicate`, `tests/test_replay.py::test_check_does_not_mutate`, `tests/test_replay.py::test_window_agrees_with_a_naive_set_oracle` | M3 |
| `context.for_stream()` (one SSRC, one direction: session keys, ROC and s_l, SRTP and SRTCP replay windows, SRTCP index; `derive_stream_keys` derives both key sets with key derivation rate 0) | RFC 3711 sec. 3.2 | `[ok]` | `tests/test_transform.py::test_packet_limits_and_rekey_keeps_the_rollover_counter` | M1 |
| `transform.protect()` (AES-CM with HMAC-SHA1 80 and 32, AES-GCM 128 and 256, NULL cipher with explicit keys; the RFC 7714 sec. 16.1.1 and 16.2.1 packets reproduce byte for byte, the AES-CM packet matches an oracle written from the RFC text) | RFC 7714 sec. 8, RFC 3711 sec. 3.3, sec. 4.1, sec. 4.2 | `[ok]` | `tests/test_transform.py::test_rfc7714_section16_protect`, `tests/test_transform.py::test_srtp_aes_cm_matches_the_oracle_and_roundtrips` | M2 |
| `transform.unprotect()` (estimate index, replay check, verify, decrypt, then update; a forged or failed packet changes nothing) | RFC 7714 sec. 8, RFC 3711 sec. 3.3 | `[ok]` | `tests/test_transform.py::test_rfc7714_section16_unprotect`, `tests/test_transform.py::test_gcm_tamper_and_failure_leave_the_context_unchanged`, `tests/test_transform.py::test_replay_reorder_and_forgery_for_aes_cm` | M2 |
| `srtcp.protect_rtcp()` (E flag, 31-bit index modulo 2^31, AES-CM with an 80-bit tag for every profile, AES-GCM with E=1 and E=0; the RFC 7714 sec. 17 packet as corrected by erratum 7858 reproduces) | RFC 3711 sec. 3.4, RFC 7714 sec. 9 | `[ok]` | `tests/test_transform.py::test_rfc7714_section17_protect`, `tests/test_transform.py::test_srtcp_aes_cm_matches_an_oracle_from_the_rfc_text` | M4 |
| `srtcp.unprotect_rtcp()` | RFC 3711 sec. 3.4, RFC 7714 sec. 9 | `[ok]` | `tests/test_transform.py::test_rfc7714_section17_unprotect`, `tests/test_transform.py::test_srtcp_gcm_without_encryption_and_aes_cm_both_ways` | M4 |
| `mki.select_key()` | RFC 3711 sec. 8.1 | `[ ]` | `tests/test_mki.py::test_select_key` (to be written) | M4 |
| `dtls.export_keys()` | RFC 5764 sec. 4.2, RFC 5705 | `[no]` | cut for now (PORTFOLIO.md section 9 item 15): the TLS exporter has no standard-library or `cryptography` path (`ssl` has no `export_keying_material` and no DTLS), so there is nothing to call; revisit only if a portfolio transport project is proposed | M5 |
| `dtls.split_keying_material()` (client key, server key, client salt, server salt; exact length checked; the NULL profiles give empty values) | RFC 5764 sec. 4.2, erratum 4788 | `[ok]` | `tests/test_transform.py::test_split_keying_material_order_and_lengths` | M5 |
| `index.packet_limits` (a sender refuses at the profile's `max_srtp_packets` and `max_srtcp_packets` with `KeyLifetimeError`; the counters are per key and restart at a re-key; a receiver does not count) | RFC 3711 sec. 3.3.1 paragraph 10, RFC 7714 sec. 14.2 | `[ok]` | `tests/test_transform.py::test_packet_limits_and_rekey_keeps_the_rollover_counter` | M3 |
| `context.rekey` (`StreamContext.rekey` replaces the keys and keeps ROC, s_l, replay lists and the SRTCP index) | RFC 3711 sec. 3.3.1 paragraph 9, sec. 3.4 paragraph 8 | `[ok]` | `tests/test_transform.py::test_packet_limits_and_rekey_keeps_the_rollover_counter` | M4 |
| `rtp.header_parse` (`rtp.parse_header`: 12-octet header, CSRC list, header extension, version 2 only; padding and payload type are not interpreted) | RFC 3550 sec. 5.1, sec. 5.3.1; RFC 3711 sec. 3.1 | `[ok]` | `tests/test_transform.py::test_header_parse_lengths`, `tests/test_transform.py::test_csrc_list_and_header_extension_are_authenticated_not_encrypted` | M2 |
| `kdf.null_cipher_master_key` (the NULL-cipher profiles 0x0005 and 0x0006 cannot be keyed: see the open question below; the exact question is recorded, the code raises `NotImplementedError`) | RFC 5764 sec. 4.1.2, sec. 4.2; RFC 3711 sec. 4.3.1, sec. 4.3.3 | `[ ]` | `tests/test_kdf.py::test_null_cipher_profile_key_derivation` (to be written once the owner answers) | M5 |
| `srtp.cryptex` | RFC 9335 | `[ ]` | `tests/test_cryptex.py::test_rfc9335_vectors` (to be written); decide whether it is in scope for 0.1.0 | - |
| `srtp.header_extension_encryption` | RFC 6904 | `[ ]` | `tests/test_hdrext.py::test_rfc6904_vectors` (to be written) | - |
| `srtp.reduced_size_rtcp` | RFC 5506 | `[ ]` | `tests/test_srtcp.py::test_reduced_size_rtcp` (to be written) | M4 |
| `srtp.f8_mode` | RFC 3711 sec. 4.1.2, Appendix B.1 | `[no]` | AES-f8 is not in any DTLS-SRTP protection profile; revisit if SDES or MIKEY signalling is added | - |
| `srtp.double_encryption` | RFC 8723 | `[no]` | a named document requires it | - |

## 2. Milestones

- M1 parameters, KDF and context against the worked examples in the specification
- M2 AES-GCM protect and unprotect, with vectors
- M3 rollover estimate and replay window
- M4 SRTCP and MKI
- M5 profile negotiation policy and the key-material split (DTLS key export itself is cut: no TLS exporter)
- M6 publication: 0.1.0 with a loopback call against a real RTP stack

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 5764 carries 3 verified errata and is updated by RFC 7983 and RFC 9443, the latter covering multiplexing when QUIC joins the picture.
- RFC 7714 carries 2 verified errata. 4938 (96-bit salt widened by 2^16 before the KDF) is applied in `kdf.widen_aead_salt` and pinned by `tests/test_kdf.py::test_gcm_salt_widened_by_2_16`; 7858 (the sec. 17 example packet is misprinted) is pinned by `tests/test_gcm.py::test_srtcp_gcm_encryption_of_the_corrected_packet_rfc7714_17_1`. The corrected packet is `81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930 4c756e61` followed by five `deadbeef`.
- RFC 3711 held erratum 3712: SRTCP key derivation uses a 48-bit index; implemented that way. Rejected 7606: B.3 prints 94 octets of auth key, checked in full.
- RFC 6188 is now in the spine (AES-192/256 and `AES_256_CM_PRF`, required by RFC 7714 sec. 11); so is RFC 5705, for the cut exporter.
- RFC 3711 has 6 errata on file with none verified, and is updated by RFC 5506, RFC 6904 and RFC 9335. Read all three before implementing the transform.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| codecs, jitter buffers or any media handling | `[no]` | a named document requires it |
| RTP transport, which aiortp already does properly | `[no]` | a named document requires it |
| the legacy transforms nobody should negotiate, kept out of the default policy | `[no]` | a named document requires it |

## 5. Open questions

- Which profiles are negotiable by default: decided 2026-11-13 as a library convention, not by a document. 0x0001, 0x0007 and 0x0008 are negotiable; 0x0002 needs `allow_legacy`; the NULL-cipher 0x0005 and 0x0006 need `allow_null`. The owner may want 0x0001 behind `allow_legacy` too, so that AES-GCM is the only default; it is the DTLS-SRTP mandatory profile, which is why it is not.
- The interoperability oracle for the M6 loopback: the README concedes aiortp does RTP, and the only independent SRTP implementation is libsrtp (or `pylibsrtp`, listed as a live incumbent, not re-measured). Name it before M6.
- **NULL-cipher key derivation, the exact question (read 2026-11-13).** RFC 5764 sec. 4.1.2 gives SRTP_NULL_HMAC_SHA1_80 and _32 `cipher_key_length: 0` and `cipher_salt_length: 0` with a 160-bit HMAC key, so the sec. 4.2 exporter produces `2 * (0 + 0)` = 0 octets and the client and server master keys are empty. RFC 3711 sec. 4.3.1 paragraph 1 requires the SRTP key derivation "regardless of the encryption or message authentication transform", and sec. 4.3.3 defines the only PRF as AES-CM keyed with a 128, 192 or 256-bit master key. Neither RFC says what key runs the PRF to derive the 160-bit HMAC key (label 0x01 or 0x04) when the master key has no octets. The row stays `[ ]`: the owner must say which master key to use, or confirm the profiles stay out. A context for one of these profiles can still be built with explicit session keys, which `transform` and `srtcp` accept (tested in `tests/test_transform.py::test_null_cipher_authenticates_without_encrypting`).
- NULL-cipher profiles have a zero-length cipher key in RFC 5764 sec. 4.1.2, so there is no AES master key for the KDF to run with; `kdf.derive_session_keys` raises `NotImplementedError` for them. If they are ever to be supported, the owner needs to say what the master key for the authentication key derivation is.
- Spec spine: RFC 7983 and RFC 9443 (both update RFC 5764's multiplexing) are cited here and not yet in `docs/rfc-map.md`. RFC 3550 is in the spine as of 2026-11-13 (sec. 5.1 and sec. 5.3.1 read; it is Internet Standard STD 64, updated by many RFCs, 4 errata on file, none verified).
- Interoperability evidence for AES-CM and HMAC-SHA1 packets: the RFC sections read for the transform (RFC 3711 sec. 3.3, 3.4, 4.2, 4.3) print no complete SRTP packet vector, only the keystream and KDF vectors of appendix B, so the packet is checked against an oracle written from the text and by round trip. A packet vector from libsrtp or another implementation is still owed (`interop` row of the publication checklist).
- Decided in the transform: the same `StreamContext` is sender and receiver, no MKI, no key derivation rate above zero, no header extension encryption (RFC 6904) and no Cryptex (RFC 9335); their rows remain `[ ]`.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
