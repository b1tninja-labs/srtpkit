# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

- Profile table and negotiation policy, packet index and ROC estimate, replay window, the SRTP key
  derivation (AES-CM PRF, 128 and 256 bit) with SRTCP labels, AES-CM keystream and crypt, and AES-GCM IV
  formation, checked against RFC 3711 App. B.2 and B.3, RFC 6188 sec. 7 and RFC 7714 sec. 16 and 17.
- Runtime dependency `cryptography>=42`. The unused `asn1core` edge is dropped from `docs/plan.md`.
- Still stubs: `context.for_stream`, `transform.protect` and `unprotect`, `srtcp.protect_rtcp`, `mki.select_key`
  and `dtls.export_keys` (cut). See [ROADMAP.md](ROADMAP.md).

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for srtpkit.
- `srtpkit.apps` namespace reserved for composition that is not protocol behaviour.
