# srtpkit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
The profile table, packet index and rollover estimate, replay window, key derivation
and AES-CM keystream are implemented and checked against the RFC test vectors; packet protect and
unprotect, SRTCP, MKI and DTLS-SRTP are not, and those public functions raise `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

srtpkit -- SRTP and SRTCP in pure Python

RTP in Python has a good async owner in aiortp 0.8.0 (2026-10-18), but securing it is a separate protocol that Python does not have. The WebRTC stacks bundle a native SRTP, so a Python media service either depends on that or transmits in the clear. RFC 3711 defines the transform, RFC 7714 the AEAD profile that should be used for new deployments, and RFC 5764 the DTLS key establishment that a modern signalling path expects. srtpkit is deliberately the transform and the key handling, not a media stack.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| aiortp | 0.8.0 | 2026-10-18 | asyncio RTP and RTCP; the transport this sits under, not the security layer |
| aiortc | current | - | bundles a native SRTP implementation inside a WebRTC stack |
| srtp, srtpkit | - | - | absent from PyPI (2026-11-05) |

What this project intends to add:

- protection and recovery with correct sequence number rollover handling, the bug that corrupts long calls
- replay databases with the window and options the specification allows, including index based
- the SRTP key derivation function and the session parameter set
- the AES-GCM profile per RFC 7714, which is what a new deployment should negotiate
- SRTCP with the E-bit and SRTCP index, plus key export from a DTLS handshake

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 3711 | Proposed Standard | 2004-03 | SRTP: transforms, the index and ROC, replay and key derivation |
| RFC 7714 | Proposed Standard | 2015-12 | AES-GCM authenticated encryption in SRTP |
| RFC 5764 | Proposed Standard | 2010-05 | DTLS handshake to establish SRTP and SRTCP keys |
| RFC 5506 | Proposed Standard | 2009-04 | reduced-size RTCP, which updates RFC 3711 |
| RFC 6904 | Proposed Standard | 2013-04 | encryption of RTP header extensions, which updates RFC 3711 |
| RFC 9335 | Proposed Standard | 2023-01 | complete encryption of header extensions and CSRCs, which updates RFC 3711 |
| RFC 6188 | Proposed Standard | 2011-03 | AES-192 and AES-256 counter mode and the AES_256_CM_PRF that RFC 7714 sec. 11 requires for AES-256-GCM |
| RFC 5705 | Proposed Standard | 2010-03 | the TLS exporter DTLS-SRTP takes its keys from; cut for now, no exporter in the standard library |

### Errata watch

- RFC 5764 carries 3 verified errata and is updated by RFC 7983 and RFC 9443, the latter covering multiplexing when QUIC joins the picture.
- RFC 7714 carries 2 verified errata. 4938: the 96-bit AEAD master salt is multiplied by 2^16 (two zero octets appended) before the RFC 3711 KDF, which is `kdf.widen_aead_salt`; a KDF fed the 12 octets as they stand derives the wrong keys without any error. 7858: the example RTCP packet at the head of sec. 17 is misprinted, and the examples use the corrected packet (`81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930 4c756e61` and five `deadbeef`).
- RFC 3711 has 6 errata on file with none verified; the technical ones are 3712 (held: the SRTCP index in key derivation is a 48-bit quantity, as libsrtp has it; `kdf.derive` takes it that way, which matters only when the derivation rate is non-zero) and 7606 (rejected: B.3 prints a 94-octet auth key block where the profile needs 20; `tests/test_kdf.py::test_appendix_b3_vectors` checks all 94 and the first 20). The RFC is updated by RFC 5506, RFC 6904 and RFC 9335. Read all three before implementing the transform.

## Module layout

| Module | Responsibility |
|---|---|
| `params` | the protection profile table and the negotiation policy (RFC 5764, RFC 7714) |
| `kdf` | the SRTP key derivation function, AES-128 and AES-256 PRFs (RFC 3711, RFC 6188) |
| `aescm` | AES counter mode keystream and IV (RFC 3711 sec. 4.1.1, RFC 6188) |
| `gcm` | AES-GCM IV formation for SRTP and SRTCP (RFC 7714) |
| `index` | packet index estimate and rollover counter (RFC 3711 sec. 3.3.1) |
| `transform` | encryption and authentication, AES-GCM profile (RFC 3711, RFC 7714) |
| `context` | stream and session context, rollover estimate and index |
| `replay` | window and bit vector, index based variant (RFC 3711) |
| `srtcp` | control packet protection and the E bit (RFC 3711) |
| `mki` | master key identifier handling (RFC 3711) |
| `dtls` | key export and the use_srtp negotiation (RFC 5764); cut, see ROADMAP.md |
| `policy` | what may be negotiated, so weak profiles are refused by default |

## Dependency

One runtime dependency, `cryptography`, for the AES block cipher and AES-GCM, which the standard
library lacks. The key derivation, the index and replay logic and every wire format are written here.
There is no `asn1core` dependency: nothing in this library parses a DER structure.

## What it does not do

- codecs, jitter buffers or any media handling
- RTP transport, which aiortp already does properly
- the legacy transforms nobody should negotiate, kept out of the default policy


## Install

```bash
git clone https://github.com/b1tninja/srtpkit.git
cd srtpkit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy srtpkit tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
