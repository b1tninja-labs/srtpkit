# srtpkit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
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

### Errata watch

- RFC 5764 carries 3 verified errata and is updated by RFC 7983 and RFC 9443, the latter covering multiplexing when QUIC joins the picture.
- RFC 7714 carries 2 verified errata.
- RFC 3711 has 6 errata on file with none verified, and is updated by RFC 5506, RFC 6904 and RFC 9335. Read all three before implementing the transform.

## Module layout

| Module | Responsibility |
|---|---|
| `params` | session parameters: cipher, auth, key and salt lengths (RFC 3711) |
| `kdf` | the SRTP key derivation function (RFC 3711) |
| `transform` | encryption and authentication, AES-GCM profile (RFC 3711, RFC 7714) |
| `context` | stream and session context, rollover estimate and index |
| `replay` | window and bit vector, index based variant (RFC 3711) |
| `srtcp` | control packet protection and the E bit (RFC 3711) |
| `mki` | master key identifier handling (RFC 3711) |
| `dtls` | key export and the use_srtp negotiation (RFC 5764) |
| `policy` | what may be negotiated, so weak profiles are refused by default |

## What it does not do

- codecs, jitter buffers or any media handling
- RTP transport, which aiortp already does properly
- the legacy transforms nobody should negotiate, kept out of the default policy


## Install

```bash
git clone https://github.com/b1tninja/srtpkit.cd srtpkit
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
mypy srtpkit
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
