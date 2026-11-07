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
| `params.select_profile()` | RFC 3711, RFC 7714 | `[ ]` | `tests/test_obligations.py::test_select_profile` (to be written) | M1 |
| `kdf.derive()` | RFC 3711 sec. 4.3.1 | `[ ]` | `tests/test_obligations.py::test_derive` (to be written) | M1 |
| `context.for_stream()` | RFC 3711 sec. 3.2 | `[ ]` | `tests/test_obligations.py::test_for_stream` (to be written) | M1 |
| `transform.protect()` | RFC 7714 sec. 8 | `[ ]` | `tests/test_obligations.py::test_protect` (to be written) | M2 |
| `transform.unprotect()` | RFC 7714 sec. 8 | `[ ]` | `tests/test_obligations.py::test_unprotect` (to be written) | M2 |
| `replay.check()` | RFC 3711 sec. 3.3.2 | `[ ]` | `tests/test_obligations.py::test_check` (to be written) | M3 |
| `srtcp.protect_rtcp()` | RFC 3711 sec. 3.4 | `[ ]` | `tests/test_obligations.py::test_protect_rtcp` (to be written) | M4 |
| `mki.select_key()` | RFC 3711 | `[ ]` | `tests/test_obligations.py::test_select_key` (to be written) | M4 |
| `dtls.export_keys()` | RFC 5764 sec. 4.2 | `[ ]` | `tests/test_obligations.py::test_export_keys` (to be written) | M5 |

## 2. Milestones

- M1 parameters, KDF and context against the worked examples in the specification
- M2 AES-GCM protect and unprotect, with vectors
- M3 rollover estimate and replay window
- M4 SRTCP and MKI
- M5 DTLS key export and profile negotiation policy
- M6 publication: 0.1.0 with a loopback call against a real RTP stack

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 5764 carries 3 verified errata and is updated by RFC 7983 and RFC 9443, the latter covering multiplexing when QUIC joins the picture.
- RFC 7714 carries 2 verified errata.
- RFC 3711 has 6 errata on file with none verified, and is updated by RFC 5506, RFC 6904 and RFC 9335. Read all three before implementing the transform.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| codecs, jitter buffers or any media handling | `[no]` | a named document requires it |
| RTP transport, which aiortp already does properly | `[no]` | a named document requires it |
| the legacy transforms nobody should negotiate, kept out of the default policy | `[no]` | a named document requires it |

## 5. Open questions

- which profiles are negotiable by default once RFC 3711 and RFC 7714 are applied

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
