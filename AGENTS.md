# Instructions for coding agents

SRTP protection and recovery, key derivation, replay databases, the AES-GCM profile, SRTCP and DTLS-SRTP key export.

Primary documents are listed in `docs/rfc-map.md` with statuses and known errata.
The obligation table in `ROADMAP.md` records what is owed, and `README.md` explains
what the library is for. Read those three before changing anything.

## Finding work

If the person gave you a task, do that task.

If you arrived with nothing to do, run this from this directory:

    python -m projecthub pickup --who <your name> --project srtpkit

Its output is your assignment: one row, already claimed for you, with what to build, the commands that prove
it and the ways to end it. The board decides the order of work, so the row it gives you is the row to work,
even if it is in another project. `NO WORK` is a real answer: ask the person what to work on.

Without the workspace beside this repository, read `.projecthub/packet.md` if it exists. If it does not, ask what
to work on.

## Commands

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python -m pytest -q tests/test_roadmap_rows.py
    python -m pytest -q tests/test_public_api.py::test_stubs_are_loud
    python -m ruff check .
    python -m ruff format --check .
    python -m mypy srtpkit tests

The first line installs the dev extras. The six commands after it are the gates,
and all six must pass before a change is finished. CI runs the same set on Linux
and Windows, plus the suite under `python -O`.

## Invariants

These are the points where a plausible-looking change makes the project wrong
rather than merely incomplete.

1. **Roadmap honesty.** Never change a `ROADMAP.md` row from `[ ]` to `[ok]` unless
   the test named in its `Where` cell exists, passes, and would fail if the behaviour
   regressed. A Where cell marked `(to be written)` names a test nobody has written:
   write it, then drop the marker in the same commit that flips the row.
   `tests/test_roadmap_rows.py` checks only that every row names a callable the
   package defines; it cannot tell a passing test from a missing one, so this rule
   is the check. Do not weaken that test, skip it, or delete it to get a green run.
2. **No silent stubs.** Code that is not implemented raises `NotImplementedError`.
   Never return an empty value, an empty collection, or a result object that reports
   success. A protocol library that answers nothing is worse than one that refuses
   to answer, and `tests/test_public_api.py` enforces that every stub is loud.
3. **Normative text is never paraphrased from memory.** Fetch it with the `rfc_*`
   tools and cite the section. If the text you fetch does not say what the obligation claims,
   the obligation is wrong: fix the roadmap row and say so in the commit.
4. **Dependencies.** The one runtime dependency is `cryptography`, for AES (CTR and the block cipher
   under the KDF) and AES-GCM only (owner rule: primitives from `cryptography`, everything else is
   ours, including the KDF, the index and replay logic and every wire format). There is no
   `asn1core` edge: nothing here parses a DER structure. Adding another runtime dependency needs a
   paragraph of justification in `docs/strategy.md` explaining why the standard library and
   `cryptography` are not enough.
5. **Scope.** What is deliberately absent is listed under Non-goals in `README.md`.
   An agent that "helpfully" implements a non-goal has expanded the API surface that
   has to be supported forever.

## Read before implementing

- RFC 5764 carries 3 verified errata and is updated by RFC 7983 and RFC 9443, the latter covering multiplexing when QUIC joins the picture.
- RFC 7714 carries 2 verified errata: 4938 (the 96-bit AEAD master salt is widened by 2^16 to 112 bits before the
  RFC 3711 KDF, applied in `kdf.widen_aead_salt`) and 7858 (sec. 17 misprints its example RTCP packet; the examples
  use the corrected one, pinned in `tests/test_gcm.py`).
- RFC 6188 supplies AES-192 and AES-256 counter mode and the `AES_256_CM_PRF` that RFC 7714 sec. 11 requires for
  AES-256-GCM. RFC 5705 defines the TLS exporter that DTLS-SRTP needs; it is cut (see `ROADMAP.md`).
- RFC 3711 has 6 errata on file with none verified, and is updated by RFC 5506, RFC 6904 and RFC 9335. Read all three before implementing the transform.

## Protocol work

`.clinerules/10-rfclib.md` describes the `rfc_*` tool calls to make for each obligation
and lists the section refs for this project. If you are not running in Cline, the
same procedure applies: confirm the document, read its errata, pull the normative
statements, then write code.
