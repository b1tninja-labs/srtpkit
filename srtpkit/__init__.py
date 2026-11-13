"""srtpkit -- SRTP and SRTCP in pure Python.

RTP in Python has a good async owner in aiortp 0.8.0 (2026-10-18), but securing it is a
separate protocol that Python does not have.
"""

from __future__ import annotations

from . import (
    aescm,
    apps,
    cli,
    context,
    dtls,
    gcm,
    index,
    kdf,
    mki,
    params,
    policy,
    replay,
    srtcp,
    transform,
)
from .context import for_stream
from .dtls import export_keys
from .kdf import derive
from .mki import select_key
from .params import select_profile
from .replay import check
from .srtcp import protect_rtcp
from .transform import protect, unprotect

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "aescm",
    "apps",
    "check",
    "cli",
    "context",
    "derive",
    "dtls",
    "export_keys",
    "for_stream",
    "gcm",
    "index",
    "kdf",
    "mki",
    "params",
    "policy",
    "protect",
    "protect_rtcp",
    "replay",
    "select_key",
    "select_profile",
    "srtcp",
    "transform",
    "unprotect",
]
