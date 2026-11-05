"""encryption and authentication, AES-GCM profile (RFC 3711, RFC 7714).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    StreamContext = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "protect",
    "unprotect",
]


def protect(packet: bytes, ctx: StreamContext, aad: bytes) -> bytes:
    """Pending behaviour defined by RFC 7714.

    Not implemented yet. See the ``transform.protect()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("protect() is not implemented: RFC 7714")


def unprotect(packet: bytes, ctx: StreamContext) -> bytes:
    """Pending behaviour defined by RFC 7714.

    Not implemented yet. See the ``transform.unprotect()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("unprotect() is not implemented: RFC 7714")
