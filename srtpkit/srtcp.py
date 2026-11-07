"""control packet protection and the E bit (RFC 3711).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Context = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "protect_rtcp",
]


def protect_rtcp(packet: bytes, ctx: Context) -> bytes:
    """Pending behaviour defined by RFC 3711 sec. 3.4.

    Not implemented yet. See the ``srtcp.protect_rtcp()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("protect_rtcp() is not implemented: RFC 3711 sec. 3.4")
