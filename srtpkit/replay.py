"""window and bit vector, index based variant (RFC 3711).

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
    "check",
]


def check(ctx: StreamContext, index: int) -> bool:
    """Pending behaviour defined by RFC 3711.

    Not implemented yet. See the ``replay.check()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("check() is not implemented: RFC 3711")
