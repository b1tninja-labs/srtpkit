"""key export and the use_srtp negotiation (RFC 5764).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Policy = Any  # placeholder: give it a real type in the milestone that needs it
    SessionKeys = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "export_keys",
]


def export_keys(tls_export: bytes, policy: Policy) -> SessionKeys:
    """Pending behaviour defined by RFC 5764.

    Not implemented yet. See the ``dtls.export_keys()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("export_keys() is not implemented: RFC 5764")
