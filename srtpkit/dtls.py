"""key export and the use_srtp negotiation (RFC 5764).

``split_keying_material`` is pure slicing of the exporter output a caller supplies (RFC 5764
sec. 4.2): the order is client write key, server write key, client write salt, server write salt,
each of the profile's own length. The exporter itself (label ``EXTRACTOR-dtls_srtp``, RFC 5705)
has no standard-library or ``cryptography`` path, so ``export_keys`` stays a loud stub, and so
does DTLS (RFC 5764 sec. 3).

RFC 5764 erratum 4788 (verified): the exporter's per-association context is not "empty" but
absent, a zero-length context in the sense of RFC 5705 sec. 4. A caller that calls an exporter
must pass no context; this module never sees it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .params import Profile

if TYPE_CHECKING:
    from typing import Any

    Policy = Any  # placeholder: give it a real type in the milestone that needs it
    SessionKeys = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "KeyingMaterial",
    "export_keys",
    "split_keying_material",
]


@dataclass(frozen=True)
class KeyingMaterial:
    """One direction's master key and master salt from the DTLS-SRTP exporter."""

    master_key: bytes
    master_salt: bytes


def split_keying_material(
    profile: Profile, material: bytes
) -> tuple[KeyingMaterial, KeyingMaterial]:
    """Split exporter output into ``(client_write, server_write)`` (RFC 5764 sec. 4.2).

    ``material`` must be exactly ``2 * (master_key_len + master_salt_len)`` octets for the
    profile. For the NULL-cipher profiles that length is zero (RFC 5764 sec. 4.1.2), so empty
    input gives two empty values; see ROADMAP.md for why those cannot be run through the KDF.
    """
    key_len, salt_len = profile.key_bits // 8, profile.salt_bits // 8
    if len(material) != 2 * (key_len + salt_len):
        raise ValueError(
            f"profile {profile.name} needs {2 * (key_len + salt_len)} octets of keying material"
        )
    client_key = material[:key_len]
    server_key = material[key_len : 2 * key_len]
    client_salt = material[2 * key_len : 2 * key_len + salt_len]
    server_salt = material[2 * key_len + salt_len :]
    return KeyingMaterial(client_key, client_salt), KeyingMaterial(server_key, server_salt)


def export_keys(tls_export: bytes, policy: Policy) -> SessionKeys:
    """Pending behaviour defined by RFC 5764 sec. 4.2.

    Cut for now (ROADMAP.md marks the row ``[no]``): the TLS exporter this takes its input
    from (RFC 5705) has no standard-library or ``cryptography`` path. Not implemented yet. See
    the ``dtls.export_keys()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("export_keys() is not implemented: RFC 5764 sec. 4.2")
