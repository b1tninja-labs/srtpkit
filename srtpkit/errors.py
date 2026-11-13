"""Exceptions for packets and contexts that must not be processed."""

from __future__ import annotations

__all__ = ["AuthenticationError", "KeyLifetimeError", "ReplayError", "SrtpError"]


class SrtpError(ValueError):
    """A packet or context is not acceptable; nothing was changed."""


class AuthenticationError(SrtpError):
    """The authentication tag did not verify: "AUTHENTICATION FAILURE" (RFC 3711 sec. 4.2)."""


class ReplayError(SrtpError):
    """The packet index was already received or is behind the replay window (sec. 3.3.2)."""


class KeyLifetimeError(SrtpError):
    """The key has protected as many packets as its profile allows (sec. 3.3.1, sec. 9.2)."""
