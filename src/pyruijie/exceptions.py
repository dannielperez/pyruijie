"""pyruijie exception hierarchy."""

from __future__ import annotations


class RuijieError(Exception):
    """Base exception for all pyruijie errors."""


class AuthenticationError(RuijieError):
    """Raised when authentication with Ruijie Cloud fails."""


class APIError(RuijieError):
    """Raised when the Ruijie Cloud API returns a non-zero error code."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Ruijie API error {code}: {message}")


class ConnectionError(RuijieError):  # noqa: A001
    """Raised when the client cannot reach the Ruijie Cloud API."""


# ── Gateway (LuCI JSON-RPC) exceptions ────────────────────────────────


class RuijieAuthError(RuijieError):
    """Authentication to a local gateway failed."""


class RuijieApiError(RuijieError):
    """The gateway LuCI API returned an error response.

    Attributes:
        rcode: Raw rcode string from the gateway (e.g. "06070001").
        message: Human-readable error message from the gateway.
        raw: Full response dict for debugging.
    """

    def __init__(
        self,
        message: str,
        *,
        rcode: str | None = None,
        raw: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.rcode = rcode
        self.message = message
        self.raw = raw


class RuijieWireGuardError(RuijieError):
    """General WireGuard operation error."""


class RuijieWireGuardValidationError(RuijieWireGuardError):
    """Input validation failed for a WireGuard operation."""


class RuijieWireGuardConflictError(RuijieWireGuardError):
    """A conflicting resource already exists (duplicate peer IP or key)."""


class RuijieWireGuardUnsupportedError(RuijieWireGuardError):
    """Operation not supported on this gateway model or firmware version."""
