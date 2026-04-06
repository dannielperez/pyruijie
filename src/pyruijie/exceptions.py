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
