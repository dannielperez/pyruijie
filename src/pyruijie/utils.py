"""Shared utility functions for pyruijie."""

from __future__ import annotations

import re
from typing import Any

_REDACT_PARAMS = frozenset({"access_token", "auth", "sid", "token", "secret"})
_REDACT_PARAM_PATTERN = re.compile(
    r"(" + "|".join(re.escape(param) for param in sorted(_REDACT_PARAMS)) + r")=[^&'\s]+"
)
_CAMEL_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")
_SECRET_KEY_MARKERS = frozenset(
    {
        "authorization",
        "password",
        "presharedkey",
        "privatekey",
        "privkey",
        "secret",
        "token",
    }
)
_SECRET_KEY_PARTS = frozenset({"auth", "psk", "sid"})
_REDACTED = "***"


def _sanitize_url(text: str) -> str:
    """Mask sensitive query-parameter values in URL-bearing text."""
    return _REDACT_PARAM_PATTERN.sub(r"\1=***", text)


def _is_secret_key(key: object) -> bool:
    if not isinstance(key, str):
        return False

    compact_key = _NON_ALPHANUMERIC.sub("", key.lower())
    if any(marker in compact_key for marker in _SECRET_KEY_MARKERS):
        return True

    key_parts = _NON_ALPHANUMERIC.split(_CAMEL_CASE_BOUNDARY.sub("_", key).lower())
    return any(part in _SECRET_KEY_PARTS for part in key_parts)


def redact_payload(payload: Any) -> Any:
    """Return a shape-preserving copy with credential-bearing values masked.

    Mutation payloads can carry WireGuard private keys and preshared keys at
    arbitrary nesting depths. Key-aware recursive masking is required because
    the values themselves have no reliable pattern that distinguishes them from
    safe operational data.
    """
    if isinstance(payload, dict):
        return {
            key: _REDACTED if _is_secret_key(key) else redact_payload(value)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [redact_payload(value) for value in payload]
    if isinstance(payload, tuple):
        return tuple(redact_payload(value) for value in payload)
    return payload


def format_mac(mac: str) -> str:
    """Normalize a MAC address to upper-case colon-separated format.

    Handles Ruijie dot-format (``aabb.ccdd.eeff``), bare hex
    (``AABBCCDDEEFF``), dash-separated, and already-colon-separated
    formats.

    Returns an empty string for empty/None input.

    Examples::

        >>> format_mac("aabb.ccdd.eeff")
        'AA:BB:CC:DD:EE:FF'
        >>> format_mac("AA-BB-CC-DD-EE-FF")
        'AA:BB:CC:DD:EE:FF'
        >>> format_mac("aabbccddeeff")
        'AA:BB:CC:DD:EE:FF'
    """
    if not mac:
        return ""
    raw = mac.replace(".", "").replace("-", "").replace(":", "").upper()
    if len(raw) == 12:
        return ":".join(raw[i : i + 2] for i in range(0, 12, 2))
    return mac
