"""Shared utility functions for pyruijie."""

from __future__ import annotations


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
