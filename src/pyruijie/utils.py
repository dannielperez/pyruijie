"""Shared utility functions for pyruijie."""

from __future__ import annotations


def format_mac(mac: str) -> str:
    """Normalize a MAC address to upper-case colon-separated format.

    Handles Ruijie dot-format (``585b.6947.b194``), bare hex
    (``585B6947B194``), dash-separated, and already-colon-separated
    formats.

    Returns an empty string for empty/None input.

    Examples::

        >>> format_mac("585b.6947.b194")
        '58:5B:69:47:B1:94'
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
