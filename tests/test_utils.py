"""Tests for pyruijie.utils — MAC normalization and helpers."""

from pyruijie.utils import format_mac


class TestFormatMac:
    def test_ruijie_dot_format(self):
        """Ruijie Cloud returns MACs in dot-notation (585b.6947.b194)."""
        assert format_mac("585b.6947.b194") == "58:5B:69:47:B1:94"

    def test_already_colon_format(self):
        assert format_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_dash_format(self):
        assert format_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_bare_hex(self):
        assert format_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    def test_lowercase_preserved_as_upper(self):
        assert format_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_empty_string(self):
        assert format_mac("") == ""

    def test_none_returns_empty(self):
        assert format_mac(None) == ""

    def test_already_upper_colon(self):
        assert format_mac("58:5B:69:47:B1:94") == "58:5B:69:47:B1:94"

    def test_invalid_length_passthrough(self):
        """Non-12-hex-char MACs are returned as-is."""
        assert format_mac("incomplete") == "incomplete"
