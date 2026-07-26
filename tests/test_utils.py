"""Tests for pyruijie.utils — normalization and redaction helpers."""

from pyruijie.utils import format_mac, redact_payload


def test_redact_payload_masks_nested_credential_keys_and_preserves_safe_fields():
    payload = {
        "operation": "configure",
        "peers": [
            {
                "name": "synthetic-peer",
                "local_privkey": "SYNTHETIC-PRIVKEY-AAAA",
                "nested": {
                    "localPrivkey": "SYNTHETIC-PRIVKEY-BBBB",
                    "preshared_key": "SYNTHETIC-PSK-CCCC",
                    "presharedkey": "SYNTHETIC-PSK-DDDD",
                    "endpoint": "192.0.2.10:51820",
                },
            }
        ],
        "private_key": "SYNTHETIC-PRIVKEY-EEEE",
        "password": "SYNTHETIC-PASSWORD-FFFF",
        "apiToken": "SYNTHETIC-TOKEN-GGGG",
        "auth": "SYNTHETIC-AUTH-HHHH",
        "sid": "SYNTHETIC-SID-IIII",
        "psk": "SYNTHETIC-PSK-JJJJ",
    }

    redacted = redact_payload(payload)

    assert redacted["operation"] == "configure"
    assert redacted["peers"][0]["name"] == "synthetic-peer"
    assert redacted["peers"][0]["nested"]["endpoint"] == "192.0.2.10:51820"
    assert redacted["peers"][0]["local_privkey"] == "***"
    assert redacted["peers"][0]["nested"]["localPrivkey"] == "***"
    assert redacted["peers"][0]["nested"]["preshared_key"] == "***"
    assert redacted["peers"][0]["nested"]["presharedkey"] == "***"
    assert redacted["private_key"] == "***"
    assert redacted["password"] == "***"
    assert redacted["apiToken"] == "***"
    assert redacted["auth"] == "***"
    assert redacted["sid"] == "***"
    assert redacted["psk"] == "***"
    assert payload["peers"][0]["local_privkey"] == "SYNTHETIC-PRIVKEY-AAAA"


class TestFormatMac:
    def test_ruijie_dot_format(self):
        """Ruijie Cloud returns MACs in dot-notation (aabb.ccdd.eeff)."""
        assert format_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"

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
        assert format_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_invalid_length_passthrough(self):
        """Non-12-hex-char MACs are returned as-is."""
        assert format_mac("incomplete") == "incomplete"
