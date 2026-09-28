from unittest.mock import Mock

import pytest

from pyruijie.models import GatewayPort
from pyruijie.wan_evidence import boolean, parse_wan_configuration, read_wan_configuration


@pytest.mark.parametrize(
    "value,expected",
    [
        ("true", True),
        ("false", False),
        (" UP ", True),
        ("", None),
        ("unexpected", None),
        (None, None),
    ],
)
def test_boolean(value, expected):
    assert boolean(value) is expected


def test_cloud_true_link():
    assert GatewayPort(alias="WAN", line_status="true").is_up


def test_configuration_allowlist_and_unknown_secondary():
    network = {"wanNum": "2", "wan": [{"proto": "dhcp", "password": "secret"}, {"proto": "pppoe"}]}
    policy = {
        "enable": "1",
        "master_list": [{"ifname": "wan", "m": "1"}, {"ifname": "wan1", "m": "0"}],
    }
    result = parse_wan_configuration(network, policy)
    assert result["secondary_enabled"] is None
    assert result["primary"] == "wan"
    assert "secret" not in str(result)
    policy["wan1"] = "1"
    assert parse_wan_configuration(network, policy)["secondary_enabled"] is True
    policy["wan1"] = "0"
    assert parse_wan_configuration(network, policy)["secondary_enabled"] is False


@pytest.mark.parametrize(
    "count,interfaces", [(True, [{}]), ("2", [{"proto": "dhcp"}]), ("0", []), ("1", [{}])]
)
def test_incomplete_inventory_rejected(count, interfaces):
    with pytest.raises(ValueError):
        parse_wan_configuration({"wanNum": count, "wan": interfaces}, {})


def test_identity_checked_before_reads_and_timeout_propagates():
    client = Mock(serial_number="actual")
    with pytest.raises(ValueError):
        read_wan_configuration(client, "different")
    client.cmd.assert_not_called()
    client.cmd.side_effect = TimeoutError
    with pytest.raises(TimeoutError):
        read_wan_configuration(client, "actual")
    client.cmd_checked.assert_not_called()
    assert 0 < client.cmd.call_args.kwargs["timeout"] <= 12


def test_reads_only_allowlisted_configuration_modules():
    client = Mock(serial_number="actual")
    client.cmd.side_effect = [
        {"data": {"wanNum": "1", "wan": [{"proto": "dhcp", "password": "hidden"}]}},
        {"data": {"enable": "0"}},
    ]
    result = read_wan_configuration(client, "actual")
    assert result["wan_count"] == 1
    assert "hidden" not in str(result)
    assert [call.args for call in client.cmd.call_args_list] == [
        ("devConfig.get", "network"),
        ("devConfig.get", "mllb"),
    ]
