from copy import deepcopy
from unittest.mock import Mock

import pytest

from pyruijie.client import RuijieClient
from pyruijie.models import WireGuardClientPolicy
from tests.test_cloud_wireguard_models import cloud_policy


def setup_client():
    raw = cloud_policy()
    raw.update(
        localPrivateKey="synthetic-private",
        preSharedKey="synthetic-psk",
        strictPriority=1,
        futureVendorField={"preserve": True},
    )
    expected = WireGuardClientPolicy.from_cloud(raw)
    client = object.__new__(RuijieClient)
    client.get_existing_wireguard_clients = Mock(return_value=[expected])
    client.get_wireguard_vpn_info = Mock(return_value={"data": {"wireguard": [raw]}})
    client.update_wireguard_policy = Mock()
    return client, raw, expected


def test_route_only_update_preserves_all_other_fields():
    client, raw, expected = setup_client()
    before = deepcopy(raw)
    client.update_existing_wireguard_client_routes(
        "project", "serial", expected, ["10.254.250.0/28"]
    )
    client.update_wireguard_policy.assert_called_once_with(
        "serial", {**before, "allowIps": ["10.254.250.0/28"]}
    )
    assert raw == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("endpoint", "other.example.test"),
        ("localPrivateKey", ""),
        ("localPrivateKey", "********"),
        ("localPort", 51899),
    ],
)
def test_stale_or_incomplete_snapshot_prevents_write(field, value):
    client, raw, expected = setup_client()
    raw[field] = value
    with pytest.raises(ValueError):
        client.update_existing_wireguard_client_routes(
            "project", "serial", expected, ["10.254.250.0/28"]
        )
    client.update_wireguard_policy.assert_not_called()
