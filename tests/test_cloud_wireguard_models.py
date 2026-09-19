"""Cloud policy reads preserve identities and every routed subnet."""

import pytest

from pyruijie.models import WireGuardClientPolicy


def cloud_policy():
    return {
        "uuid": "existing-client",
        "type": 0,
        "name": "Existing cloud client",
        "enable": 1,
        "localAddress": "10.253.250.1/32",
        "localPort": 51821,
        "localPublicKey": "client-public",
        "peerPublicKey": "hub-public",
        "endpoint": "vpn.example.test",
        "endpointPort": 51820,
        "allowIps": ["10.20.0.0/16", "10.50.0.0/23", "10.200.80.0/24"],
        "localDns": ["10.20.0.1"],
        "keepAlive": 25,
    }


def test_cloud_client_preserves_configuration_and_canonical_snapshot():
    raw = cloud_policy()
    policy = WireGuardClientPolicy.from_cloud(raw)

    assert policy.uuid == raw["uuid"]
    assert policy.desc == raw["name"]
    assert policy.enabled is True
    assert policy.local_addr == "10.253.250.1/32"
    assert policy.local_port == "51821"
    assert policy.local_pubkey == "client-public"
    assert policy.peer_pubkey == "hub-public"
    assert policy.endpoint_port == "51820"
    assert policy.allow_ips == raw["allowIps"]
    assert policy.raw["allowips"] == raw["allowIps"]
    assert policy.keepalive == "25"
    assert "localAddr" not in raw  # Parsing never mutates the response.


@pytest.mark.parametrize(
    "field", ["uuid", "localAddress", "localPublicKey", "peerPublicKey", "endpoint", "allowIps"]
)
def test_cloud_client_rejects_incomplete_configuration(field):
    raw = cloud_policy()
    del raw[field]
    with pytest.raises(ValueError):
        WireGuardClientPolicy.from_cloud(raw)


def test_cloud_client_rejects_server_and_malformed_routes():
    raw = cloud_policy()
    raw["type"] = 1
    with pytest.raises(ValueError):
        WireGuardClientPolicy.from_cloud(raw)
    raw["type"] = 0
    raw["allowIps"] = "10.20.0.0/16"
    with pytest.raises(ValueError):
        WireGuardClientPolicy.from_cloud(raw)


def test_disabled_cloud_client_remains_disabled():
    raw = cloud_policy()
    raw["enable"] = 0
    assert WireGuardClientPolicy.from_cloud(raw).enabled is False


@pytest.mark.parametrize("serials", [["wrong"], ["expected", "second"], []])
def test_cloud_read_rejects_wrong_or_ambiguous_gateway(serials):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from pyruijie.client import RuijieClient

    client = Mock()
    client.get_devices.return_value = [
        SimpleNamespace(product_type="EGW", serial_number=sn) for sn in serials
    ]
    with pytest.raises(ValueError, match="uniquely identify"):
        RuijieClient.get_existing_wireguard_clients(client, "project", "expected")
    client.get_wireguard_vpn_info.assert_not_called()


def test_verified_cloud_read_preserves_routes_and_rejects_duplicate_ids():
    from types import SimpleNamespace
    from unittest.mock import Mock

    from pyruijie.client import RuijieClient

    client = Mock()
    client.get_devices.return_value = [
        SimpleNamespace(product_type="EGW", serial_number="expected"),
        SimpleNamespace(product_type="SWITCH", serial_number="irrelevant"),
    ]
    rows = [cloud_policy()]
    client.get_wireguard_vpn_info.return_value = {"data": {"wireguard": rows}}
    policies = RuijieClient.get_existing_wireguard_clients(client, "project", "expected")
    assert policies[0].allow_ips == rows[0]["allowIps"]
    client.get_devices.assert_called_once_with("project", deadline_seconds=30)
    rows.append(cloud_policy())
    with pytest.raises(ValueError, match="duplicate"):
        RuijieClient.get_existing_wireguard_clients(client, "project", "expected")
