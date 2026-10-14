"""Peer edits must not erase existing firmware configuration."""

from copy import deepcopy
from unittest.mock import Mock

from pyruijie.models import WireGuardPeer, WireGuardServerPolicy
from pyruijie.wireguard import WireGuardManager


def test_add_peer_preserves_existing_configuration_without_runtime_fields():
    raw = {
        "uuid": "server",
        "desc": "hub",
        "enable": "1",
        "type": "1",
        "localAddr": "10.254.250.1/20",
        "localPort": "51820",
        "localPrivkey": "synthetic-server-private",
        "localPubkey": "server-public",
        "localDns": [],
        "endpointPort": "51820",
        "keepalive": "30",
        "localDomain": "hub.example.test",
        "localIfname": "wgs0",
        "metric": "101",
        "priority": [],
        "strictPriority": "0",
        "suppCustRt": "1",
        "clientlist": [
            {
                "uuid": "old",
                "desc": "existing",
                "ipaddr": "10.254.251.1",
                "peerPubkey": "old-public",
                "peerPrikey": "synthetic-old-private",
                "presharedkey": "",
                "allowips": ["10.40.1.0/24"],
                "rxbyte": "123",
                "txbyte": "456",
                "updateTime": "789",
            }
        ],
    }
    original = deepcopy(raw)
    client = Mock()
    manager = WireGuardManager(client)
    manager.get_server_policy = Mock(return_value=WireGuardServerPolicy.from_gateway(raw))
    manager.add_peer(WireGuardPeer("new", "new-site", "10.254.251.45", "new-public"))
    sent = client.cmd_checked.call_args.args[2]
    expected = deepcopy(original)
    for key in ("rxbyte", "txbyte", "updateTime"):
        expected["clientlist"][0].pop(key)
    assert {k: v for k, v in sent.items() if k != "clientlist"} == {
        k: v for k, v in expected.items() if k != "clientlist"
    }
    assert sent["clientlist"][0] == expected["clientlist"][0]
    assert len(sent["clientlist"]) == 2
    assert "peerPrikey" not in sent["clientlist"][1]
    assert "synthetic-old-private" not in repr(manager.get_server_policy.return_value.peers[0])
    assert raw == original


def test_typed_edits_win_and_unknown_fields_are_not_forwarded():
    policy = WireGuardServerPolicy.from_gateway(
        {
            "uuid": "server",
            "desc": "old",
            "enable": "1",
            "unexpectedRuntimeField": "ignore",
            "metric": "101",
        }
    )
    policy.desc = "new"
    policy.enabled = False
    assert policy.to_gateway()["desc"] == "new"
    assert policy.to_gateway()["enable"] == "0"
    assert "unexpectedRuntimeField" not in policy.to_gateway()
