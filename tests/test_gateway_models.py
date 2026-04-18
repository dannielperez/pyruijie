"""Tests for pyruijie.models — WireGuard data models."""

from __future__ import annotations

import copy

import pytest

from pyruijie.models import (
    WireGuardClientPolicy,
    WireGuardConfigExport,
    WireGuardPeer,
    WireGuardServerPolicy,
    validate_ipv4_cidr,
    validate_ipv4_network,
)


# ── WireGuardPeer ─────────────────────────────────────────────────────


class TestWireGuardPeer:

    RAW = {
        "uuid": "peer_uuid_001",
        "desc": "Caridad Pineiro",
        "ipaddr": "10.254.250.105",
        "peerPubkey": "wFTN1ARryoOvdyf37A0U8K1GA0fspN293guFjYlHRg4=",
        "presharedkey": "riXUgQwPj06rWqQcRC/2U7+OXC+f6xA4od/DeksBo3o=",
        "allowips": ["10.254.250.105/32"],
        "endpoint": "10.1.2.3",
        "rxbyte": "1572",
        "txbyte": "2230",
        "updateTime": "1776532498",
    }

    def test_from_gateway(self):
        peer = WireGuardPeer.from_gateway(self.RAW)
        assert peer.uuid == "peer_uuid_001"
        assert peer.desc == "Caridad Pineiro"
        assert peer.ipaddr == "10.254.250.105"
        assert peer.peer_pubkey == "wFTN1ARryoOvdyf37A0U8K1GA0fspN293guFjYlHRg4="
        assert peer.preshared_key == "riXUgQwPj06rWqQcRC/2U7+OXC+f6xA4od/DeksBo3o="
        assert peer.allow_ips == ["10.254.250.105/32"]
        assert peer.rx_bytes == 1572
        assert peer.tx_bytes == 2230
        assert peer.raw == self.RAW

    def test_from_gateway_minimal(self):
        peer = WireGuardPeer.from_gateway({"uuid": "x", "desc": "test"})
        assert peer.uuid == "x"
        assert peer.ipaddr == ""
        assert peer.rx_bytes == 0

    def test_to_gateway(self):
        peer = WireGuardPeer.from_gateway(self.RAW)
        out = peer.to_gateway()
        assert out["uuid"] == "peer_uuid_001"
        assert out["desc"] == "Caridad Pineiro"
        assert out["ipaddr"] == "10.254.250.105"
        assert out["peerPubkey"] == peer.peer_pubkey
        assert out["presharedkey"] == peer.preshared_key
        assert out["allowips"] == ["10.254.250.105/32"]
        # Runtime fields should not be in output
        assert "rxbyte" not in out
        assert "endpoint" not in out

    def test_to_gateway_generates_uuid(self):
        peer = WireGuardPeer(uuid="", desc="new", ipaddr="10.0.0.5", peer_pubkey="key==")
        out = peer.to_gateway()
        assert len(out["uuid"]) == 32  # uuid4 hex

    def test_to_gateway_default_allowips(self):
        peer = WireGuardPeer(uuid="x", desc="t", ipaddr="10.0.0.5", peer_pubkey="k==")
        out = peer.to_gateway()
        assert out["allowips"] == ["10.0.0.5/32"]

    def test_to_dict_excludes_raw(self):
        peer = WireGuardPeer.from_gateway(self.RAW)
        d = peer.to_dict()
        assert "raw" not in d
        assert d["desc"] == "Caridad Pineiro"

    def test_roundtrip(self):
        peer = WireGuardPeer.from_gateway(self.RAW)
        out = peer.to_gateway()
        peer2 = WireGuardPeer.from_gateway(out)
        assert peer2.uuid == peer.uuid
        assert peer2.desc == peer.desc
        assert peer2.ipaddr == peer.ipaddr


# ── WireGuardServerPolicy ────────────────────────────────────────────


class TestWireGuardServerPolicy:

    RAW = {
        "uuid": "server_uuid_001",
        "enable": "1",
        "type": "1",
        "desc": "US_CentroCaguas_WG",
        "localAddr": "10.254.250.1/20",
        "localPort": "51820",
        "localPrivkey": "PRIVKEY==",
        "localPubkey": "PUBKEY==",
        "localDns": ["8.8.8.8"],
        "clientlist": [
            {
                "uuid": "p1",
                "desc": "peer1",
                "ipaddr": "10.254.250.2",
                "peerPubkey": "K1==",
                "presharedkey": "PSK1==",
                "allowips": ["10.254.250.2/32"],
            },
        ],
    }

    def test_from_gateway(self):
        policy = WireGuardServerPolicy.from_gateway(self.RAW)
        assert policy.uuid == "server_uuid_001"
        assert policy.desc == "US_CentroCaguas_WG"
        assert policy.enabled is True
        assert policy.local_addr == "10.254.250.1/20"
        assert policy.local_port == "51820"
        assert len(policy.peers) == 1
        assert policy.peers[0].desc == "peer1"

    def test_from_gateway_disabled(self):
        raw = copy.deepcopy(self.RAW)
        raw["enable"] = "0"
        policy = WireGuardServerPolicy.from_gateway(raw)
        assert policy.enabled is False

    def test_to_gateway(self):
        policy = WireGuardServerPolicy.from_gateway(self.RAW)
        out = policy.to_gateway()
        assert out["uuid"] == "server_uuid_001"
        assert out["enable"] == "1"
        assert out["type"] == "1"
        assert len(out["clientlist"]) == 1
        assert out["clientlist"][0]["desc"] == "peer1"

    def test_find_peer_by_ip(self):
        policy = WireGuardServerPolicy.from_gateway(self.RAW)
        p = policy.find_peer(ip="10.254.250.2")
        assert p is not None
        assert p.desc == "peer1"

    def test_find_peer_by_pubkey(self):
        policy = WireGuardServerPolicy.from_gateway(self.RAW)
        p = policy.find_peer(pubkey="K1==")
        assert p is not None
        assert p.desc == "peer1"

    def test_find_peer_by_desc(self):
        policy = WireGuardServerPolicy.from_gateway(self.RAW)
        p = policy.find_peer(desc="peer1")
        assert p is not None

    def test_find_peer_not_found(self):
        policy = WireGuardServerPolicy.from_gateway(self.RAW)
        assert policy.find_peer(ip="10.0.0.99") is None


# ── WireGuardClientPolicy ────────────────────────────────────────────


class TestWireGuardClientPolicy:

    RAW = {
        "uuid": "client_uuid_001",
        "enable": "1",
        "type": "0",
        "desc": "US_WG",
        "endpoint": "67.203.206.66",
        "endpointPort": "51820",
        "localAddr": "10.254.250.105/32",
        "localPort": "51820",
        "localPrivkey": "PRIVKEY==",
        "localPubkey": "PUBKEY==",
        "peerPubkey": "SERVER_PUBKEY==",
        "presharedkey": "PSK==",
        "allowips": ["0.0.0.0/0"],
        "localDns": ["8.8.8.8"],
        "intf": "all",
        "keepalive": "30",
        "localIfname": "wgclt0",
        "metric": "101",
        "priority": [],
        "strictPriority": "0",
        "rxbyte": "500",
        "txbyte": "700",
    }

    def test_from_gateway(self):
        policy = WireGuardClientPolicy.from_gateway(self.RAW)
        assert policy.uuid == "client_uuid_001"
        assert policy.desc == "US_WG"
        assert policy.enabled is True
        assert policy.endpoint == "67.203.206.66"
        assert policy.endpoint_port == "51820"
        assert policy.local_addr == "10.254.250.105/32"
        assert policy.local_pubkey == "PUBKEY=="
        assert policy.peer_pubkey == "SERVER_PUBKEY=="
        assert policy.keepalive == "30"
        assert policy.rx_bytes == 500

    def test_to_gateway(self):
        policy = WireGuardClientPolicy.from_gateway(self.RAW)
        out = policy.to_gateway()
        assert out["uuid"] == "client_uuid_001"
        assert out["enable"] == "1"
        assert out["type"] == "0"
        assert out["endpoint"] == "67.203.206.66"
        assert out["endpointPort"] == "51820"
        assert out["peerPubkey"] == "SERVER_PUBKEY=="
        # Runtime fields should not be in config output
        assert "rxbyte" not in out
        assert "txbyte" not in out

    def test_roundtrip(self):
        policy = WireGuardClientPolicy.from_gateway(self.RAW)
        out = policy.to_gateway()
        policy2 = WireGuardClientPolicy.from_gateway(out)
        assert policy2.uuid == policy.uuid
        assert policy2.endpoint == policy.endpoint
        assert policy2.local_pubkey == policy.local_pubkey


# ── WireGuardConfigExport ────────────────────────────────────────────


class TestWireGuardConfigExport:

    CONF_TEXT = """\
[Interface]
PrivateKey = WOiUnNig97Nc5CjxBVNn6NrEkifAr5iXm3knAnRAz3w=
Address = 10.254.250.101/32
DNS = 8.8.8.8

[Peer]
PublicKey = u6tlEzHg/qQVZtnslLStHfuqDfMjxkDCsoLOpvEcyFI=
Endpoint = centrouniquec.ruijieddnsd.com:51820
AllowedIPs = 10.254.250.101/32,10.254.250.1/32
PresharedKey = Uquw72TXgoJ3NH+ucpK++UVFzdtfHLwYBt0k1VXDzaA=
"""

    def test_from_conf_text(self):
        cfg = WireGuardConfigExport.from_conf_text(self.CONF_TEXT)
        assert cfg.interface_ip == "10.254.250.101"
        assert cfg.private_key == "WOiUnNig97Nc5CjxBVNn6NrEkifAr5iXm3knAnRAz3w="
        assert cfg.dns == "8.8.8.8"
        assert cfg.peer_pubkey == "u6tlEzHg/qQVZtnslLStHfuqDfMjxkDCsoLOpvEcyFI="
        assert cfg.endpoint == "centrouniquec.ruijieddnsd.com"
        assert cfg.endpoint_port == "51820"
        assert "10.254.250.101/32" in cfg.allowed_ips
        assert cfg.preshared_key == "Uquw72TXgoJ3NH+ucpK++UVFzdtfHLwYBt0k1VXDzaA="

    def test_to_conf_text(self):
        cfg = WireGuardConfigExport(
            interface_ip="10.254.250.101",
            private_key="PRIVKEY==",
            dns="8.8.8.8",
            peer_pubkey="PUBKEY==",
            endpoint="example.com",
            endpoint_port="51820",
            allowed_ips="0.0.0.0/0",
            preshared_key="PSK==",
        )
        text = cfg.to_conf_text()
        assert "[Interface]" in text
        assert "PrivateKey = PRIVKEY==" in text
        assert "Address = 10.254.250.101/32" in text
        assert "DNS = 8.8.8.8" in text
        assert "[Peer]" in text
        assert "PublicKey = PUBKEY==" in text
        assert "Endpoint = example.com:51820" in text
        assert "AllowedIPs = 0.0.0.0/0" in text
        assert "PresharedKey = PSK==" in text

    def test_roundtrip(self):
        cfg = WireGuardConfigExport(
            interface_ip="10.0.0.5",
            private_key="KEY==",
            dns="1.1.1.1",
            peer_pubkey="PEER==",
            endpoint="vpn.example.com",
            endpoint_port="51820",
            allowed_ips="10.0.0.0/24",
            preshared_key="PSK==",
        )
        text = cfg.to_conf_text()
        parsed = WireGuardConfigExport.from_conf_text(text)
        assert parsed.interface_ip == cfg.interface_ip
        assert parsed.private_key == cfg.private_key
        assert parsed.peer_pubkey == cfg.peer_pubkey
        assert parsed.endpoint == cfg.endpoint
        assert parsed.preshared_key == cfg.preshared_key

    def test_from_conf_text_ip_only_endpoint(self):
        text = "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nEndpoint = 1.2.3.4:51820\n"
        cfg = WireGuardConfigExport.from_conf_text(text)
        assert cfg.endpoint == "1.2.3.4"
        assert cfg.endpoint_port == "51820"


# ── Validation helpers ────────────────────────────────────────────────


class TestValidation:

    def test_validate_ipv4_cidr(self):
        iface = validate_ipv4_cidr("10.254.250.105/32")
        assert str(iface.ip) == "10.254.250.105"
        assert iface.network.prefixlen == 32

    def test_validate_ipv4_network(self):
        net = validate_ipv4_network("10.254.250.0/20")
        assert str(net) == "10.254.240.0/20"

    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError):
            validate_ipv4_cidr("not-an-ip")

    def test_invalid_network_raises(self):
        with pytest.raises(ValueError):
            validate_ipv4_network("999.999.999.999/99")
