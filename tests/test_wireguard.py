"""Tests for pyruijie.wireguard — WireGuardManager."""

from __future__ import annotations

import pytest

from pyruijie.exceptions import (
    RuijieWireGuardConflictError,
    RuijieWireGuardError,
    RuijieWireGuardValidationError,
)
from pyruijie.models import WireGuardClientPolicy, WireGuardPeer, WireGuardServerPolicy
from pyruijie.wireguard import DriftField, DriftReport, ReconciliationPlan, WireGuardManager

from .conftest import MockGatewayClient, SAMPLE_CLIENT_POLICY, SAMPLE_SERVER_POLICY


# ── Server Policy Tests ───────────────────────────────────────────────


class TestListServerPolicies:

    def test_returns_parsed_policies(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policies = wg.list_server_policies()
        assert len(policies) == 1
        assert policies[0].uuid == SAMPLE_SERVER_POLICY["uuid"]
        assert len(policies[0].peers) == 3

    def test_get_server_policy_default(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.get_server_policy()
        assert policy.desc == "US_CentroCaguas_WG"

    def test_get_server_policy_by_uuid(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.get_server_policy(SAMPLE_SERVER_POLICY["uuid"])
        assert policy.uuid == SAMPLE_SERVER_POLICY["uuid"]

    def test_get_server_policy_not_found(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        with pytest.raises(RuijieWireGuardError, match="not found"):
            wg.get_server_policy("nonexistent_uuid")


class TestUpdateServerPolicy:

    def test_update_pushes_config(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.get_server_policy()
        policy.desc = "Updated Name"
        wg.update_server_policy(policy)

        # Verify a cmd_checked call was made
        update_calls = [
            c for c in mock_gateway.calls if c["method"] == "devConfig.update"
        ]
        assert len(update_calls) >= 1


class TestSetServerPolicyEnabled:

    def test_disable(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        wg.set_server_policy_enabled(SAMPLE_SERVER_POLICY["uuid"], False)

        update_calls = [
            c for c in mock_gateway.calls if c["method"] == "devConfig.update"
        ]
        assert len(update_calls) >= 1
        # The updated data should have enable="0"
        last_update = update_calls[-1]["data"]
        assert last_update["enable"] == "0"


# ── Peer Tests ────────────────────────────────────────────────────────


class TestListPeers:

    def test_returns_all_peers(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peers = wg.list_peers()
        assert len(peers) == 3
        descs = {p.desc for p in peers}
        assert "laptop-Danny" in descs
        assert "Caridad Pineiro" in descs


class TestGetPeer:

    def test_by_ip(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = wg.get_peer(ip="10.254.250.2")
        assert peer is not None
        assert peer.desc == "laptop-Danny"

    def test_by_desc(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = wg.get_peer(desc="Caridad Plaza del Carmen")
        assert peer is not None
        assert peer.ipaddr == "10.254.250.103"

    def test_not_found(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        assert wg.get_peer(ip="10.0.0.99") is None


class TestAddPeer:

    def test_add_new_peer(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = WireGuardPeer(
            uuid="new_uuid",
            desc="New Site",
            ipaddr="10.254.250.200",
            peer_pubkey="NEW_KEY==",
            preshared_key="NEW_PSK==",
        )
        policy = wg.add_peer(peer)
        assert len(policy.peers) == 4
        assert any(p.ipaddr == "10.254.250.200" for p in policy.peers)

    def test_conflict_ip(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = WireGuardPeer(
            uuid="dup_uuid",
            desc="Duplicate IP",
            ipaddr="10.254.250.2",  # Already used by laptop-Danny
            peer_pubkey="UNIQUE_KEY==",
        )
        with pytest.raises(RuijieWireGuardConflictError, match="IP"):
            wg.add_peer(peer)

    def test_conflict_pubkey(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = WireGuardPeer(
            uuid="dup_uuid",
            desc="Duplicate Key",
            ipaddr="10.254.250.200",
            peer_pubkey="FAKE_PUBKEY_DANNY==",  # Already used
        )
        with pytest.raises(RuijieWireGuardConflictError, match="public key"):
            wg.add_peer(peer)

    def test_auto_assigns_uuid(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = WireGuardPeer(
            uuid="",
            desc="No UUID",
            ipaddr="10.254.250.200",
            peer_pubkey="NO_UUID_KEY==",
        )
        policy = wg.add_peer(peer)
        added = [p for p in policy.peers if p.desc == "No UUID"][0]
        assert added.uuid != ""


class TestAddPeersBatch:

    def test_batch_add(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peers = [
            WireGuardPeer(uuid="", desc="Site A", ipaddr="10.254.250.200", peer_pubkey="A=="),
            WireGuardPeer(uuid="", desc="Site B", ipaddr="10.254.250.201", peer_pubkey="B=="),
        ]
        policy = wg.add_peers_batch(peers)
        assert len(policy.peers) == 5  # 3 existing + 2 new

    def test_batch_conflict_within_batch(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peers = [
            WireGuardPeer(uuid="", desc="Site A", ipaddr="10.254.250.200", peer_pubkey="A=="),
            WireGuardPeer(uuid="", desc="Site B", ipaddr="10.254.250.200", peer_pubkey="B=="),
        ]
        with pytest.raises(RuijieWireGuardConflictError):
            wg.add_peers_batch(peers)


class TestUpdatePeer:

    def test_update_by_uuid(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = WireGuardPeer(
            uuid="peer_uuid_001",
            desc="laptop-Danny-Updated",
            ipaddr="10.254.250.2",
            peer_pubkey="FAKE_PUBKEY_DANNY==",
        )
        policy = wg.update_peer(peer, match_by="uuid")
        updated = [p for p in policy.peers if p.uuid == "peer_uuid_001"][0]
        assert updated.desc == "laptop-Danny-Updated"

    def test_update_by_ip(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = WireGuardPeer(
            uuid="new_uuid",
            desc="Updated by IP",
            ipaddr="10.254.250.105",
            peer_pubkey="NEW_KEY==",
        )
        policy = wg.update_peer(peer, match_by="ip")
        updated = [p for p in policy.peers if p.ipaddr == "10.254.250.105"][0]
        assert updated.desc == "Updated by IP"

    def test_update_not_found(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = WireGuardPeer(
            uuid="nonexistent",
            desc="Ghost",
            ipaddr="10.0.0.99",
            peer_pubkey="X==",
        )
        with pytest.raises(RuijieWireGuardError, match="not found"):
            wg.update_peer(peer, match_by="uuid")


class TestDeletePeer:

    def test_delete_by_ip(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.delete_peer(ip="10.254.250.2")
        assert len(policy.peers) == 2
        assert not any(p.ipaddr == "10.254.250.2" for p in policy.peers)

    def test_delete_by_uuid(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.delete_peer(uuid="peer_uuid_003")
        assert len(policy.peers) == 2

    def test_delete_not_found(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        with pytest.raises(RuijieWireGuardError, match="not found"):
            wg.delete_peer(ip="10.0.0.99")


class TestRenamePeers:

    def test_rename(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        count = wg.rename_peers({
            "laptop-Danny": "Danny Laptop",
            "Caridad Pineiro": "FC Pineiro",
        })
        assert count == 2

    def test_rename_partial_match(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        count = wg.rename_peers({"laptop-Danny": "Danny", "nonexistent": "X"})
        assert count == 1

    def test_rename_no_match(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        count = wg.rename_peers({"not_here": "nope"})
        assert count == 0


# ── Client Policy Tests ──────────────────────────────────────────────


class TestListClientPolicies:

    def test_returns_parsed(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policies = wg.list_client_policies()
        assert len(policies) == 1
        assert policies[0].desc == "US_WG"

    def test_get_client_policy_default(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.get_client_policy()
        assert policy.endpoint == "67.203.206.66"


class TestUpdateClientEndpoint:

    def test_changes_endpoint(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.update_client_endpoint("centrouniquec.ruijieddnsd.com")
        assert policy.endpoint == "centrouniquec.ruijieddnsd.com"

    def test_changes_endpoint_and_port(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.update_client_endpoint("new.host.com", endpoint_port="51821")
        assert policy.endpoint == "new.host.com"
        assert policy.endpoint_port == "51821"


# ── Config Export ─────────────────────────────────────────────────────


class TestExportPeerConfig:

    def test_export(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        policy = wg.get_server_policy()
        peer = policy.peers[1]  # Caridad Pineiro
        cfg = wg.export_peer_config(
            peer, policy,
            hub_endpoint="centrouniquec.ruijieddnsd.com",
        )
        assert cfg.interface_ip == "10.254.250.105"
        assert cfg.peer_pubkey == policy.local_pubkey
        assert cfg.endpoint == "centrouniquec.ruijieddnsd.com"
        assert cfg.preshared_key == peer.preshared_key
        assert cfg.private_key == ""  # not available server-side


class TestParseConfigText:

    def test_parse(self):
        text = """\
[Interface]
PrivateKey = KEY==
Address = 10.0.0.5/32
DNS = 1.1.1.1

[Peer]
PublicKey = PEER_KEY==
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PresharedKey = PSK==
"""
        cfg = WireGuardManager.parse_config_text(text)
        assert cfg.interface_ip == "10.0.0.5"
        assert cfg.private_key == "KEY=="
        assert cfg.peer_pubkey == "PEER_KEY=="
        assert cfg.endpoint == "vpn.example.com"
        assert cfg.endpoint_port == "51820"


# ── IP Allocation ─────────────────────────────────────────────────────


class TestAllocateInterfaceIp:

    def test_skips_used(self):
        ip = WireGuardManager.allocate_interface_ip(
            "10.254.250.0/24",
            {"10.254.250.1", "10.254.250.2"},
        )
        assert ip == "10.254.250.3"

    def test_preferred_available(self):
        ip = WireGuardManager.allocate_interface_ip(
            "10.254.250.0/24",
            {"10.254.250.2"},
            preferred="10.254.250.100",
        )
        assert ip == "10.254.250.100"

    def test_preferred_taken(self):
        ip = WireGuardManager.allocate_interface_ip(
            "10.254.250.0/24",
            {"10.254.250.1", "10.254.250.100"},
            preferred="10.254.250.100",
        )
        assert ip != "10.254.250.100"

    def test_reserve_gateway_skips_dot_one(self):
        ip = WireGuardManager.allocate_interface_ip(
            "10.254.250.0/24",
            set(),
            reserve_gateway=True,
        )
        assert ip == "10.254.250.2"  # .1 skipped

    def test_no_reserve_uses_dot_one(self):
        ip = WireGuardManager.allocate_interface_ip(
            "10.254.250.0/24",
            set(),
            reserve_gateway=False,
        )
        assert ip == "10.254.250.1"

    def test_exhausted_network(self):
        # /30 gives 2 hosts: .1 and .2 — reserve .1, use .2, none left
        used = {"10.0.0.2"}
        with pytest.raises(RuijieWireGuardValidationError, match="No available IPs"):
            WireGuardManager.allocate_interface_ip("10.0.0.0/30", used)


class TestAllocateNextPeerIp:

    def test_allocates(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        # Existing peers use .2, .105, .103
        ip = wg.allocate_next_peer_ip("10.254.250.0/24")
        assert ip not in {"10.254.250.1", "10.254.250.2", "10.254.250.103", "10.254.250.105"}


class TestBuildAccessibleIps:

    def test_default_interface_only(self):
        result = WireGuardManager.build_accessible_ips("10.254.250.5")
        assert result == ["10.254.250.5/32"]

    def test_custom_ranges(self):
        result = WireGuardManager.build_accessible_ips("10.0.0.1", custom_ranges=["10.0.0.0/24"])
        assert result == ["10.0.0.0/24"]

    def test_no_ip_no_interface_only(self):
        result = WireGuardManager.build_accessible_ips(None, interface_only=False)
        assert result == ["0.0.0.0/0"]


class TestSuggestPolicyName:

    def test_basic(self):
        assert WireGuardManager.suggest_policy_name("Caridad Pineiro") == "Caridad Pineiro GW"

    def test_with_suffix(self):
        name = WireGuardManager.suggest_policy_name("Pineiro", suffix="Primary")
        assert name == "Pineiro GW Primary"

    def test_custom_role(self):
        name = WireGuardManager.suggest_policy_name("Site A", role="AP")
        assert name == "Site A AP"


# ── Add Site Peer (Orchestration) ─────────────────────────────────────


class TestAddSitePeer:

    def test_adds_peer(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer = wg.add_site_peer(
            desc="New Remote Site",
            interface_ip="10.254.250.200",
            peer_pubkey="REMOTE_PUB==",
            preshared_key="REMOTE_PSK==",
        )
        assert peer.desc == "New Remote Site"
        assert peer.ipaddr == "10.254.250.200"
        assert peer.uuid != ""

        # Verify it's in the updated state
        policy = wg.get_server_policy()
        assert any(p.ipaddr == "10.254.250.200" for p in policy.peers)


# ── Drift Detection ──────────────────────────────────────────────────


class TestDetectDrift:

    def _make_peer_and_client(self):
        peer = WireGuardPeer(
            uuid="peer_uuid_002",
            desc="Caridad Pineiro",
            ipaddr="10.254.250.105",
            peer_pubkey="wFTN1ARryoOvdyf37A0U8K1GA0fspN293guFjYlHRg4=",
            preshared_key="riXUgQwPj06rWqQcRC/2U7+OXC+f6xA4od/DeksBo3o=",
        )
        client = WireGuardClientPolicy(
            uuid="client_uuid_001",
            desc="US_WG",
            endpoint="centrouniquec.ruijieddnsd.com",
            local_addr="10.254.250.105/32",
            local_pubkey="wFTN1ARryoOvdyf37A0U8K1GA0fspN293guFjYlHRg4=",
            preshared_key="riXUgQwPj06rWqQcRC/2U7+OXC+f6xA4od/DeksBo3o=",
        )
        return peer, client

    def test_no_drift(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer, client = self._make_peer_and_client()
        report = wg.detect_drift(peer, client)
        assert not report.has_drift
        assert "in sync" in str(report)

    def test_endpoint_drift(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer, client = self._make_peer_and_client()
        client.endpoint = "67.203.206.66"  # old endpoint
        report = wg.detect_drift(
            peer, client,
            expected_endpoint="centrouniquec.ruijieddnsd.com",
        )
        assert report.has_drift
        endpoint_drift = [d for d in report.drifts if d.field == "endpoint"]
        assert len(endpoint_drift) == 1
        assert endpoint_drift[0].actual == "67.203.206.66"

    def test_ip_drift(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer, client = self._make_peer_and_client()
        client.local_addr = "10.254.250.99/32"
        report = wg.detect_drift(peer, client)
        assert report.has_drift
        assert any(d.field == "interface_ip" for d in report.drifts)

    def test_pubkey_drift(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        peer, client = self._make_peer_and_client()
        peer.peer_pubkey = "WRONG_KEY=="
        report = wg.detect_drift(peer, client)
        assert report.has_drift
        assert any(d.field == "peer_pubkey" for d in report.drifts)


# ── Reconciliation ────────────────────────────────────────────────────


class TestReconciliation:

    def test_no_changes_when_no_drift(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        report = DriftReport(peer_desc="test", peer_ip="10.0.0.1")
        plan = wg.generate_reconciliation_plan(report)
        assert not plan.has_changes

    def test_endpoint_fix_goes_to_site(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        report = DriftReport(
            peer_desc="test",
            peer_ip="10.0.0.1",
            drifts=[DriftField("endpoint", "correct.host.com", "old.host.com")],
        )
        plan = wg.generate_reconciliation_plan(report)
        assert plan.has_changes
        assert "endpoint" in plan.site_updates
        assert plan.site_updates["endpoint"] == "correct.host.com"

    def test_ip_drift_prefer_hub(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        report = DriftReport(
            peer_desc="test",
            peer_ip="10.0.0.1",
            drifts=[DriftField("interface_ip", "10.0.0.1", "10.0.0.99")],
        )
        plan = wg.generate_reconciliation_plan(report, prefer_hub=True)
        assert "local_addr" in plan.site_updates

    def test_ip_drift_prefer_site(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        report = DriftReport(
            peer_desc="test",
            peer_ip="10.0.0.1",
            drifts=[DriftField("interface_ip", "10.0.0.1", "10.0.0.99")],
        )
        plan = wg.generate_reconciliation_plan(report, prefer_hub=False)
        assert "ipaddr" in plan.hub_updates

    def test_apply_reconciliation_site_only(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        site_gw = MockGatewayClient(host="10.254.250.105")

        plan = ReconciliationPlan(
            peer_desc="test",
            peer_ip="10.254.250.105",
            site_updates={"endpoint": "new.host.com"},
        )
        wg.apply_reconciliation(plan, site_client=site_gw)

        update_calls = [c for c in site_gw.calls if c["method"] == "devConfig.update"]
        assert len(update_calls) >= 1

    def test_apply_reconciliation_requires_site_client(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        plan = ReconciliationPlan(
            peer_desc="test",
            peer_ip="10.0.0.1",
            site_updates={"endpoint": "x"},
        )
        with pytest.raises(RuijieWireGuardError, match="site_client required"):
            wg.apply_reconciliation(plan)

    def test_apply_reconciliation_hub_only(self, mock_gateway: MockGatewayClient):
        wg = WireGuardManager(mock_gateway)
        plan = ReconciliationPlan(
            peer_desc="Caridad Pineiro",
            peer_ip="10.254.250.105",
            hub_updates={"peer_pubkey": "CORRECTED_KEY=="},
        )
        wg.apply_reconciliation(plan)

        update_calls = [c for c in mock_gateway.calls if c["method"] == "devConfig.update"]
        assert len(update_calls) >= 1


# ── DriftReport / ReconciliationPlan dataclass tests ──────────────────


class TestDriftDataclasses:

    def test_drift_field_str(self):
        df = DriftField("endpoint", "correct", "wrong")
        assert "endpoint" in str(df)
        assert "correct" in str(df)

    def test_drift_report_str_with_drifts(self):
        report = DriftReport(
            peer_desc="test",
            peer_ip="10.0.0.1",
            drifts=[DriftField("endpoint", "a", "b")],
        )
        s = str(report)
        assert "1 drift(s)" in s

    def test_reconciliation_plan_no_changes(self):
        plan = ReconciliationPlan(peer_desc="x", peer_ip="10.0.0.1")
        assert not plan.has_changes
