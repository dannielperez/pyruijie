"""WireGuard VPN management for Ruijie/Reyee gateways.

Provides both low-level endpoint wrappers and high-level orchestration
helpers for managing WireGuard server and client policies on Ruijie EG
gateways in a hub-and-spoke deployment.

Architecture:
    - Hub/central gateway runs a WireGuard Server policy with peers
    - Site gateways run a WireGuard Client policy connecting to the hub
    - This module manages both sides via the LuCI JSON-RPC API

API Notes (reverse-engineered):
    - Server policies: ``devSta.get`` getype=1, ``devConfig.update`` with full
      server config including clientlist
    - Client policies: ``devConfig.get`` module=wireguard, ``devConfig.update``
      with the client object directly (not wrapped)
    - ``devConfig.add`` does NOT work for WireGuard peers (returns "Invalid parameters")
    - Config updates can timeout (60-120s) when the gateway applies changes
"""

from __future__ import annotations

import copy
import ipaddress
import logging
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Any

import requests

from pyruijie.gateway import GatewayClient
from pyruijie.exceptions import (
    RuijieApiError,
    RuijieWireGuardConflictError,
    RuijieWireGuardError,
    RuijieWireGuardValidationError,
)
from pyruijie.models import (
    WireGuardClientPolicy,
    WireGuardConfigExport,
    WireGuardPeer,
    WireGuardServerPolicy,
)

logger = logging.getLogger(__name__)


# ── Drift detection result ────────────────────────────────────────────


@dataclass
class DriftField:
    """A single field difference between expected and actual state."""

    field: str
    expected: Any
    actual: Any

    def __str__(self) -> str:
        return f"{self.field}: {self.actual!r} → {self.expected!r}"


@dataclass
class DriftReport:
    """Result of comparing hub peer state vs site client state."""

    peer_desc: str
    peer_ip: str
    drifts: list[DriftField] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return len(self.drifts) > 0

    def __str__(self) -> str:
        if not self.has_drift:
            return f"{self.peer_desc} ({self.peer_ip}): in sync"
        lines = [f"{self.peer_desc} ({self.peer_ip}): {len(self.drifts)} drift(s)"]
        for d in self.drifts:
            lines.append(f"  {d}")
        return "\n".join(lines)


@dataclass
class ReconciliationPlan:
    """Plan for reconciling drift between hub and site."""

    peer_desc: str
    peer_ip: str
    hub_updates: dict[str, Any] = field(default_factory=dict)
    site_updates: dict[str, Any] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.hub_updates or self.site_updates)


# ── WireGuard Manager ─────────────────────────────────────────────────


class WireGuardManager:
    """High-level WireGuard VPN manager for a Ruijie gateway.

    Wraps a :class:`GatewayClient` with typed methods for server policies,
    client policies, peer management, and hub-and-spoke orchestration.

    Usage::

        gw = GatewayClient("192.168.1.1", "admin", "password")
        gw.login()
        wg = WireGuardManager(gw)

        # List server policies
        servers = wg.list_server_policies()

        # Add a peer
        wg.add_peer(server_uuid, peer)
    """

    def __init__(self, client: GatewayClient) -> None:
        self.client = client

    # ── Server Policy: List / Read ────────────────────────────────────

    def list_server_policies(self) -> list[WireGuardServerPolicy]:
        """List all WireGuard server policies.

        Confirmed: ``devSta.get`` module=wireguard data={"getype":"1"}
        returns ``{"serverlist": [...]}`` with full peer info.
        """
        resp = self.client.cmd("devSta.get", "wireguard", {"getype": "1"})
        servers = resp.get("data", {}).get("serverlist", [])
        return [WireGuardServerPolicy.from_gateway(s) for s in servers]

    def get_server_policy(self, uuid: str | None = None) -> WireGuardServerPolicy:
        """Get a specific server policy by UUID, or the first one.

        Most gateways have a single WireGuard server policy.

        Raises:
            RuijieWireGuardError: If no server policies exist.
        """
        policies = self.list_server_policies()
        if not policies:
            raise RuijieWireGuardError("No WireGuard server policies configured")
        if uuid:
            for p in policies:
                if p.uuid == uuid:
                    return p
            raise RuijieWireGuardError(f"Server policy {uuid} not found")
        return policies[0]

    def get_server_policy_config(self) -> dict:
        """Get raw server policy config via devConfig.get.

        Useful for debugging or when you need the exact config shape.
        """
        resp = self.client.cmd("devConfig.get", "wireguard")
        return resp.get("data", {})

    # ── Server Policy: Create / Update / Delete ───────────────────────

    def create_server_policy(self, policy: WireGuardServerPolicy) -> None:
        """Create a new WireGuard server policy.

        Inferred: uses ``devConfig.add`` — this may not work on all firmware
        versions.  If it fails, try ``devConfig.update`` with the full config
        from ``get_server_policy_config()`` plus the new server entry.

        TODO: Confirm whether devConfig.add works for server policies.
              Known to NOT work for peers (clientlist entries).
        """
        data = policy.to_gateway()
        self.client.cmd_checked("devConfig.add", "wireguard", data, timeout=120)

    def update_server_policy(self, policy: WireGuardServerPolicy) -> None:
        """Update an existing WireGuard server policy.

        Confirmed: ``devConfig.update`` with the full server config including
        the complete clientlist.  The gateway replaces the entire policy.
        """
        data = policy.to_gateway()
        self.client.cmd_checked("devConfig.update", "wireguard", data, timeout=120)

    def delete_server_policy(self, uuid: str) -> None:
        """Delete a WireGuard server policy.

        Inferred: uses ``devConfig.del``.

        TODO: Confirm delete payload shape.  Use with extreme caution.
        """
        self.client.cmd_checked("devConfig.del", "wireguard", {"uuid": uuid})

    def set_server_policy_enabled(self, uuid: str, enabled: bool) -> None:
        """Enable or disable a server policy.

        Loads the full policy, toggles the enable flag, and pushes the update.
        """
        policy = self.get_server_policy(uuid)
        policy.enabled = enabled
        self.update_server_policy(policy)

    # ── Server Peers: List / Add / Edit / Delete ──────────────────────

    def list_peers(self, server_uuid: str | None = None) -> list[WireGuardPeer]:
        """List all peers on a server policy."""
        policy = self.get_server_policy(server_uuid)
        return policy.peers

    def get_peer(
        self,
        *,
        ip: str | None = None,
        pubkey: str | None = None,
        desc: str | None = None,
        server_uuid: str | None = None,
    ) -> WireGuardPeer | None:
        """Find a specific peer by IP, public key, or description."""
        policy = self.get_server_policy(server_uuid)
        return policy.find_peer(ip=ip, pubkey=pubkey, desc=desc)

    def add_peer(
        self,
        peer: WireGuardPeer,
        server_uuid: str | None = None,
    ) -> WireGuardServerPolicy:
        """Add a new peer to a server policy.

        Confirmed: the only way to add peers is to fetch the full server
        config, append to clientlist, and push the entire config back via
        ``devConfig.update``.  ``devConfig.add`` returns "Invalid parameters".

        Args:
            peer: The peer to add.
            server_uuid: Target server policy UUID (default: first).

        Returns:
            The updated server policy.

        Raises:
            RuijieWireGuardConflictError: If a peer with the same IP or
                public key already exists.
        """
        policy = self.get_server_policy(server_uuid)

        # Check for conflicts
        if policy.find_peer(ip=peer.ipaddr):
            raise RuijieWireGuardConflictError(
                f"Peer with IP {peer.ipaddr} already exists"
            )
        if policy.find_peer(pubkey=peer.peer_pubkey):
            raise RuijieWireGuardConflictError(
                f"Peer with public key {peer.peer_pubkey[:20]}... already exists"
            )

        # Assign UUID if missing
        if not peer.uuid:
            peer.uuid = _uuid.uuid4().hex

        policy.peers.append(peer)
        self.update_server_policy(policy)
        return policy

    def add_peers_batch(
        self,
        peers: list[WireGuardPeer],
        server_uuid: str | None = None,
    ) -> WireGuardServerPolicy:
        """Add multiple peers at once (single API call).

        More efficient than adding one-by-one since it only makes one
        update call.  All-or-nothing semantics.
        """
        policy = self.get_server_policy(server_uuid)
        existing_ips = {p.ipaddr for p in policy.peers}
        existing_keys = {p.peer_pubkey for p in policy.peers}

        for peer in peers:
            if peer.ipaddr in existing_ips:
                raise RuijieWireGuardConflictError(
                    f"Peer with IP {peer.ipaddr} already exists"
                )
            if peer.peer_pubkey in existing_keys:
                raise RuijieWireGuardConflictError(
                    f"Peer with public key {peer.peer_pubkey[:20]}... already exists"
                )
            if not peer.uuid:
                peer.uuid = _uuid.uuid4().hex
            existing_ips.add(peer.ipaddr)
            existing_keys.add(peer.peer_pubkey)

        policy.peers.extend(peers)
        self.update_server_policy(policy)
        return policy

    def update_peer(
        self,
        peer: WireGuardPeer,
        *,
        match_by: str = "uuid",
        server_uuid: str | None = None,
    ) -> WireGuardServerPolicy:
        """Update an existing peer on a server policy.

        Loads the full config, replaces the matching peer, and pushes.

        Args:
            peer: Updated peer data.
            match_by: Field to match on: "uuid", "ip", or "pubkey".
            server_uuid: Target server policy UUID.
        """
        policy = self.get_server_policy(server_uuid)

        found = False
        for i, existing in enumerate(policy.peers):
            match = False
            if match_by == "uuid" and existing.uuid == peer.uuid:
                match = True
            elif match_by == "ip" and existing.ipaddr == peer.ipaddr:
                match = True
            elif match_by == "pubkey" and existing.peer_pubkey == peer.peer_pubkey:
                match = True

            if match:
                policy.peers[i] = peer
                found = True
                break

        if not found:
            raise RuijieWireGuardError(f"Peer not found (match_by={match_by})")

        self.update_server_policy(policy)
        return policy

    def delete_peer(
        self,
        *,
        ip: str | None = None,
        pubkey: str | None = None,
        uuid: str | None = None,
        server_uuid: str | None = None,
    ) -> WireGuardServerPolicy:
        """Remove a peer from a server policy.

        Loads the full config, removes the matching peer, and pushes.
        """
        policy = self.get_server_policy(server_uuid)
        original_count = len(policy.peers)

        policy.peers = [
            p for p in policy.peers
            if not (
                (ip and p.ipaddr == ip)
                or (pubkey and p.peer_pubkey == pubkey)
                or (uuid and p.uuid == uuid)
            )
        ]

        if len(policy.peers) == original_count:
            raise RuijieWireGuardError("Peer not found for deletion")

        self.update_server_policy(policy)
        return policy

    def rename_peers(
        self,
        name_map: dict[str, str],
        server_uuid: str | None = None,
    ) -> int:
        """Rename multiple peers by matching current desc → new desc.

        Args:
            name_map: ``{current_desc: new_desc}`` mapping.
            server_uuid: Target server policy UUID.

        Returns:
            Number of peers renamed.
        """
        policy = self.get_server_policy(server_uuid)
        count = 0
        for peer in policy.peers:
            if peer.desc in name_map:
                peer.desc = name_map[peer.desc]
                count += 1

        if count > 0:
            self.update_server_policy(policy)
        return count

    # ── Client Policy: List / Read ────────────────────────────────────

    def list_client_policies(self) -> list[WireGuardClientPolicy]:
        """List WireGuard client policies on this gateway.

        Confirmed: ``devSta.get`` getype=0 returns ``{"clientlist": [...]}``
        with runtime stats (rxbyte, txbyte, updateTime).
        """
        resp = self.client.cmd("devSta.get", "wireguard", {"getype": "0"})
        clients = resp.get("data", {}).get("clientlist", [])
        return [WireGuardClientPolicy.from_gateway(c) for c in clients]

    def get_client_policy(self, uuid: str | None = None) -> WireGuardClientPolicy:
        """Get a specific client policy or the first one.

        Raises:
            RuijieWireGuardError: If no client policies exist.
        """
        policies = self.list_client_policies()
        if not policies:
            raise RuijieWireGuardError("No WireGuard client policies configured")
        if uuid:
            for p in policies:
                if p.uuid == uuid:
                    return p
            raise RuijieWireGuardError(f"Client policy {uuid} not found")
        return policies[0]

    def get_client_policy_config(self) -> dict:
        """Get raw client policy config via devConfig.get.

        Returns the full config structure including version and configId.
        """
        resp = self.client.cmd("devConfig.get", "wireguard")
        return resp.get("data", {})

    # ── Client Policy: Create / Update / Delete ───────────────────────

    def create_client_policy(self, policy: WireGuardClientPolicy) -> None:
        """Create a new WireGuard client policy on a site gateway.

        Inferred: uses ``devConfig.add``.

        TODO: Confirm whether devConfig.add works for client policies.
              If not, use devConfig.update with the full config.
        """
        data = policy.to_gateway()
        self.client.cmd_checked("devConfig.add", "wireguard", data, timeout=120)

    def update_client_policy(self, policy: WireGuardClientPolicy) -> None:
        """Update an existing WireGuard client policy.

        Confirmed on EG310GH-P-E: ``devConfig.update`` accepts the client
        object directly (not wrapped in the full config structure).
        """
        data = policy.to_gateway()
        self.client.cmd_checked("devConfig.update", "wireguard", data, timeout=120)

    def delete_client_policy(self, uuid: str) -> None:
        """Delete a WireGuard client policy.

        Inferred: uses ``devConfig.del``.

        TODO: Confirm delete payload shape.
        """
        self.client.cmd_checked("devConfig.del", "wireguard", {"uuid": uuid})

    def update_client_endpoint(
        self,
        endpoint: str,
        endpoint_port: str | None = None,
        uuid: str | None = None,
    ) -> WireGuardClientPolicy:
        """Update the server endpoint on a client policy.

        Convenience method for the common task of changing the hub's
        IP/domain on a site gateway.
        """
        policy = self.get_client_policy(uuid)
        policy.endpoint = endpoint
        if endpoint_port is not None:
            policy.endpoint_port = endpoint_port
        self.update_client_policy(policy)
        return policy

    # ── Config Export / Import ─────────────────────────────────────────

    def export_peer_config(
        self,
        peer: WireGuardPeer,
        server: WireGuardServerPolicy,
        *,
        hub_endpoint: str = "",
        hub_endpoint_port: str = "51820",
        dns: str = "8.8.8.8",
        allowed_ips: str = "0.0.0.0/0",
    ) -> WireGuardConfigExport:
        """Build a WireGuard config file for a peer to connect to the hub.

        Note: The private key is NOT available from the server side.
        The config will have an empty private_key field — the caller
        must supply it if generating a complete .conf file.
        """
        return WireGuardConfigExport(
            interface_ip=peer.ipaddr,
            private_key="",  # Not available server-side
            dns=dns,
            peer_pubkey=server.local_pubkey,
            endpoint=hub_endpoint or self.client.host,
            endpoint_port=hub_endpoint_port or server.local_port,
            allowed_ips=allowed_ips,
            preshared_key=peer.preshared_key,
        )

    @staticmethod
    def parse_config_text(text: str) -> WireGuardConfigExport:
        """Parse a standard WireGuard .conf file into normalized fields."""
        return WireGuardConfigExport.from_conf_text(text)

    # ── Network / IP Allocation Helpers ────────────────────────────────

    @staticmethod
    def allocate_interface_ip(
        network: str,
        used_ips: set[str],
        *,
        preferred: str | None = None,
        reserve_gateway: bool = True,
    ) -> str:
        """Allocate the next available IP in a network.

        Args:
            network: CIDR network (e.g. "10.100.0.0/20").
            used_ips: Set of already-allocated IPs.
            preferred: Preferred IP to use if available.
            reserve_gateway: Skip .1 address (hub gateway).

        Returns:
            The allocated IP as a string.

        Raises:
            RuijieWireGuardValidationError: If no IPs are available.
        """
        net = ipaddress.ip_network(network, strict=False)

        if preferred and preferred not in used_ips:
            if ipaddress.ip_address(preferred) in net:
                return preferred

        for host in net.hosts():
            ip_str = str(host)
            if reserve_gateway and ip_str.endswith(".1"):
                continue
            if ip_str not in used_ips:
                return ip_str

        raise RuijieWireGuardValidationError(
            f"No available IPs in {network} ({len(used_ips)} used)"
        )

    def allocate_next_peer_ip(
        self,
        network: str,
        server_uuid: str | None = None,
        *,
        preferred: str | None = None,
    ) -> str:
        """Allocate the next available peer IP from the server's network.

        Queries existing peers and finds the next free IP.
        """
        policy = self.get_server_policy(server_uuid)
        used = {p.ipaddr for p in policy.peers}
        return self.allocate_interface_ip(network, used, preferred=preferred)

    @staticmethod
    def build_accessible_ips(
        interface_ip: str | None = None,
        custom_ranges: list[str] | None = None,
        *,
        interface_only: bool = True,
    ) -> list[str]:
        """Build the accessible IP ranges for a peer.

        Args:
            interface_ip: The peer's VPN interface IP.
            custom_ranges: Custom IP ranges to allow.
            interface_only: If True, only allow the interface IP (default).

        Returns:
            List of CIDR strings.
        """
        if custom_ranges:
            return custom_ranges
        if interface_ip and interface_only:
            return [f"{interface_ip}/32"]
        return ["0.0.0.0/0"]

    @staticmethod
    def suggest_policy_name(
        site_name: str,
        role: str = "GW",
        suffix: str | None = None,
    ) -> str:
        """Generate a consistent policy name for a site.

        Args:
            site_name: Human-readable site name.
            role: Device role suffix (e.g. "GW", "AP").
            suffix: Optional extra suffix.

        Returns:
            A policy name like "Site Alpha GW".
        """
        parts = [site_name, role]
        if suffix:
            parts.append(suffix)
        return " ".join(parts)

    # ── Hub-and-Spoke Orchestration ───────────────────────────────────

    def add_site_peer(
        self,
        *,
        desc: str,
        interface_ip: str,
        peer_pubkey: str,
        preshared_key: str = "",
        allow_ips: list[str] | None = None,
        server_uuid: str | None = None,
    ) -> WireGuardPeer:
        """Add a new site peer to the hub server policy.

        Convenience method that builds the peer and adds it.

        Args:
            desc: Peer description (site name).
            interface_ip: VPN IP for the peer.
            peer_pubkey: The site gateway's WireGuard public key.
            preshared_key: Pre-shared key for this peer.
            allow_ips: Accessible IP ranges (default: interface IP /32).
            server_uuid: Target server policy UUID.

        Returns:
            The created WireGuardPeer.
        """
        peer = WireGuardPeer(
            uuid=_uuid.uuid4().hex,
            desc=desc,
            ipaddr=interface_ip,
            peer_pubkey=peer_pubkey,
            preshared_key=preshared_key,
            allow_ips=allow_ips or [f"{interface_ip}/32"],
        )
        self.add_peer(peer, server_uuid)
        return peer

    def create_site_client_policy(
        self,
        site_client: GatewayClient,
        *,
        policy_name: str = "US_WG",
        hub_endpoint: str,
        hub_endpoint_port: str = "51820",
        hub_pubkey: str,
        interface_ip: str,
        local_privkey: str,
        local_pubkey: str,
        preshared_key: str = "",
        allow_ips: list[str] | None = None,
        dns: list[str] | None = None,
        keepalive: str = "30",
    ) -> WireGuardClientPolicy:
        """Create a WireGuard client policy on a remote site gateway.

        Creates the client-side configuration that connects the site
        gateway back to the hub.

        Args:
            site_client: Authenticated GatewayClient for the site gateway.
            policy_name: Name for the client policy.
            hub_endpoint: Hub server IP or hostname.
            hub_endpoint_port: Hub server WireGuard port.
            hub_pubkey: Hub server's public key.
            interface_ip: VPN IP assigned to this site.
            local_privkey: Site gateway's private key.
            local_pubkey: Site gateway's public key.
            preshared_key: Pre-shared key for this connection.
            allow_ips: Routing IPs (default: 0.0.0.0/0).
            dns: DNS servers (default: ["8.8.8.8"]).
            keepalive: Persistent keepalive interval.

        Returns:
            The created WireGuardClientPolicy.
        """
        policy = WireGuardClientPolicy(
            uuid=_uuid.uuid4().hex,
            desc=policy_name,
            enabled=True,
            endpoint=hub_endpoint,
            endpoint_port=hub_endpoint_port,
            local_addr=f"{interface_ip}/32",
            local_port="51820",
            local_privkey=local_privkey,
            local_pubkey=local_pubkey,
            peer_pubkey=hub_pubkey,
            preshared_key=preshared_key,
            allow_ips=allow_ips or ["0.0.0.0/0"],
            local_dns=dns or ["8.8.8.8"],
            keepalive=keepalive,
        )

        site_wg = WireGuardManager(site_client)
        site_wg.update_client_policy(policy)
        return policy

    # ── Drift Detection & Reconciliation ──────────────────────────────

    def detect_drift(
        self,
        peer: WireGuardPeer,
        client_policy: WireGuardClientPolicy,
        *,
        expected_endpoint: str | None = None,
    ) -> DriftReport:
        """Compare hub peer state against site client policy.

        Checks for mismatches in endpoint, public keys, interface IP,
        preshared key, and DNS.

        Args:
            peer: The peer entry from the hub server policy.
            client_policy: The client policy from the site gateway.
            expected_endpoint: Expected hub endpoint on the client side.
        """
        report = DriftReport(peer_desc=peer.desc, peer_ip=peer.ipaddr)

        # Interface IP: peer.ipaddr should match client localAddr (minus /32)
        client_ip = client_policy.local_addr.split("/")[0]
        if peer.ipaddr != client_ip:
            report.drifts.append(DriftField(
                field="interface_ip",
                expected=peer.ipaddr,
                actual=client_ip,
            ))

        # Public key: peer should have the client's public key
        if peer.peer_pubkey != client_policy.local_pubkey:
            report.drifts.append(DriftField(
                field="peer_pubkey",
                expected=client_policy.local_pubkey,
                actual=peer.peer_pubkey,
            ))

        # Preshared key
        if peer.preshared_key and client_policy.preshared_key:
            if peer.preshared_key != client_policy.preshared_key:
                report.drifts.append(DriftField(
                    field="preshared_key",
                    expected=peer.preshared_key,
                    actual=client_policy.preshared_key,
                ))

        # Endpoint check (if expected is provided)
        if expected_endpoint and client_policy.endpoint != expected_endpoint:
            report.drifts.append(DriftField(
                field="endpoint",
                expected=expected_endpoint,
                actual=client_policy.endpoint,
            ))

        return report

    def generate_reconciliation_plan(
        self,
        drift: DriftReport,
        *,
        prefer_hub: bool = True,
    ) -> ReconciliationPlan:
        """Generate a plan to fix detected drift.

        Args:
            drift: Drift report from detect_drift().
            prefer_hub: If True, hub values are authoritative (default).
                       If False, site values are authoritative.
        """
        plan = ReconciliationPlan(
            peer_desc=drift.peer_desc,
            peer_ip=drift.peer_ip,
        )

        for d in drift.drifts:
            if d.field == "endpoint":
                # Endpoint is always updated on the site side
                plan.site_updates["endpoint"] = d.expected
            elif d.field == "interface_ip":
                if prefer_hub:
                    plan.site_updates["local_addr"] = f"{d.expected}/32"
                else:
                    plan.hub_updates["ipaddr"] = d.actual
            elif d.field == "peer_pubkey":
                if prefer_hub:
                    # Hub has wrong key — update hub
                    plan.hub_updates["peer_pubkey"] = d.expected
                else:
                    # Site has wrong key — unusual, may need key regeneration
                    plan.site_updates["local_pubkey"] = d.expected
            elif d.field == "preshared_key":
                # PSK mismatches require both sides to agree
                # Default: set site to match hub
                if prefer_hub:
                    plan.site_updates["preshared_key"] = d.expected
                else:
                    plan.hub_updates["preshared_key"] = d.actual

        return plan

    def apply_reconciliation(
        self,
        plan: ReconciliationPlan,
        *,
        site_client: GatewayClient | None = None,
        server_uuid: str | None = None,
    ) -> None:
        """Apply a reconciliation plan.

        Args:
            plan: Plan generated by generate_reconciliation_plan().
            site_client: Authenticated client for the site gateway
                        (required if plan has site_updates).
            server_uuid: Hub server policy UUID.

        Raises:
            RuijieWireGuardError: If site_client is needed but not provided.
        """
        if plan.hub_updates:
            peer = self.get_peer(ip=plan.peer_ip, server_uuid=server_uuid)
            if not peer:
                raise RuijieWireGuardError(
                    f"Hub peer {plan.peer_ip} not found for reconciliation"
                )
            for field_name, value in plan.hub_updates.items():
                setattr(peer, field_name, value)
            self.update_peer(peer, match_by="ip", server_uuid=server_uuid)

        if plan.site_updates:
            if not site_client:
                raise RuijieWireGuardError(
                    "site_client required to apply site-side updates"
                )
            site_wg = WireGuardManager(site_client)
            policy = site_wg.get_client_policy()
            for field_name, value in plan.site_updates.items():
                if field_name == "endpoint":
                    policy.endpoint = value
                elif field_name == "local_addr":
                    policy.local_addr = value
                elif field_name == "preshared_key":
                    policy.preshared_key = value
                elif field_name == "local_pubkey":
                    policy.local_pubkey = value
            site_wg.update_client_policy(policy)
