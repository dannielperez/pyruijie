"""Typed models for Ruijie Cloud API responses and Gateway WireGuard configuration."""

from __future__ import annotations

import uuid as _uuid
from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Interface, IPv4Network, ip_interface, ip_network
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Project(BaseModel):
    """A Ruijie Cloud project (building-level network group)."""

    name: str
    group_id: str = Field(alias="groupId")

    @field_validator("group_id", mode="before")
    @classmethod
    def _coerce_group_id_to_str(cls, value):
        """Ruijie may return numeric group IDs; normalize to string."""
        if value is None:
            return ""
        return str(value)

    model_config = {"populate_by_name": True}


class Device(BaseModel):
    """A network device managed by Ruijie Cloud."""

    serial_number: str = Field(alias="serialNumber")
    product_type: str | None = Field(default=None, alias="productType")
    product_class: str | None = Field(default=None, alias="productClass")
    name: str | None = Field(default=None, alias="aliasName")
    online_status: str | None = Field(default=None, alias="onlineStatus")
    local_ip: str | None = Field(default=None, alias="localIp")
    egress_ip: str | None = Field(default=None, alias="cpeIp")
    mac: str | None = None
    firmware_version: str | None = Field(default=None, alias="softwareVersion")

    model_config = {"populate_by_name": True}

    @property
    def is_online(self) -> bool:
        return self.online_status == "ONLINE"


class ClientDevice(BaseModel):
    """A client device connected to a Ruijie-managed network.

    Maps to the ``/service/api/open/v1/dev/user/current-user`` response.
    Connected devices include phones, laptops, cameras, intercoms, etc.
    """

    mac: str = Field(alias="mac")
    ip: str | None = Field(default=None, alias="ip")
    user_name: str | None = Field(default=None, alias="userName")
    connect_type: str | None = Field(default=None, alias="connectType")
    ssid: str | None = Field(default=None, alias="ssid")
    linked_device: str | None = Field(default=None, alias="linkedDevice")
    device_name: str | None = Field(default=None, alias="deviceName")
    client_source: str | None = Field(default=None, alias="clientSource")
    manufacturer: str | None = Field(default=None, alias="manufacturer")
    manufacturer_id: str | None = Field(default=None, alias="manufacturerId")
    sta_category: str | None = Field(default=None, alias="staCategory")
    sta_category_name: str | None = Field(default=None, alias="staCategoryName")
    sta_label: str | None = Field(default=None, alias="staLabel")
    sta_label_name: str | None = Field(default=None, alias="staLabelName")
    sta_os: str | None = Field(default=None, alias="staOs")
    sta_model: str | None = Field(default=None, alias="staModel")
    online_time: int | None = Field(default=None, alias="onlineTime")
    group_name: str | None = Field(default=None, alias="groupName")
    flow_up: int | None = Field(default=None, alias="flowUp")
    flow_down: int | None = Field(default=None, alias="flowDown")
    band: str | None = Field(default=None, alias="band")
    rssi: int | None = Field(default=None, alias="rssi")
    channel: int | None = Field(default=None, alias="channel")

    model_config = {"populate_by_name": True}

    # -- backward-compatible property accessors for discovery code -----------

    @property
    def hostname(self) -> str | None:
        """Client hostname (from ``userName`` field)."""
        return self.user_name

    @property
    def os_type(self) -> str | None:
        """OS / vendor string for classification heuristics."""
        return self.sta_os or self.manufacturer

    @property
    def ap_name(self) -> str | None:
        """Name of the AP this client is connected to (if wireless)."""
        if self.client_source == "AP":
            return self.device_name
        return None

    @property
    def ap_mac(self) -> str | None:
        """SN of the AP this client is connected to (if wireless)."""
        if self.client_source == "AP":
            return self.linked_device
        return None

    @property
    def switch_name(self) -> str | None:
        """Name of the switch this client is connected to (if wired)."""
        if self.client_source == "Switch":
            return self.device_name
        return None

    @property
    def switch_port(self) -> str | None:
        """Switch port (not available from current-user endpoint)."""
        return None

    @property
    def vlan_id(self) -> int | None:
        """VLAN ID (not available from current-user endpoint)."""
        return None

    @property
    def is_online(self) -> bool:
        """Clients returned by current-user are always online."""
        return True


class GatewayPort(BaseModel):
    """A WAN or LAN port on a Ruijie gateway device.

    Maps to the ``/service/api/gateway/intf/info/{sn}`` response items.
    """

    alias: str = Field(default="", alias="alias")
    port_type: str = Field(default="", alias="type")
    ip_address: str = Field(default="", alias="ipAddr")
    ip_mask: str = Field(default="", alias="ipMask")
    line_status: str = Field(default="", alias="linestatus")
    speed: str = Field(default="", alias="speed")
    next_hop: str = Field(default="", alias="nextHop")
    pppoe: str = Field(default="", alias="pppoe")

    model_config = {"populate_by_name": True}

    @property
    def subnet(self) -> str | None:
        """Derive CIDR subnet from IP address and mask (e.g. ``192.168.1.0/24``)."""
        if not self.ip_address or not self.ip_mask:
            return None
        try:
            return str(IPv4Network(f"{self.ip_address}/{self.ip_mask}", strict=False))
        except (ValueError, TypeError):
            return None

    @property
    def is_lan(self) -> bool:
        return self.port_type.upper() == "LAN"

    @property
    def is_wan(self) -> bool:
        return self.port_type.upper() == "WAN"

    @property
    def is_up(self) -> bool:
        return self.line_status.lower() in ("up", "1")


class SwitchPort(BaseModel):
    """A port on a Ruijie-managed switch.

    Maps to the ``/service/api/conf/switch/device/{sn}/ports`` response items.
    """

    name: str = Field(default="", alias="name")
    port_type: str = Field(default="", alias="type")
    vlan: int | None = Field(default=None, alias="vlan")
    vlan_list: str = Field(default="", alias="vlanList")
    status: str = Field(default="", alias="status")
    speed: str = Field(default="", alias="speed")
    is_uplink: bool = Field(default=False, alias="isUplink")
    poe_status: str = Field(default="", alias="poeStatus")
    power_used: str = Field(default="", alias="powerUsed")
    loop_state: str = Field(default="", alias="loopState")
    enable: str = Field(default="", alias="enable")

    model_config = {"populate_by_name": True}

    @field_validator("is_uplink", mode="before")
    @classmethod
    def _coerce_uplink(cls, value: object) -> bool:
        """Ruijie returns various truthy values for uplink flag."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        if isinstance(value, int):
            return value != 0
        return False

    @property
    def is_up(self) -> bool:
        return self.status.lower() in ("up", "1")

    @property
    def allowed_vlans(self) -> set[int]:
        """Parse ``vlan_list`` (e.g. ``'1-4,100,200'``) into integer set."""
        return parse_vlan_list(self.vlan_list)


def parse_vlan_list(vlan_str: str) -> set[int]:
    """Parse a VLAN list string like ``'1-4,100,200'`` into a set of ints.

    Handles ranges (``'1-4'``), individual values (``'100'``), and mixed
    (``'1-4,100,200-205'``).  Returns an empty set for empty/invalid input.
    """
    vlans: set[int] = set()
    if not vlan_str:
        return vlans
    for part in vlan_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start_s, end_s = part.split("-", 1)
                for v in range(int(start_s), int(end_s) + 1):
                    vlans.add(v)
            except (ValueError, TypeError):
                pass
        elif part.isdigit():
            vlans.add(int(part))
    return vlans


# ══════════════════════════════════════════════════════════════════════
# Gateway WireGuard models (dataclasses — for local LuCI JSON-RPC API)
# ══════════════════════════════════════════════════════════════════════


@dataclass
class WireGuardPeer:
    """A single WireGuard peer/client registered on a server policy.

    Confirmed fields from ``devSta.get`` getype=1 → serverlist[].clientlist[]:
        uuid, desc, ipaddr, peerPubkey, presharedkey, allowips

    Additional runtime fields (present in status queries but not config):
        endpoint, rxbyte, txbyte, updateTime
    """

    uuid: str
    desc: str
    ipaddr: str
    peer_pubkey: str
    preshared_key: str = ""
    allow_ips: list[str] = field(default_factory=list)
    endpoint: str = ""
    rx_bytes: int = 0
    tx_bytes: int = 0
    update_time: str = ""
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_gateway(cls, data: dict) -> WireGuardPeer:
        return cls(
            uuid=data.get("uuid", ""),
            desc=data.get("desc", ""),
            ipaddr=data.get("ipaddr", ""),
            peer_pubkey=data.get("peerPubkey", ""),
            preshared_key=data.get("presharedkey", ""),
            allow_ips=data.get("allowips", []),
            endpoint=data.get("endpoint", ""),
            rx_bytes=int(data.get("rxbyte", 0) or 0),
            tx_bytes=int(data.get("txbyte", 0) or 0),
            update_time=data.get("updateTime", ""),
            raw=data,
        )

    def to_gateway(self) -> dict:
        return {
            "uuid": self.uuid or _uuid.uuid4().hex,
            "desc": self.desc,
            "ipaddr": self.ipaddr,
            "peerPubkey": self.peer_pubkey,
            "presharedkey": self.preshared_key,
            "allowips": self.allow_ips or [f"{self.ipaddr}/32"],
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return d


@dataclass
class WireGuardServerPolicy:
    """A WireGuard VPN Server policy on the gateway.

    Confirmed fields from ``devSta.get`` getype=1 → serverlist[].
    """

    uuid: str
    desc: str
    enabled: bool = True
    local_addr: str = ""
    local_port: str = "51820"
    local_privkey: str = ""
    local_pubkey: str = ""
    local_dns: list[str] = field(default_factory=list)
    peers: list[WireGuardPeer] = field(default_factory=list)
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_gateway(cls, data: dict) -> WireGuardServerPolicy:
        peers = [WireGuardPeer.from_gateway(p) for p in data.get("clientlist", [])]
        return cls(
            uuid=data.get("uuid", ""),
            desc=data.get("desc", ""),
            enabled=data.get("enable") == "1",
            local_addr=data.get("localAddr", ""),
            local_port=data.get("localPort", "51820"),
            local_privkey=data.get("localPrivkey", ""),
            local_pubkey=data.get("localPubkey", ""),
            local_dns=data.get("localDns", []),
            peers=peers,
            raw=data,
        )

    def to_gateway(self) -> dict:
        return {
            "uuid": self.uuid,
            "enable": "1" if self.enabled else "0",
            "type": "1",
            "desc": self.desc,
            "localAddr": self.local_addr,
            "localPort": self.local_port,
            "localPrivkey": self.local_privkey,
            "localPubkey": self.local_pubkey,
            "localDns": self.local_dns,
            "clientlist": [p.to_gateway() for p in self.peers],
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return d

    def find_peer(
        self,
        *,
        ip: str | None = None,
        pubkey: str | None = None,
        desc: str | None = None,
    ) -> WireGuardPeer | None:
        for p in self.peers:
            if ip and p.ipaddr == ip:
                return p
            if pubkey and p.peer_pubkey == pubkey:
                return p
            if desc and p.desc == desc:
                return p
        return None


@dataclass
class WireGuardClientPolicy:
    """A WireGuard VPN Client policy on a site gateway.

    Confirmed fields from ``devConfig.get`` module=wireguard on EG310GH-P-E.
    """

    uuid: str
    desc: str
    enabled: bool = True
    endpoint: str = ""
    endpoint_port: str = "51820"
    local_addr: str = ""
    local_port: str = "51820"
    local_privkey: str = ""
    local_pubkey: str = ""
    peer_pubkey: str = ""
    preshared_key: str = ""
    allow_ips: list[str] = field(default_factory=list)
    local_dns: list[str] = field(default_factory=list)
    interface: str = "all"
    keepalive: str = "30"
    local_ifname: str = "wgclt0"
    metric: str = "101"
    priority: list[str] = field(default_factory=list)
    strict_priority: str = "0"
    rx_bytes: int = 0
    tx_bytes: int = 0
    update_time: str = ""
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_gateway(cls, data: dict) -> WireGuardClientPolicy:
        return cls(
            uuid=data.get("uuid", ""),
            desc=data.get("desc", ""),
            enabled=data.get("enable") == "1",
            endpoint=data.get("endpoint", ""),
            endpoint_port=data.get("endpointPort", "51820"),
            local_addr=data.get("localAddr", ""),
            local_port=data.get("localPort", "51820"),
            local_privkey=data.get("localPrivkey", ""),
            local_pubkey=data.get("localPubkey", ""),
            peer_pubkey=data.get("peerPubkey", ""),
            preshared_key=data.get("presharedkey", ""),
            allow_ips=data.get("allowips", []),
            local_dns=data.get("localDns", []),
            interface=data.get("intf", "all"),
            keepalive=data.get("keepalive", "30"),
            local_ifname=data.get("localIfname", "wgclt0"),
            metric=data.get("metric", "101"),
            priority=data.get("priority", []),
            strict_priority=data.get("strictPriority", "0"),
            rx_bytes=int(data.get("rxbyte", 0) or 0),
            tx_bytes=int(data.get("txbyte", 0) or 0),
            update_time=data.get("updateTime", ""),
            raw=data,
        )

    def to_gateway(self) -> dict:
        return {
            "uuid": self.uuid,
            "enable": "1" if self.enabled else "0",
            "type": "0",
            "desc": self.desc,
            "endpoint": self.endpoint,
            "endpointPort": self.endpoint_port,
            "localAddr": self.local_addr,
            "localPort": self.local_port,
            "localPrivkey": self.local_privkey,
            "localPubkey": self.local_pubkey,
            "peerPubkey": self.peer_pubkey,
            "presharedkey": self.preshared_key,
            "allowips": self.allow_ips,
            "localDns": self.local_dns,
            "intf": self.interface,
            "keepalive": self.keepalive,
            "localIfname": self.local_ifname,
            "metric": self.metric,
            "priority": self.priority,
            "strictPriority": self.strict_priority,
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return d


@dataclass
class WireGuardConfigExport:
    """A standard WireGuard .conf file representation."""

    interface_ip: str
    private_key: str = ""
    dns: str = "8.8.8.8"
    peer_pubkey: str = ""
    endpoint: str = ""
    endpoint_port: str = "51820"
    allowed_ips: str = "0.0.0.0/0"
    preshared_key: str = ""

    def to_conf_text(self) -> str:
        lines = ["[Interface]"]
        if self.private_key:
            lines.append(f"PrivateKey = {self.private_key}")
        lines.append(f"Address = {self.interface_ip}/32")
        if self.dns:
            lines.append(f"DNS = {self.dns}")
        lines.append("")
        lines.append("[Peer]")
        if self.peer_pubkey:
            lines.append(f"PublicKey = {self.peer_pubkey}")
        if self.endpoint:
            ep = f"{self.endpoint}:{self.endpoint_port}" if self.endpoint_port else self.endpoint
            lines.append(f"Endpoint = {ep}")
        if self.allowed_ips:
            lines.append(f"AllowedIPs = {self.allowed_ips}")
        if self.preshared_key:
            lines.append(f"PresharedKey = {self.preshared_key}")
        lines.append("")
        return "\n".join(lines)

    @classmethod
    def from_conf_text(cls, text: str) -> WireGuardConfigExport:
        import re

        def _get(key: str) -> str:
            m = re.search(
                rf"^\s*{re.escape(key)}\s*=\s*(.+)$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            return m.group(1).strip() if m else ""

        address = _get("Address")
        interface_ip = address.split("/")[0] if address else ""
        endpoint_raw = _get("Endpoint")
        endpoint = ""
        endpoint_port = "51820"
        if endpoint_raw:
            if ":" in endpoint_raw:
                endpoint, endpoint_port = endpoint_raw.rsplit(":", 1)
            else:
                endpoint = endpoint_raw

        return cls(
            interface_ip=interface_ip,
            private_key=_get("PrivateKey"),
            dns=_get("DNS"),
            peer_pubkey=_get("PublicKey"),
            endpoint=endpoint,
            endpoint_port=endpoint_port,
            allowed_ips=_get("AllowedIPs"),
            preshared_key=_get("PresharedKey"),
        )


# ── Network helpers ───────────────────────────────────────────────────


def validate_ipv4_cidr(value: str) -> IPv4Interface:
    """Parse and validate an IPv4 address with optional CIDR prefix."""
    return ip_interface(value)


def validate_ipv4_network(value: str) -> IPv4Network:
    """Parse and validate an IPv4 network."""
    return ip_network(value, strict=False)
