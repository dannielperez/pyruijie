"""Typed models for Ruijie Cloud API responses."""

from __future__ import annotations

from ipaddress import IPv4Network

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
