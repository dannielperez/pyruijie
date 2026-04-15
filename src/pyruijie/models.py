"""Typed models for Ruijie Cloud API responses."""

from __future__ import annotations

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

    Represents end-user devices (phones, laptops, IoT, etc.) discovered
    via Ruijie Cloud's client listing API.
    """

    mac: str = Field(alias="mac")
    ip: str | None = Field(default=None, alias="ip")
    hostname: str | None = Field(default=None, alias="hostname")
    os_type: str | None = Field(default=None, alias="osType")
    connect_type: str | None = Field(default=None, alias="connectType")
    ssid: str | None = Field(default=None, alias="ssid")
    ap_name: str | None = Field(default=None, alias="apName")
    ap_mac: str | None = Field(default=None, alias="apMac")
    switch_name: str | None = Field(default=None, alias="switchName")
    switch_port: str | None = Field(default=None, alias="switchPort")
    vlan_id: int | None = Field(default=None, alias="vlanId")
    online_status: str | None = Field(default=None, alias="onlineStatus")
    up_time: int | None = Field(default=None, alias="upTime")

    model_config = {"populate_by_name": True}

    @property
    def is_online(self) -> bool:
        return self.online_status == "ONLINE"
