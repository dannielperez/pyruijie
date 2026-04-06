"""Typed models for Ruijie Cloud API responses."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Project(BaseModel):
    """A Ruijie Cloud project (building-level network group)."""

    name: str
    group_id: str = Field(alias="groupId")

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
