"""pyruijie — Python client library for Ruijie/Reyee Cloud-managed networking."""

from pyruijie.client import DEFAULT_BASE_URL, RuijieClient
from pyruijie.exceptions import APIError, AuthenticationError, ConnectionError, RuijieError
from pyruijie.models import (
    ClientDevice,
    Device,
    GatewayPort,
    Project,
    SwitchPort,
    parse_vlan_list,
)
from pyruijie.utils import format_mac

__version__ = "0.2.0"

__all__ = [
    "DEFAULT_BASE_URL",
    "RuijieClient",
    "APIError",
    "AuthenticationError",
    "ConnectionError",
    "RuijieError",
    "ClientDevice",
    "Device",
    "GatewayPort",
    "Project",
    "SwitchPort",
    "format_mac",
    "parse_vlan_list",
]
