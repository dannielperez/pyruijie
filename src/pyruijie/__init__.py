"""pyruijie — Python client library for Ruijie/Reyee Cloud and Gateway management."""

from pyruijie.client import DEFAULT_BASE_URL, RuijieClient
from pyruijie.exceptions import (
    APIError,
    AuthenticationError,
    ConnectionError,
    RuijieApiError,
    RuijieAuthError,
    RuijieError,
    RuijieWireGuardConflictError,
    RuijieWireGuardError,
    RuijieWireGuardValidationError,
)
from pyruijie.gateway import GatewayClient
from pyruijie.models import (
    ClientDevice,
    Device,
    GatewayPort,
    Project,
    SwitchPort,
    WireGuardClientPolicy,
    WireGuardConfigExport,
    WireGuardPeer,
    WireGuardServerPolicy,
    parse_vlan_list,
)
from pyruijie.utils import format_mac
from pyruijie.wireguard import WireGuardManager

__version__ = "0.3.0"

__all__ = [
    # Cloud API
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
    # Gateway (LuCI JSON-RPC)
    "GatewayClient",
    "RuijieAuthError",
    "RuijieApiError",
    "RuijieWireGuardError",
    "RuijieWireGuardValidationError",
    "RuijieWireGuardConflictError",
    "WireGuardPeer",
    "WireGuardServerPolicy",
    "WireGuardClientPolicy",
    "WireGuardConfigExport",
    "WireGuardManager",
]
