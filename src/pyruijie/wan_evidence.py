"""Read-only, allowlisted WAN evidence. Configuration is not link health."""

from __future__ import annotations

import math
import time

import requests

from pyruijie.exceptions import RuijieApiError, RuijieError

WAN_READ_ERRORS = (
    RuijieError,
    requests.RequestException,
    ValueError,
    TypeError,
    KeyError,
    TimeoutError,
)


def boolean(value):
    value = str(value).strip().lower()
    if value in {"1", "true", "on", "up", "online"}:
        return True
    if value in {"0", "false", "off", "down", "offline"}:
        return False
    return None


def parse_wan_configuration(network: dict, policy: dict) -> dict:
    """Discard raw interface records (which may contain PPPoE credentials)."""
    count = network.get("wanNum")
    interfaces = network.get("wan")
    if isinstance(count, bool) or not str(count).isdigit():
        raise ValueError("Missing WAN interface count")
    count = int(count)
    if not isinstance(interfaces, list) or not 1 <= count <= 16 or len(interfaces) != count:
        raise ValueError("Incomplete WAN interface inventory")
    if any(not isinstance(row, dict) or not row.get("proto") for row in interfaces):
        raise ValueError("Incomplete WAN configuration")
    lines = policy.get("master_list") or []
    if not isinstance(lines, list) or any(not isinstance(row, dict) for row in lines):
        raise ValueError("Invalid WAN policy")
    primary = next(
        (str(row.get("ifname", "")) for row in lines if boolean(row.get("m")) is True), ""
    )
    secondary = [
        str(row.get("ifname", ""))
        for row in lines
        if row.get("ifname") and row.get("ifname") != primary
    ]
    flags = [boolean(policy.get(name)) for name in secondary]
    secondary_enabled = None
    if primary and flags:
        secondary_enabled = True if True in flags else None if None in flags else False
    return {
        "wan_count": count,
        "configured_interfaces": len(interfaces),
        "primary": primary if count > 1 else "WAN (only configured interface)",
        "policy_enabled": boolean(policy.get("enable")),
        "secondary_enabled": secondary_enabled,
    }


def read_wan_configuration(client, expected_serial: str, *, deadline_seconds=12) -> dict:
    """Require an authenticated, identity-matched gateway; never use cmd_checked.

    cmd_checked historically swallows read timeouts as write success. A failed
    read here must remain an error, never an empty/healthy configuration.
    """
    if not expected_serial or client.serial_number != expected_serial:
        raise ValueError("Gateway identity mismatch")
    if not math.isfinite(deadline_seconds) or deadline_seconds <= 0:
        raise ValueError("A finite positive WAN deadline is required")
    deadline = time.monotonic() + deadline_seconds
    sections = []
    for module in ("network", "mllb"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("WAN read deadline exceeded")
        response = client.cmd("devConfig.get", module, timeout=remaining)
        data = response.get("data")
        if (
            not isinstance(data, dict)
            or data.get("rcode") not in (None, "", "00000000")
            or data.get("code") not in (None, 0, "0")
        ):
            raise RuijieApiError("WAN configuration unavailable")
        sections.append(data)
    return parse_wan_configuration(*sections)
