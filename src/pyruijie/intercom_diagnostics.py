"""Read-only, secret-free gateway evidence for one endpoint/registrar pair."""

import ipaddress
import re
import time

from .exceptions import RuijieError


def _contains(value, address):
    try:
        if "-" in value:
            low, high = value.split("-", 1)
            return ipaddress.ip_address(low) <= address <= ipaddress.ip_address(high)
        return address in ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return False


def inspect_intercom_path(gateway, source, destination, *, deadline_seconds=35):
    source_ip = ipaddress.ip_address(source)
    destination_ip = ipaddress.ip_address(destination)
    deadline = time.monotonic() + deadline_seconds
    result = {
        "observed_at": time.time(),
        "source": str(source_ip),
        "destination": str(destination_ip),
        "route_basis": "configured_only",
        "errors": [],
    }

    def read(method, module, data):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("diagnostic deadline")
        value = gateway.cmd(method, module, data=data, timeout=min(5, remaining))
        if value.get("code") not in (None, 0) or value.get("error"):
            raise ValueError("diagnostic unavailable")
        payload = value.get("data", {})
        if isinstance(payload, dict) and payload.get("rcode") not in (None, "", "00000000"):
            raise ValueError("diagnostic unavailable")
        return payload

    for section in ("routes", "tunnels", "firewall", "flows", "wan_events"):
        try:
            if section == "routes":
                rows = read("devConfig.get", "policy_route", {}).get("list", [])
                result[section] = [
                    {
                        k: str(row.get(k, ""))[:128]
                        for k in (
                            "name",
                            "intf",
                            "enable",
                            "intf_switch",
                            "proto",
                            "sipRange",
                            "dipRange",
                        )
                    }
                    for row in rows[:500]
                    if _contains(row.get("sipRange", ""), source_ip)
                    and _contains(row.get("dipRange", ""), destination_ip)
                ]
            elif section == "tunnels":
                rows = read("devConfig.get", "wireguard", {}).get("clientlist", [])
                result[section] = [
                    {
                        **{
                            k: str(row.get(k, ""))[:128]
                            for k in ("desc", "localIfname", "enable", "metric")
                        },
                        "allowips": [str(v)[:80] for v in row.get("allowips", [])[:64]]
                        if isinstance(row.get("allowips"), list)
                        else [],
                    }
                    for row in rows[:30]
                ]
            elif section == "firewall":
                value = read("devConfig.get", "firewall_extern", {})
                result[section] = {
                    k: True
                    if value.get(k) in (True, 1, "1")
                    else False
                    if value.get(k) in (False, 0, "0")
                    else None
                    for k in ("sip_alg", "ipProtCheck")
                }
            elif section == "flows":
                rows = read(
                    "devSta.get",
                    "content_audit",
                    {"func": "ca_get_flow_info", "ip": str(source_ip)},
                )
                result[section] = [
                    {
                        k: str(row.get(k, "")).strip()[:128]
                        for k in ("in_ip", "out_ip", "in_port", "out_port", "is_deny")
                    }
                    for row in rows[:500]
                    if str(row.get("in_ip", "")).strip() == str(source_ip)
                    and str(row.get("out_ip", "")).strip() == str(destination_ip)
                ]
            else:
                rows = read(
                    "devSta.get", "std_syslog_get", {"user": "web", "option": "log_detail"}
                ).get("log_list", [])
                events = []
                for row in rows[-2000:]:
                    if not isinstance(row, list) or len(row) < 5:
                        continue
                    match = re.fullmatch(r'port:"(WAN\d+)" action:(up|down)', str(row[-1]))
                    if (
                        match
                        and result["observed_at"] - 86400
                        <= int(row[0])
                        <= result["observed_at"] + 30
                    ):
                        events.append({"at": int(row[0]), "port": match[1], "state": match[2]})
                result[section] = events[-100:]
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            TimeoutError,
            OSError,
            RuijieError,
        ):
            result["errors"].append(section)
    return result
