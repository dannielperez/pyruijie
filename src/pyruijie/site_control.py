"""Observed site policy/diagnostic contracts; no guessed port-to-DPI mapping.

Cloud writes use the same app-policy endpoint as the web console. Local reads
verify delivery, never replace cloud policy ownership. Callers persist the plan
before invoking apply, and must not retry an uncertain write automatically.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import time


class SiteControlError(ValueError):
    """Invalid evidence, concurrent drift, or unsupported policy."""


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def canonical_policy(row):
    return {k: v for k, v in row.items() if k not in {"updateTime", "updateTimeMills"}}


def policy_revision(rows):
    return fingerprint(sorted((canonical_policy(r) for r in rows), key=lambda r: r["id"]))


def make_plan(rows, policy_id, remove):
    matches = [r for r in rows if r.get("id") == policy_id]
    if len(matches) != 1:
        raise SiteControlError("Policy is missing or ambiguous; inspect again.")
    before = copy.deepcopy(matches[0])
    if before.get("policyType") != "BLOCK" or before.get("enable") is not True:
        raise SiteControlError("Only enabled application block policies are supported.")
    if before.get("userGroupList") or before.get("customGroup") or not before.get("ipSlots"):
        raise SiteControlError("Grouped or implicit policy scopes require manual review.")
    remove = set(remove)
    if not remove or not remove.issubset(before["appList"]):
        raise SiteControlError("Select existing blocked applications.")
    after = canonical_policy(before)
    after["appList"] = [a for a in before["appList"] if a not in remove]
    if not after["appList"]:
        raise SiteControlError("Removing every application is not supported.")
    return {
        "revision": policy_revision(rows),
        "before": before,
        "after": after,
        "removed": sorted(remove),
        "added": [],
    }


def matching_scope(policy, address):
    """Tri-state: unknown group scope must never be presented as a non-match."""
    ip = ipaddress.ip_address(address)
    if policy.get("userGroupList") or policy.get("customGroup") or not policy.get("ipSlots"):
        return "unknown"
    unknown = False
    for slot in policy["ipSlots"]:
        try:
            if "-" in slot:
                start, end = map(ipaddress.ip_address, slot.split("-", 1))
                if start <= ip <= end:
                    return "matches"
            elif ip in ipaddress.ip_network(slot, strict=False):
                return "matches"
        except (ValueError, TypeError):
            unknown = True
    return "unknown" if unknown else "outside"


def compare_traffic(before, after, *, after_ms=0, now_ms=None, max_age_ms=900000):
    """Compare rates, not byte consumption; unknown units remain explicitly raw."""
    result = {"status": "unavailable", "percent": None}
    if not before or not after or before.get("mac") != after.get("mac"):
        return result
    timestamps = [before.get("observed_ms"), after.get("observed_ms")]
    if any(not isinstance(t, int) or isinstance(t, bool) or t <= 0 for t in timestamps):
        return result
    if timestamps[1] <= max(timestamps[0], after_ms):
        return {**result, "status": "cached"}
    if now_ms is not None and (
        timestamps[1] > now_ms + 60000 or now_ms - timestamps[1] > max_age_ms
    ):
        return {**result, "status": "stale"}
    values = [r.get(k) for r in (before, after) for k in ("upload", "download")]
    if any(not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0 for v in values):
        return result
    old, new = sum(values[:2]), sum(values[2:])
    return {
        "status": "increased" if new > old else "decreased" if new < old else "unchanged",
        "percent": round((new / old - 1) * 100, 1) if old else None,
        "before_total": old,
        "after_total": new,
    }


def traffic_record(client):
    mac = re.sub(r"[^0-9a-f]", "", client.mac.lower())
    return {
        "mac": mac,
        "ip": client.ip,
        "name": client.hostname,
        "upload": client.up_rate,
        "download": client.down_rate,
        "observed_ms": client.update_time,
        "units": "vendor rate units (unverified)",
        "switch": client.device_name,
        "port": client.linked_port,
    }


class SiteControl:
    def __init__(self, web, gateway, serial):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", serial):
            raise SiteControlError("A valid gateway serial is required.")
        self.web, self.gateway, self.serial = web, gateway, serial

    def policies(self):
        api = f"/smartscene/app/control/list/{self.serial}?policyType=BLOCK,WEBSITE"
        result = self.web.webproxy(api)
        rows = result.get("list")
        if result.get("code") != 0 or not isinstance(rows, list) or len(rows) > 200:
            raise SiteControlError("Cloud policy read failed.")
        if len(json.dumps(rows)) > 512000:
            raise SiteControlError("Cloud evidence exceeds the supported capture size.")
        ids = []
        for row in rows:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("id"), int)
                or not isinstance(row.get("appList"), list)
            ):
                raise SiteControlError("Malformed cloud policy.")
            ids.append(row["id"])
        if len(set(ids)) != len(ids):
            raise SiteControlError("Duplicate policy identifiers.")
        return rows

    def gateway_read(self, module):
        if self.gateway.serial_number != self.serial:
            raise SiteControlError("Gateway serial does not match inventory.")
        methods = {
            "ca_app_policy": "devConfig.get",
            "access_ctrl": "devConfig.get",
            "arp": "devSta.get",
            "policy_route": "devConfig.get",
            "static_route": "devConfig.get",
        }
        result = self.gateway.cmd(methods[module], module, data={})
        if result.get("code") != 0 or not isinstance(result.get("data"), dict):
            raise SiteControlError("Gateway read failed.")
        if len(json.dumps(result["data"])) > 512000:
            raise SiteControlError("Gateway evidence exceeds the supported capture size.")
        return result["data"]

    @staticmethod
    def delivered(cloud_row, native_rows):
        rows = [r for r in native_rows if r.get("policy") == cloud_row.get("policy")]
        if len(rows) != 1:
            return False
        native = rows[0]
        pairs = {
            "appList": "applist",
            "ipSlots": "ip_slots",
            "userGroupList": "user_group_list",
            "timeMode": "time_mode",
            "trGroup": "tr_group",
        }
        return all(cloud_row.get(k) == native.get(v) for k, v in pairs.items()) and (
            native.get("enable") == ("1" if cloud_row.get("enable") else "0")
        )

    def apply(self, plan, *, before_write=None, on_verifying=None):
        rows = self.policies()
        if policy_revision(rows) != plan["revision"]:
            raise SiteControlError("Cloud policy changed since preview; inspect again.")
        before = self.gateway_read("ca_app_policy")["list"]
        if not self.delivered(plan["before"], before):
            raise SiteControlError("Cloud and gateway differ; reconcile before changing policy.")
        # Defense in depth: only appList may change, even if the caller is buggy.
        old, new = canonical_policy(plan["before"]), canonical_policy(plan["after"])
        if {k: v for k, v in old.items() if k != "appList"} != {
            k: v for k, v in new.items() if k != "appList"
        }:
            raise SiteControlError("Only application-list changes are supported.")
        api = f"/smartscene/app/control/policy/{self.serial}"
        self.web.login()
        envelope = {
            "api": api,
            "method": "POST",
            "module": "default",
            "params": new,
            "querys": {"lang": "en"},
            "authParams": {"api": api, "method": "POST"},
        }
        if before_write:
            before_write()
        response = self.web.session.post(
            f"{self.web.base_url}/webproxy/common/api?{api}",
            json=envelope,
            timeout=self.web.timeout,
        )
        response.raise_for_status()
        if response.json().get("code") != 0:
            raise SiteControlError("Cloud did not accept the change; inspect before retrying.")
        applied_ms = int(time.time() * 1000)
        if on_verifying:
            on_verifying()
        after = self.policies()
        expected = [new if r["id"] == new["id"] else r for r in rows]
        cloud_ok = policy_revision(after) == policy_revision(expected)
        local = self.gateway_read("ca_app_policy")["list"]
        for _ in range(2):
            if self.delivered(new, local):
                break
            time.sleep(2)
            local = self.gateway_read("ca_app_policy")["list"]

        def untouched(rs):
            return [r for r in rs if r.get("policy") != new.get("policy")]

        def preserved_target():
            original = next(r for r in before if r.get("policy") == new["policy"])
            actual = next((r for r in local if r.get("policy") == new["policy"]), {})
            expected = {**original, "applist": new["appList"]}

            # Cloud normalizes only the empty time-slot container on delivery.
            def normalize(row):
                row = dict(row)
                if row.get("tr_slots") in ([], {}, "{}"):
                    row["tr_slots"] = []
                return row

            return normalize(actual) == normalize(expected)

        gateway_ok = (
            self.delivered(new, local)
            and untouched(before) == untouched(local)
            and preserved_target()
        )
        return {
            "applied_ms": applied_ms,
            "cloud_verified": cloud_ok,
            "gateway_verified": gateway_ok,
            "cloud": after,
            "gateway": local,
            "revision": policy_revision(after),
        }
