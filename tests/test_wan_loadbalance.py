"""Offline tests for the WAN multi-line load-balance (``mllb``) helpers.

Fixtures mirror a real ``devConfig.get module=mllb`` response captured from a
ReyeeOS EG (firmware EG_3.0(1)B11P410): Active/Backup, Forced-Switch, two WANs.
"""

from __future__ import annotations

import pytest

from pyruijie.wan_loadbalance import (
    WanLoadBalance,
    build_master_swap_payload,
)

# Real-shaped mllb config: wan = master, wan1 = backup.
MLLB_WAN_MASTER = {
    "mode": "master",
    "enable": "1",
    "policy": "load",
    "intf_cnt": "2",
    "wan": "1",
    "wan1": "1",
    "backup_discon": "1",
    "master_list": [
        {"band_up": "100", "band_down": "30", "ifname": "wan", "m": "1"},
        {"band_up": "30", "band_down": "30", "ifname": "wan1", "m": "0"},
    ],
    # read-only stamps the setter must NOT echo back:
    "version": "1.0.0",
    "configTime": "1759855330",
    "currentTime": "1759855330",
    "configId": "1759855330",
}


def test_parse_reads_master_and_flags() -> None:
    lb = WanLoadBalance.parse(MLLB_WAN_MASTER)
    assert lb.mode == "master"
    assert lb.policy == "load"
    assert lb.forced_switch is True
    assert lb.enable is True
    assert lb.master_ifname == "wan"
    assert [(ln.ifname, ln.is_master) for ln in lb.lines] == [("wan", True), ("wan1", False)]


def test_swap_makes_target_master_and_demotes_others() -> None:
    payload = build_master_swap_payload(MLLB_WAN_MASTER, "wan1")
    flags = {e["ifname"]: e["m"] for e in payload["master_list"]}
    assert flags == {"wan": "0", "wan1": "1"}
    # re-parsing the payload confirms the new master
    assert WanLoadBalance.parse(payload).master_ifname == "wan1"


def test_swap_strips_readonly_stamp_fields() -> None:
    payload = build_master_swap_payload(MLLB_WAN_MASTER, "wan1")
    for stamp in ("version", "configTime", "currentTime", "configId"):
        assert stamp not in payload
    # non-stamp config is preserved
    assert payload["mode"] == "master"
    assert payload["backup_discon"] == "1"


def test_swap_preserves_per_line_bandwidth() -> None:
    payload = build_master_swap_payload(MLLB_WAN_MASTER, "wan1")
    bands = {e["ifname"]: (e["band_up"], e["band_down"]) for e in payload["master_list"]}
    assert bands == {"wan": ("100", "30"), "wan1": ("30", "30")}


def test_swap_line_field_order_matches_gui() -> None:
    # GUI Save emits band_up, band_down, ifname, m — in that order.
    payload = build_master_swap_payload(MLLB_WAN_MASTER, "wan1")
    assert list(payload["master_list"][0].keys()) == ["band_up", "band_down", "ifname", "m"]


def test_swap_to_current_master_is_idempotent() -> None:
    payload = build_master_swap_payload(MLLB_WAN_MASTER, "wan")
    flags = {e["ifname"]: e["m"] for e in payload["master_list"]}
    assert flags == {"wan": "1", "wan1": "0"}


def test_swap_unknown_ifname_raises() -> None:
    with pytest.raises(ValueError, match="wan2"):
        build_master_swap_payload(MLLB_WAN_MASTER, "wan2")


def test_swap_does_not_mutate_input() -> None:
    before = {e["ifname"]: e["m"] for e in MLLB_WAN_MASTER["master_list"]}
    build_master_swap_payload(MLLB_WAN_MASTER, "wan1")
    after = {e["ifname"]: e["m"] for e in MLLB_WAN_MASTER["master_list"]}
    assert before == after == {"wan": "1", "wan1": "0"}
