"""Policy mutation guards and cached traffic semantics, with all I/O mocked."""

from unittest.mock import Mock

import pytest

from pyruijie.models import ClientDevice
from pyruijie.site_control import (
    SiteControl,
    SiteControlError,
    compare_traffic,
    make_plan,
    matching_scope,
    traffic_record,
)


def policy():
    return {
        "id": 14839,
        "policy": "policy_2",
        "policyName": "Block_intelli",
        "enable": True,
        "policyType": "BLOCK",
        "ipSlots": ["10.40.5.1-10.40.5.254"],
        "appList": ["DoH", "IBM-MQSERIES2", "HTTP-ALT", "Game"],
        "timeMode": "calendar",
        "trGroup": "all",
        "userGroupList": [],
        "updateTime": 123,
    }


def native(p):
    return {
        "policy": p["policy"],
        "enable": "1",
        "applist": p["appList"],
        "ip_slots": p["ipSlots"],
        "user_group_list": [],
        "time_mode": "calendar",
        "tr_group": "all",
    }


def control(before, after):
    web, gw = Mock(), Mock(serial_number="SN1")
    web.timeout = 5
    web.base_url = "https://example.test"
    web.webproxy.side_effect = [{"code": 0, "list": [before]}, {"code": 0, "list": [after]}]
    web.session.post.return_value.json.return_value = {"code": 0}
    gw.cmd.side_effect = [
        {"code": 0, "data": {"list": [native(before)]}},
        {"code": 0, "data": {"list": [native(after)]}},
    ]
    return SiteControl(web, gw, "SN1")


def test_exact_mutation_and_native_readback():
    before = policy()
    plan = make_plan([before], before["id"], ["DoH"])
    ctl = control(before, plan["after"])
    result = ctl.apply(plan)
    assert result["cloud_verified"] and result["gateway_verified"]
    payload = ctl.web.session.post.call_args.kwargs["json"]["params"]
    assert payload["ipSlots"] == before["ipSlots"]
    assert payload["appList"] == ["IBM-MQSERIES2", "HTTP-ALT", "Game"]
    assert before["appList"][0] == "DoH"
    assert "updateTime" not in payload


def test_drift_prevents_any_write():
    before = policy()
    plan = make_plan([before], before["id"], ["DoH"])
    changed = {**before, "ipSlots": ["10.0.0.0/8"]}
    ctl = control(changed, plan["after"])
    with pytest.raises(SiteControlError, match="changed since preview"):
        ctl.apply(plan)
    ctl.web.session.post.assert_not_called()


def test_identity_mismatch_prevents_write():
    before = policy()
    plan = make_plan([before], before["id"], ["DoH"])
    ctl = control(before, plan["after"])
    ctl.gateway.serial_number = "OTHER"
    with pytest.raises(SiteControlError, match="serial"):
        ctl.apply(plan)
    ctl.web.session.post.assert_not_called()


def test_tampered_plan_cannot_change_scope():
    before = policy()
    plan = make_plan([before], before["id"], ["DoH"])
    plan["after"]["ipSlots"] = ["0.0.0.0/0"]
    ctl = control(before, plan["after"])
    with pytest.raises(SiteControlError, match="Only application-list"):
        ctl.apply(plan)
    ctl.web.session.post.assert_not_called()


def test_readback_mismatch_is_not_success(monkeypatch):
    monkeypatch.setattr("pyruijie.site_control.time.sleep", lambda _: None)
    before = policy()
    plan = make_plan([before], before["id"], ["DoH"])
    ctl = control(before, plan["after"])
    ctl.gateway.cmd.side_effect = None
    ctl.gateway.cmd.return_value = {"code": 0, "data": {"list": [native(before)]}}
    result = ctl.apply(plan)
    assert result["cloud_verified"] and not result["gateway_verified"]
    assert ctl.web.session.post.call_count == 1


def test_snapshot_disagreement_prevents_write():
    before = policy()
    plan = make_plan([before], before["id"], ["DoH"])
    ctl = control(before, plan["after"])
    ctl.gateway.cmd.side_effect = None
    ctl.gateway.cmd.return_value = {"code": 0, "data": {"list": []}}
    with pytest.raises(SiteControlError, match="differ"):
        ctl.apply(plan)
    ctl.web.session.post.assert_not_called()


def test_no_implicit_allow_all():
    p = policy()
    with pytest.raises(SiteControlError, match="every application"):
        make_plan([p], p["id"], p["appList"])
    with pytest.raises(SiteControlError, match="existing"):
        make_plan([p], p["id"], ["MQTT"])


@pytest.mark.parametrize(
    "observed, threshold, status",
    [(100, 0, "cached"), (99, 0, "cached"), (200, 200, "cached"), (201, 200, "increased")],
)
def test_traffic_uses_source_timestamp(observed, threshold, status):
    before = {"mac": "a", "upload": 2, "download": 3, "observed_ms": 100}
    after = {"mac": "a", "upload": 5, "download": 5, "observed_ms": observed}
    assert compare_traffic(before, after, after_ms=threshold)["status"] == status


def test_missing_stale_zero_and_other_client():
    before = {"mac": "a", "upload": 0, "download": 0, "observed_ms": 100}
    after = {**before, "observed_ms": 200, "upload": 5}
    assert compare_traffic(before, after)["percent"] is None
    assert compare_traffic(before, {**after, "mac": "b"})["status"] == "unavailable"
    assert compare_traffic(before, {**after, "download": None})["status"] == "unavailable"
    assert compare_traffic(before, after, now_ms=2000000)["status"] == "stale"


def test_scope_and_raw_rate_fields():
    assert matching_scope(policy(), "10.40.5.2") == "matches"
    assert matching_scope(policy(), "10.40.20.2") == "outside"
    assert matching_scope({**policy(), "customGroup": "unknown"}, "10.40.5.2") == "unknown"
    row = traffic_record(
        ClientDevice(
            mac="e051.d81c.6f2a", upRate=9500, downRate=8020, updateTime=1000, linkedPort="port 1"
        )
    )
    assert row["mac"] == "e051d81c6f2a"
    assert row["upload"] == 9500 and row["observed_ms"] == 1000


def test_revocation_callback_precedes_write():
    before = policy()
    plan = make_plan([before], before["id"], ["DoH"])
    ctl = control(before, plan["after"])
    guard = Mock(side_effect=PermissionError)
    with pytest.raises(PermissionError):
        ctl.apply(plan, before_write=guard)
    ctl.web.session.post.assert_not_called()


def test_group_scope_requires_manual_review():
    p = {**policy(), "customGroup": "dynamic"}
    with pytest.raises(SiteControlError, match="manual review"):
        make_plan([p], p["id"], ["DoH"])


def test_changed_native_effective_state_is_not_verified():
    before = policy()
    plan = make_plan([before], before["id"], ["DoH"])
    ctl = control(before, plan["after"])
    ctl.gateway.cmd.side_effect = [
        {"code": 0, "data": {"list": [{**native(before), "app_available": "1"}]}},
        {"code": 0, "data": {"list": [{**native(plan["after"]), "app_available": "0"}]}},
    ]
    assert not ctl.apply(plan)["gateway_verified"]
