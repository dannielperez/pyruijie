import time
from unittest.mock import Mock

from pyruijie.intercom_diagnostics import inspect_intercom_path


def test_allowlists_identity_scoped_evidence_and_never_exports_private_keys():
    now = int(time.time())
    data = {
        "policy_route": {
            "list": [
                {
                    "name": "sip",
                    "sipRange": "192.0.2.20-192.0.2.20",
                    "dipRange": "192.0.2.11-192.0.2.11",
                    "intf": "wgclt1",
                    "intf_switch": "true",
                }
            ]
        },
        "wireguard": {
            "clientlist": [
                {
                    "desc": "cloud",
                    "localIfname": "wgclt1",
                    "allowips": ["192.0.2.11/32"],
                    "localPrikey": "DO_NOT_EXPORT",
                }
            ]
        },
        "firewall_extern": {"sip_alg": False},
        "content_audit": [
            {
                "in_ip": "192.0.2.20",
                "out_ip": "192.0.2.11",
                "in_port": "5064",
                "out_port": "5060",
                "is_deny": "allow",
            }
        ],
        "std_syslog_get": {
            "log_list": [
                [str(now - 30), "a", "b", "5", 'port:"WAN0" action:down'],
                [str(now - 10), "a", "b", "5", "unrelated secret"],
            ]
        },
    }
    gateway = Mock()
    gateway.cmd.side_effect = lambda method, module, **kw: {"code": 0, "data": data[module]}
    report = inspect_intercom_path(gateway, "192.0.2.20", "192.0.2.11")
    assert report["routes"][0]["intf"] == "wgclt1"
    assert report["route_basis"] == "configured_only"
    assert report["wan_events"] == [{"at": now - 30, "port": "WAN0", "state": "down"}]
    assert "DO_NOT_EXPORT" not in str(report) and "unrelated secret" not in str(report)
    assert all(
        call.args[0] in ("devConfig.get", "devSta.get") for call in gateway.cmd.call_args_list
    )


def test_failed_sections_are_unknown_not_healthy():
    gateway = Mock()
    gateway.cmd.return_value = {"code": 1, "error": "not available"}
    report = inspect_intercom_path(gateway, "192.0.2.20", "192.0.2.11")
    assert len(report["errors"]) == 5
    assert "routes" not in report
