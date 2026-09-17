"""Inventory reconciliation must distinguish checked-empty from failed reads."""

from unittest.mock import Mock

import pytest

from pyruijie.exceptions import RuijieWireGuardError
from pyruijie.wireguard import WireGuardManager


@pytest.mark.parametrize("kind,key", [("server", "serverlist"), ("client", "clientlist")])
@pytest.mark.parametrize("payload", [None, {}, {"data": {}}, {"data": None}, {"error": "bad"}])
def test_missing_section_is_not_empty(kind, key, payload):
    manager = WireGuardManager(Mock(cmd=Mock(return_value=payload)))
    with pytest.raises(RuijieWireGuardError):
        getattr(manager, f"list_{kind}_policies")()


@pytest.mark.parametrize("kind,key", [("server", "serverlist"), ("client", "clientlist")])
def test_explicit_empty_section_is_success(kind, key):
    manager = WireGuardManager(Mock(cmd=Mock(return_value={"data": {key: []}})))
    assert getattr(manager, f"list_{kind}_policies")() == []


@pytest.mark.parametrize("kind,key", [("server", "serverlist"), ("client", "clientlist")])
@pytest.mark.parametrize(
    "entries", [None, {}, [None], [{}], [{"uuid": ""}], [{"uuid": "a"}, {"uuid": "a"}]]
)
def test_malformed_lists_and_identities_fail_closed(kind, key, entries):
    manager = WireGuardManager(Mock(cmd=Mock(return_value={"data": {key: entries}})))
    with pytest.raises(RuijieWireGuardError):
        getattr(manager, f"list_{kind}_policies")()


def test_missing_peer_section_does_not_remove_known_peers():
    manager = WireGuardManager(
        Mock(cmd=Mock(return_value={"data": {"serverlist": [{"uuid": "a"}]}}))
    )
    with pytest.raises(RuijieWireGuardError):
        manager.list_server_policies()


def test_gateway_error_with_empty_list_is_not_success():
    manager = WireGuardManager(
        Mock(
            cmd=Mock(
                return_value={
                    "data": {"clientlist": [], "rcode": "failed", "message": "secret-sentinel"}
                }
            )
        )
    )
    with pytest.raises(RuijieWireGuardError) as caught:
        manager.list_client_policies()
    assert "secret-sentinel" not in str(caught.value)
