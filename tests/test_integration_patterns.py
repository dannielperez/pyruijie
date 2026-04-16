"""Integration-pattern tests — mirrors how UniqueOS consumes pyruijie.

These tests validate that the public API surface used by the platform
application remains stable.  Each test directly mimics a usage pattern
found in the UniqueOS codebase.
"""

import pytest

import pyruijie
from pyruijie import (
    DEFAULT_BASE_URL,
    APIError,
    AuthenticationError,
    ClientDevice,
    Device,
    Project,
    RuijieClient,
    RuijieError,
    format_mac,
)
from pyruijie import (
    ConnectionError as RuijieConnectionError,
)

# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------


class TestPublicExports:
    """Verify __all__ exports match what the app imports."""

    def test_default_base_url_exported(self):
        assert DEFAULT_BASE_URL == "https://cloud-us.ruijienetworks.com"

    def test_version_string(self):
        assert isinstance(pyruijie.__version__, str)
        parts = pyruijie.__version__.split(".")
        assert len(parts) >= 2

    def test_all_symbols_importable(self):
        for name in pyruijie.__all__:
            assert hasattr(pyruijie, name), f"{name!r} listed in __all__ but not importable"


# ---------------------------------------------------------------------------
# Exception hierarchy — app catches at various granularities
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """UniqueOS catches RuijieError broadly and subtypes specifically."""

    def test_auth_error_is_ruijie_error(self):
        exc = AuthenticationError("bad creds")
        assert isinstance(exc, RuijieError)

    def test_api_error_is_ruijie_error(self):
        exc = APIError(500, "server error")
        assert isinstance(exc, RuijieError)
        assert exc.code == 500
        assert exc.message == "server error"

    def test_connection_error_is_ruijie_error(self):
        exc = RuijieConnectionError("unreachable")
        assert isinstance(exc, RuijieError)

    def test_connection_error_alias_works(self):
        """App uses `from pyruijie import ConnectionError as RuijieConnectionError`."""
        from pyruijie import ConnectionError as Alias  # noqa: A004

        assert Alias is RuijieConnectionError


# ---------------------------------------------------------------------------
# Client init kwargs — matching app patterns
# ---------------------------------------------------------------------------


class TestClientInit:
    """RuijieAdapter._build_client() passes these exact kwargs."""

    def test_full_kwargs(self, mock_api):
        """Matches: RuijieClient(app_id=..., app_secret=..., base_url=..., timeout=30)"""
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok-123"},
        )
        with RuijieClient(
            app_id="test-app",
            app_secret="test-secret",
            base_url="https://cloud-us.ruijienetworks.com",
            timeout=30,
        ) as client:
            client.authenticate()
            assert client.is_authenticated

    def test_minimal_kwargs(self, mock_api):
        """Matches: RuijieClient(app_id=..., app_secret=...)"""
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok-456"},
        )
        client = RuijieClient(app_id="a", app_secret="s")
        client.authenticate()
        assert client.is_authenticated


# ---------------------------------------------------------------------------
# Context manager + authenticate + get_clients flow
# ---------------------------------------------------------------------------


class TestDiscoveryProviderFlow:
    """Mirrors RuijieDiscoveryProvider.collect() end-to-end pattern."""

    def test_context_manager_auth_get_clients(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok"},
        )
        mock_api.get("/service/api/open/v1/dev/user/current-user").respond(
            json={
                "code": 0,
                "list": [
                    {
                        "mac": "AA:BB:CC:DD:EE:01",
                        "ip": "192.168.1.50",
                        "userName": "cam-01",
                        "staOs": "Linux",
                        "connectType": "wireless",
                        "ssid": "SiteLAN",
                        "linkedDevice": "SN-AP-001",
                        "deviceName": "AP-Lobby",
                        "clientSource": "AP",
                        "manufacturer": "Hikvision",
                        "onlineTime": 1700000000000,
                    },
                    {
                        "mac": "AA:BB:CC:DD:EE:02",
                        "ip": "192.168.1.51",
                        "userName": "intercom-01",
                        "connectType": "wired",
                        "linkedDevice": "SN-SW-001",
                        "deviceName": "Switch-Floor1",
                        "clientSource": "Switch",
                    },
                ],
                "totalCount": 2,
            },
        )

        with RuijieClient(app_id="test", app_secret="secret") as client:
            client.authenticate()
            clients = client.get_clients("proj-1")

        # -- property accesses the app performs for each client --
        wireless = clients[0]
        assert wireless.mac == "AA:BB:CC:DD:EE:01"
        assert wireless.ip == "192.168.1.50"
        assert wireless.hostname == "cam-01"
        assert wireless.os_type == "Linux"
        assert wireless.is_online is True
        assert wireless.connect_type == "wireless"
        assert wireless.ssid == "SiteLAN"
        assert wireless.ap_name == "AP-Lobby"
        assert wireless.ap_mac == "SN-AP-001"
        assert wireless.switch_name is None
        assert wireless.switch_port is None
        assert wireless.vlan_id is None

        wired = clients[1]
        assert wired.switch_name == "Switch-Floor1"
        assert wired.ap_name is None
        assert wired.ap_mac is None

    def test_ruijie_error_catch_all(self, mock_api):
        """App catches (RuijieError, OSError, TimeoutError)."""
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok"},
        )
        mock_api.get("/service/api/open/v1/dev/user/current-user").respond(
            json={"code": 500, "msg": "Internal error"},
        )
        with RuijieClient(app_id="a", app_secret="s") as client:
            client.authenticate()
            with pytest.raises(RuijieError):
                client.get_clients("proj-1")


# ---------------------------------------------------------------------------
# model_dump(by_alias=True) contract — raw_payload serialization
# ---------------------------------------------------------------------------


class TestModelDumpByAlias:
    """The app serializes ClientDevice via model_dump(by_alias=True).

    This is the raw_payload stored in the database — alias names are a
    public contract and MUST NOT change.
    """

    def test_client_device_alias_keys(self):
        c = ClientDevice.model_validate(
            {
                "mac": "AA:BB:CC:DD:EE:01",
                "ip": "10.0.0.1",
                "userName": "laptop-01",
                "staOs": "Windows",
                "connectType": "wireless",
                "ssid": "Corp",
                "linkedDevice": "SN-AP-001",
                "deviceName": "AP-Main",
                "clientSource": "AP",
                "manufacturer": "Dell",
                "manufacturerId": "m-001",
                "staCategory": "PC",
                "staCategoryName": "Computer",
                "staLabel": "office",
                "staLabelName": "Office",
                "staModel": "XPS 15",
                "onlineTime": 1700000000000,
                "groupName": "Site A",
                "flowUp": 1024,
                "flowDown": 2048,
                "band": "5G",
                "rssi": -50,
                "channel": 36,
            }
        )
        dumped = c.model_dump(by_alias=True)

        # All alias keys the app relies on
        expected_alias_keys = {
            "mac",
            "ip",
            "userName",
            "connectType",
            "ssid",
            "linkedDevice",
            "deviceName",
            "clientSource",
            "manufacturer",
            "manufacturerId",
            "staCategory",
            "staCategoryName",
            "staLabel",
            "staLabelName",
            "staOs",
            "staModel",
            "onlineTime",
            "groupName",
        }
        assert expected_alias_keys.issubset(dumped.keys())

        # WiFi/traffic alias keys (added in post-0.2.0)
        wifi_alias_keys = {"flowUp", "flowDown", "band", "rssi", "channel"}
        assert wifi_alias_keys.issubset(dumped.keys())

    def test_device_alias_keys(self):
        d = Device.model_validate(
            {
                "serialNumber": "SN001",
                "productType": "AP",
                "productClass": "RG-RAP2260(G)",
                "aliasName": "Office AP",
                "onlineStatus": "ONLINE",
                "localIp": "192.168.1.10",
                "cpeIp": "1.2.3.4",
                "mac": "AA:BB:CC:DD:EE:FF",
                "softwareVersion": "11.1(6)B3",
            }
        )
        dumped = d.model_dump(by_alias=True)

        expected_alias_keys = {
            "serialNumber",
            "productType",
            "productClass",
            "aliasName",
            "onlineStatus",
            "localIp",
            "cpeIp",
            "mac",
            "softwareVersion",
        }
        assert expected_alias_keys.issubset(dumped.keys())

    def test_project_alias_keys(self):
        p = Project.model_validate({"name": "Site A", "groupId": "g-123"})
        dumped = p.model_dump(by_alias=True)
        assert "groupId" in dumped
        assert "name" in dumped


# ---------------------------------------------------------------------------
# Device import flow — get_projects + get_devices
# ---------------------------------------------------------------------------


class TestDeviceImportFlow:
    """Mirrors discover_ruijie_devices() in ruijie_import.py."""

    def test_project_fields(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={
                "code": 0,
                "groups": {
                    "type": "BUILDING",
                    "name": "HQ",
                    "groupId": 12345,  # numeric — tests coercion
                    "subGroups": [],
                },
            },
        )
        projects = client.get_projects()
        p = projects[0]
        assert isinstance(p.group_id, str)
        assert p.group_id == "12345"
        assert p.name == "HQ"

    def test_device_fields_used_by_import(self, authed_client):
        """All Device fields that ruijie_import.py accesses."""
        client, mock_api = authed_client
        mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [
                    {
                        "serialNumber": "SN001",
                        "productType": "EGW",
                        "productClass": "RG-EG3230",
                        "aliasName": "Main Gateway",
                        "onlineStatus": "ONLINE",
                        "localIp": "10.0.0.1",
                        "cpeIp": "203.0.113.5",
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "softwareVersion": "11.1(6)B3",
                    }
                ],
            },
        )
        devices = client.get_devices("proj-1")
        dev = devices[0]

        # Fields used by ruijie_import.py
        assert dev.name == "Main Gateway"
        assert dev.serial_number == "SN001"
        assert dev.local_ip == "10.0.0.1"
        assert dev.product_class == "RG-EG3230"
        assert dev.product_type == "EGW"
        assert dev.firmware_version == "11.1(6)B3"
        assert dev.mac == "AA:BB:CC:DD:EE:FF"
        assert dev.is_online is True
        assert dev.egress_ip == "203.0.113.5"

        # Fields used by RuijieAdapter.get_status()
        assert dev.online_status == "ONLINE"


# ---------------------------------------------------------------------------
# Adapter status flow — granular exception handling
# ---------------------------------------------------------------------------


class TestAdapterExceptionHandling:
    """Mirrors RuijieAdapter.test_connection() and get_status() error paths."""

    def test_auth_failure_is_specific(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 1, "msg": "invalid app credentials"},
        )
        client = RuijieClient(app_id="bad", app_secret="bad")
        with pytest.raises(AuthenticationError):
            client.authenticate()

    def test_api_error_has_code_and_message(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={"code": 403, "msg": "Forbidden"},
        )
        with pytest.raises(APIError) as exc_info:
            client.get_projects()
        assert exc_info.value.code == 403
        assert exc_info.value.message == "Forbidden"

    def test_http_404_gives_helpful_message(self, authed_client):
        """404 errors should mention endpoint unavailability."""
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(status_code=404)
        with pytest.raises(APIError) as exc_info:
            client.get_projects()
        assert "not be available" in str(exc_info.value)


# ---------------------------------------------------------------------------
# format_mac compatibility
# ---------------------------------------------------------------------------


class TestFormatMacIntegration:
    """UniqueOS normalize_mac() duplicates format_mac(); verify equivalence."""

    def test_ruijie_dot_format(self):
        assert format_mac("585b.6947.b194") == "58:5B:69:47:B1:94"

    def test_bare_hex(self):
        assert format_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    def test_none_safe(self):
        assert format_mac(None) == ""

    def test_empty_safe(self):
        assert format_mac("") == ""
