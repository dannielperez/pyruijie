"""Tests for RuijieClient."""

import httpx
import pytest

from pyruijie import RuijieClient
from pyruijie.client import _sanitize_url
from pyruijie.exceptions import APIError, AuthenticationError
from pyruijie.exceptions import ConnectionError as RuijieConnectionError

BASE_URL = "https://cloud-us.ruijienetworks.com"


# -- authentication tests ------------------------------------------------------


class TestAuthenticate:
    def test_success(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok-123"}
        )
        client = RuijieClient(app_id="a", app_secret="s")
        token = client.authenticate()

        assert token == "tok-123"
        assert client.is_authenticated

    def test_bad_credentials(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 1, "msg": "invalid credentials"}
        )
        client = RuijieClient(app_id="a", app_secret="bad")

        with pytest.raises(AuthenticationError, match="invalid credentials"):
            client.authenticate()

        assert not client.is_authenticated

    def test_http_error(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(status_code=500)
        client = RuijieClient(app_id="a", app_secret="s")

        with pytest.raises(AuthenticationError, match="500"):
            client.authenticate()

    def test_missing_api_token(self, mock_api, monkeypatch):
        monkeypatch.delenv("RUIJIE_API_TOKEN", raising=False)
        client = RuijieClient(app_id="a", app_secret="s")

        with pytest.raises(AuthenticationError, match="API token"):
            client.authenticate()

    def test_api_token_argument(self, mock_api, monkeypatch):
        monkeypatch.delenv("RUIJIE_API_TOKEN", raising=False)
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok-xyz"}
        )
        client = RuijieClient(app_id="a", app_secret="s", api_token="explicit-token")
        assert client.authenticate() == "tok-xyz"

    def test_auto_auth_on_first_request(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "auto-tok"}
        )
        mock_api.get("/service/api/group/single/tree").respond(json={"code": 0, "groups": {}})
        client = RuijieClient(app_id="a", app_secret="s")

        assert not client.is_authenticated
        client.get_projects()
        assert client.is_authenticated


# -- get_projects tests --------------------------------------------------------


class TestGetProjects:
    def test_empty(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(json={"code": 0, "groups": {}})
        projects = client.get_projects()
        assert projects == []

    def test_nested_buildings(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={
                "code": 0,
                "groups": {
                    "type": "COMPANY",
                    "name": "Root",
                    "groupId": "root-1",
                    "subGroups": [
                        {
                            "type": "BUILDING",
                            "name": "Site A",
                            "groupId": "site-a",
                            "subGroups": [],
                        },
                        {
                            "type": "BUILDING",
                            "name": "Site B",
                            "groupId": "site-b",
                            "subGroups": [],
                        },
                    ],
                },
            }
        )
        projects = client.get_projects()
        assert len(projects) == 2
        assert projects[0].name == "Site A"
        assert projects[0].group_id == "site-a"
        assert projects[1].name == "Site B"

    def test_api_error(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={"code": 500, "msg": "Internal error"}
        )
        with pytest.raises(APIError, match="Internal error"):
            client.get_projects()


# -- get_devices tests ---------------------------------------------------------


class TestGetDevices:
    def test_single_page(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [
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
                ],
            }
        )
        devices = client.get_devices("proj-1")
        assert len(devices) == 1

        dev = devices[0]
        assert dev.serial_number == "SN001"
        assert dev.product_type == "AP"
        assert dev.name == "Office AP"
        assert dev.is_online is True
        assert dev.local_ip == "192.168.1.10"
        assert dev.firmware_version == "11.1(6)B3"

    def test_pagination(self, authed_client):
        client, mock_api = authed_client
        call_count = 0

        def device_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(
                    200,
                    json={
                        "code": 0,
                        "deviceList": [
                            {"serialNumber": f"SN{i:03d}", "productType": "Switch"}
                            for i in range(100)
                        ],
                    },
                )
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "deviceList": [{"serialNumber": "SN100", "productType": "AP"}],
                },
            )

        mock_api.get("/service/api/maint/devices").mock(side_effect=device_handler)
        devices = client.get_devices("proj-1", per_page=100)
        assert len(devices) == 101
        assert call_count == 2

    def test_empty_project(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/maint/devices").respond(json={"code": 0, "deviceList": []})
        devices = client.get_devices("proj-empty")
        assert devices == []

    def test_read_timeout_is_normalized_at_sdk_boundary(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/maint/devices").mock(
            side_effect=httpx.ReadTimeout("vendor stalled"),
        )

        with pytest.raises(RuijieConnectionError, match="vendor stalled"):
            client.get_devices("proj-timeout")


class TestGetFleetDevices:
    @staticmethod
    def _mock_single_project_tree(mock_api):
        return mock_api.get("/service/api/group/single/tree").respond(
            json={
                "code": 0,
                "groups": {
                    "type": "COMPANY",
                    "name": "Root",
                    "groupId": "root-1",
                    "subGroups": [
                        {
                            "type": "BUILDING",
                            "name": "Site One",
                            "groupId": "p1",
                            "subGroups": [],
                        },
                    ],
                },
            },
        )

    def test_fetches_root_group_once_and_resolves_building_ancestors(
        self,
        authed_client,
    ):
        client, mock_api = authed_client
        tree_route = mock_api.get("/service/api/group/single/tree").respond(
            json={
                "code": 0,
                "groups": {
                    "type": "COMPANY",
                    "name": "Root",
                    "groupId": "root-1",
                    "subGroups": [
                        {
                            "type": "BUILDING",
                            "name": "Site One",
                            "groupId": "p1",
                            "subGroups": [
                                {
                                    "type": "NETWORK",
                                    "name": "Floor One",
                                    "groupId": "n1",
                                    "subGroups": [],
                                },
                            ],
                        },
                        {
                            "type": "BUILDING",
                            "name": "Site Two",
                            "groupId": "p2",
                            "subGroups": [],
                        },
                    ],
                },
            },
        )
        device_route = mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [
                    {
                        "serialNumber": "SN-ONE",
                        "onlineStatus": "ON",
                        "groupId": "n1",
                        "groupName": "Floor One",
                    },
                    {
                        "serialNumber": "SN-TWO",
                        "onlineStatus": "OFF",
                        "groupId": "p2",
                        "groupName": "Site Two",
                    },
                ],
                "totalCount": 2,
            },
        )

        devices = client.get_fleet_devices()

        assert tree_route.call_count == 1
        assert device_route.call_count == 1
        request_params = device_route.calls[0].request.url.params
        assert request_params["group_id"] == "root-1"
        assert [(d.serial_number, d.project_id, d.project_name) for d in devices] == [
            ("SN-ONE", "p1", "Site One"),
            ("SN-TWO", "p2", "Site Two"),
        ]

    def test_accepts_root_group_id_from_response_envelope(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={
                "code": 0,
                "groupId": "root-1",
                "groups": {
                    "type": "COMPANY",
                    "name": "Root",
                    "subGroups": [
                        {
                            "type": "BUILDING",
                            "name": "Site One",
                            "groupId": "p1",
                            "subGroups": [],
                        },
                    ],
                },
            },
        )
        device_route = mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [{"serialNumber": "SN-ONE", "groupId": "p1"}],
                "totalCount": 1,
            },
        )

        devices = client.get_fleet_devices()

        assert device_route.calls[0].request.url.params["group_id"] == "root-1"
        assert devices[0].project_id == "p1"

    def test_accepts_single_root_below_synthetic_wrapper(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={
                "code": 0,
                "groups": {
                    "subGroups": [
                        {
                            "type": "COMPANY",
                            "name": "Root",
                            "groupId": "root-1",
                            "subGroups": [
                                {
                                    "type": "BUILDING",
                                    "name": "Site One",
                                    "groupId": "p1",
                                    "subGroups": [],
                                },
                            ],
                        },
                    ],
                },
            },
        )
        device_route = mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [{"serialNumber": "SN-ONE", "groupId": "p1"}],
                "totalCount": 1,
            },
        )

        devices = client.get_fleet_devices()

        assert device_route.calls[0].request.url.params["group_id"] == "root-1"
        assert devices[0].project_id == "p1"

    def test_fails_closed_when_synthetic_wrapper_has_multiple_roots(
        self,
        authed_client,
    ):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={
                "code": 0,
                "groups": {
                    "subGroups": [
                        {"groupId": "root-1", "subGroups": []},
                        {"groupId": "root-2", "subGroups": []},
                    ],
                },
            },
        )

        with pytest.raises(APIError, match="ambiguous root group"):
            client.get_fleet_devices()

    def test_fails_closed_when_total_count_is_missing(self, authed_client):
        client, mock_api = authed_client
        self._mock_single_project_tree(mock_api)
        mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [{"serialNumber": "SN-ONE", "groupId": "p1"}],
            },
        )

        with pytest.raises(APIError, match="totalCount"):
            client.get_fleet_devices()

    def test_fails_closed_on_short_incomplete_page(self, authed_client):
        client, mock_api = authed_client
        self._mock_single_project_tree(mock_api)
        mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [{"serialNumber": "SN-ONE", "groupId": "p1"}],
                "totalCount": 2,
            },
        )

        with pytest.raises(APIError, match="incomplete"):
            client.get_fleet_devices()

    def test_fails_closed_when_a_full_page_repeats(self, authed_client):
        client, mock_api = authed_client
        self._mock_single_project_tree(mock_api)
        device_route = mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [{"serialNumber": "SN-ONE", "groupId": "p1"}],
                "totalCount": 2,
            },
        )

        with pytest.raises(APIError, match="duplicate"):
            client.get_fleet_devices(per_page=1)

        assert device_route.call_count == 2

    def test_rejects_fleet_larger_than_defensive_page_limit(self, authed_client):
        client, mock_api = authed_client
        self._mock_single_project_tree(mock_api)
        device_route = mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [{"serialNumber": "SN-ONE", "groupId": "p1"}],
                "totalCount": 2,
            },
        )

        with pytest.raises(APIError, match="defensive pagination limit"):
            client.get_fleet_devices(per_page=1, max_pages=1)

        assert device_route.call_count == 1

    def test_rejects_non_positive_pagination_bounds(self, authed_client):
        client, _mock_api = authed_client

        with pytest.raises(ValueError, match="bounds"):
            client.get_fleet_devices(deadline_seconds=0)

    def test_token_refresh_cannot_exhaust_aggregate_deadline(self, monkeypatch):
        class Clock:
            now = 100.0

            def monotonic(self):
                return self.now

        clock = Clock()
        client = RuijieClient(
            app_id="test-app",
            app_secret="test-secret",
            timeout=30.0,
        )
        auth_timeouts = []

        def delayed_auth(path, *, params, json, timeout=None):
            auth_timeouts.append(timeout)
            clock.now += 6.0
            return httpx.Response(
                200,
                json={"code": 0, "accessToken": "fresh-token"},
                request=httpx.Request("POST", f"{BASE_URL}{path}"),
            )

        def unexpected_fleet_request(*args, **kwargs):
            pytest.fail("fleet request started after authentication exhausted its deadline")

        monkeypatch.setattr("pyruijie.client.time", clock)
        monkeypatch.setattr(client._http, "post", delayed_auth)
        monkeypatch.setattr(client._http, "request", unexpected_fleet_request)

        with pytest.raises(RuijieConnectionError, match="deadline"):
            client.get_fleet_devices(deadline_seconds=5.0)

        assert auth_timeouts == pytest.approx([5.0])

    def test_token_refresh_time_is_removed_from_request_timeout(self, monkeypatch):
        class Clock:
            now = 100.0

            def monotonic(self):
                return self.now

        clock = Clock()
        client = RuijieClient(
            app_id="test-app",
            app_secret="test-secret",
            timeout=30.0,
        )
        request_timeouts = []

        def delayed_auth(path, *, params, json, timeout=None):
            clock.now += 2.0
            return httpx.Response(
                200,
                json={"code": 0, "accessToken": "fresh-token"},
                request=httpx.Request("POST", f"{BASE_URL}{path}"),
            )

        def fleet_request(method, path, *, params, timeout):
            request_timeouts.append(timeout)
            if path.endswith("/group/single/tree"):
                body = {
                    "code": 0,
                    "groups": {
                        "type": "COMPANY",
                        "name": "Root",
                        "groupId": "root-1",
                        "subGroups": [],
                    },
                }
            else:
                body = {"code": 0, "deviceList": [], "totalCount": 0}
            return httpx.Response(
                200,
                json=body,
                request=httpx.Request(method, f"{BASE_URL}{path}"),
            )

        monkeypatch.setattr("pyruijie.client.time", clock)
        monkeypatch.setattr(client._http, "post", delayed_auth)
        monkeypatch.setattr(client._http, "request", fleet_request)

        assert client.get_fleet_devices(deadline_seconds=5.0) == []
        assert request_timeouts == pytest.approx([3.0, 3.0])

    def test_fails_closed_when_root_group_is_missing(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={"code": 0, "groups": {}},
        )

        with pytest.raises(APIError, match="root group"):
            client.get_fleet_devices()

    def test_fails_closed_when_device_group_is_outside_hierarchy(
        self,
        authed_client,
    ):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={
                "code": 0,
                "groups": {
                    "type": "COMPANY",
                    "name": "Root",
                    "groupId": "root-1",
                    "subGroups": [],
                },
            },
        )
        mock_api.get("/service/api/maint/devices").respond(
            json={
                "code": 0,
                "deviceList": [
                    {"serialNumber": "SN-X", "groupId": "unknown"},
                ],
                "totalCount": 1,
            },
        )

        with pytest.raises(APIError, match="outside the fetched hierarchy"):
            client.get_fleet_devices()


# -- context manager -----------------------------------------------------------


class TestContextManager:
    def test_close(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok"}
        )
        with RuijieClient(app_id="a", app_secret="s") as client:
            client.authenticate()
            assert client.is_authenticated


# -- repr and properties -------------------------------------------------------


class TestClientRepr:
    def test_repr_unauthenticated(self):
        client = RuijieClient(app_id="a", app_secret="s")
        r = repr(client)
        assert "RuijieClient(" in r
        assert "authenticated=False" in r
        assert "cloud-us.ruijienetworks.com" in r

    def test_repr_authenticated(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok"}
        )
        client = RuijieClient(app_id="a", app_secret="s")
        client.authenticate()
        assert "authenticated=True" in repr(client)

    def test_base_url_property(self):
        client = RuijieClient(app_id="a", app_secret="s")
        assert client.base_url == "https://cloud-us.ruijienetworks.com"

    def test_custom_base_url_property(self):
        client = RuijieClient(
            app_id="a",
            app_secret="s",
            base_url="https://cloud-as.ruijienetworks.com",
        )
        assert client.base_url == "https://cloud-as.ruijienetworks.com"

    def test_base_url_trailing_slash_stripped(self):
        client = RuijieClient(
            app_id="a",
            app_secret="s",
            base_url="https://example.com/",
        )
        assert client.base_url == "https://example.com"


# -- get_clients tests ---------------------------------------------------------


class TestGetClients:
    def test_single_page(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/open/v1/dev/user/current-user").respond(
            json={
                "code": 0,
                "list": [
                    {
                        "mac": "AA:BB:CC:DD:EE:01",
                        "ip": "192.168.1.100",
                        "userName": "phone-01",
                        "staOs": "Android",
                        "connectType": "wireless",
                        "ssid": "OfficeWiFi",
                        "linkedDevice": "SN-AP-001",
                        "deviceName": "AP-Lobby",
                        "clientSource": "AP",
                        "manufacturer": "Samsung",
                        "onlineTime": 1700000000000,
                    }
                ],
                "totalCount": 1,
            }
        )
        clients = client.get_clients("proj-1")
        assert len(clients) == 1
        assert clients[0].mac == "AA:BB:CC:DD:EE:01"
        assert clients[0].ip == "192.168.1.100"
        assert clients[0].hostname == "phone-01"
        assert clients[0].ap_name == "AP-Lobby"
        assert clients[0].ap_mac == "SN-AP-001"
        assert clients[0].is_online is True

    def test_empty(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/open/v1/dev/user/current-user").respond(
            json={"code": 0, "list": [], "totalCount": 0}
        )
        clients = client.get_clients("proj-empty")
        assert clients == []

    def test_404_does_not_leak_token(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/open/v1/dev/user/current-user").respond(status_code=404)

        with pytest.raises(APIError) as exc_info:
            client.get_clients("proj-1")

        error_msg = str(exc_info.value)
        assert "access_token" not in error_msg
        assert "not be available" in error_msg

    def test_pagination_is_1_indexed(self, authed_client):
        """Regression test: Ruijie clients API uses 1-based page_index."""
        client, mock_api = authed_client
        requests_seen = []

        def handler(request):
            requests_seen.append(dict(request.url.params))
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "list": [{"mac": "AA:BB:CC:DD:EE:01"}],
                    "totalCount": 1,
                },
            )

        mock_api.get("/service/api/open/v1/dev/user/current-user").mock(side_effect=handler)
        client.get_clients("proj-1")

        assert requests_seen[0]["page_index"] == "1"

    def test_default_page_size_200(self, authed_client):
        """Regression test: default page_size should be 200, matching the CLI."""
        client, mock_api = authed_client
        requests_seen = []

        def handler(request):
            requests_seen.append(dict(request.url.params))
            return httpx.Response(200, json={"code": 0, "list": [], "totalCount": 0})

        mock_api.get("/service/api/open/v1/dev/user/current-user").mock(side_effect=handler)
        client.get_clients("proj-1")

        assert requests_seen[0]["page_size"] == "200"

    def test_pagination_multi_page(self, authed_client):
        client, mock_api = authed_client
        call_count = 0

        def handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(
                    200,
                    json={
                        "code": 0,
                        "list": [{"mac": f"AA:BB:CC:DD:EE:{i:02d}"} for i in range(200)],
                        "totalCount": 201,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "list": [{"mac": "AA:BB:CC:DD:EE:FF"}],
                    "totalCount": 201,
                },
            )

        mock_api.get("/service/api/open/v1/dev/user/current-user").mock(side_effect=handler)
        clients = client.get_clients("proj-1")
        assert len(clients) == 201
        assert call_count == 2


# -- get_gateway_ports tests ---------------------------------------------------


class TestGetGatewayPorts:
    def test_returns_typed_ports(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/gateway/intf/info/SN-GW-001").respond(
            json={
                "code": 0,
                "data": [
                    {
                        "alias": "WAN1",
                        "type": "WAN",
                        "ipAddr": "203.0.113.5",
                        "ipMask": "255.255.255.0",
                        "linestatus": "up",
                        "speed": "1000M",
                        "nextHop": "203.0.113.1",
                        "pppoe": "",
                    },
                    {
                        "alias": "LAN1",
                        "type": "LAN",
                        "ipAddr": "192.168.1.1",
                        "ipMask": "255.255.255.0",
                        "linestatus": "up",
                        "speed": "1000M",
                        "nextHop": "",
                        "pppoe": "",
                    },
                ],
            }
        )
        ports = client.get_gateway_ports("SN-GW-001")
        assert len(ports) == 2
        assert ports[0].alias == "WAN1"
        assert ports[0].is_wan is True
        assert ports[0].subnet == "203.0.113.0/24"
        assert ports[1].is_lan is True
        assert ports[1].subnet == "192.168.1.0/24"

    def test_empty(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/gateway/intf/info/SN-GW-002").respond(
            json={"code": 0, "data": []}
        )
        ports = client.get_gateway_ports("SN-GW-002")
        assert ports == []


# -- get_switch_ports tests ----------------------------------------------------


class TestGetSwitchPorts:
    def test_returns_typed_ports(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/conf/switch/device/SN-SW-001/ports").respond(
            json={
                "code": 0,
                "portList": [
                    {
                        "name": "GigabitEthernet0/1",
                        "type": "access",
                        "vlan": 100,
                        "vlanList": "1-4,100",
                        "status": "up",
                        "speed": "1000M",
                        "isUplink": False,
                        "poeStatus": "delivering",
                        "powerUsed": "12.5W",
                        "loopState": "normal",
                        "enable": "true",
                    }
                ],
            }
        )
        ports = client.get_switch_ports("SN-SW-001")
        assert len(ports) == 1
        assert ports[0].name == "GigabitEthernet0/1"
        assert ports[0].vlan == 100
        assert ports[0].allowed_vlans == {1, 2, 3, 4, 100}
        assert ports[0].is_up is True

    def test_pagination_0_indexed(self, authed_client):
        """Switch ports use 0-based pagination (different from clients)."""
        client, mock_api = authed_client
        requests_seen = []

        def handler(request):
            requests_seen.append(dict(request.url.params))
            return httpx.Response(200, json={"code": 0, "portList": []})

        mock_api.get("/service/api/conf/switch/device/SN-SW-001/ports").mock(side_effect=handler)
        client.get_switch_ports("SN-SW-001")

        assert requests_seen[0]["page_index"] == "0"

    def test_empty(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/conf/switch/device/SN-SW-002/ports").respond(
            json={"code": 0, "portList": []}
        )
        ports = client.get_switch_ports("SN-SW-002")
        assert ports == []


# -- URL sanitization tests ----------------------------------------------------


class TestSanitizeUrl:
    def test_strips_access_token(self):
        url = "https://cloud-us.ruijienetworks.com/service/api/open/v1/dev/user/current-user?group_id=123&access_token=SECRET123"
        result = _sanitize_url(url)
        assert "SECRET123" not in result
        assert "access_token=***" in result

    def test_strips_multiple_params(self):
        url = "https://example.com/api?token=TOK&access_token=ACC&secret=SEC&other=safe"
        result = _sanitize_url(url)
        assert "TOK" not in result
        assert "ACC" not in result
        assert "SEC" not in result
        assert "other=safe" in result

    def test_preserves_clean_url(self):
        url = "https://example.com/api?group_id=123&page=1"
        result = _sanitize_url(url)
        assert result == url
