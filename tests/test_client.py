"""Tests for RuijieClient."""

import httpx
import pytest

from pyruijie import RuijieClient
from pyruijie.exceptions import APIError, AuthenticationError

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

    def test_auto_auth_on_first_request(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "auto-tok"}
        )
        mock_api.get("/service/api/group/single/tree").respond(
            json={"code": 0, "groups": {}}
        )
        client = RuijieClient(app_id="a", app_secret="s")

        assert not client.is_authenticated
        client.get_projects()
        assert client.is_authenticated


# -- get_projects tests --------------------------------------------------------


class TestGetProjects:
    def test_empty(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/group/single/tree").respond(
            json={"code": 0, "groups": {}}
        )
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
                    "deviceList": [
                        {"serialNumber": "SN100", "productType": "AP"}
                    ],
                },
            )

        mock_api.get("/service/api/maint/devices").mock(side_effect=device_handler)
        devices = client.get_devices("proj-1", per_page=100)
        assert len(devices) == 101
        assert call_count == 2

    def test_empty_project(self, authed_client):
        client, mock_api = authed_client
        mock_api.get("/service/api/maint/devices").respond(
            json={"code": 0, "deviceList": []}
        )
        devices = client.get_devices("proj-empty")
        assert devices == []


# -- context manager -----------------------------------------------------------


class TestContextManager:
    def test_close(self, mock_api):
        mock_api.post("/service/api/oauth20/client/access_token").respond(
            json={"code": 0, "accessToken": "tok"}
        )
        with RuijieClient(app_id="a", app_secret="s") as client:
            client.authenticate()
            assert client.is_authenticated
