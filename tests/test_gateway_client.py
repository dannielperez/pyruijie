"""Tests for pyruijie.client — GatewayClient."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from pyruijie.gateway import GatewayClient
from pyruijie.exceptions import RuijieApiError, RuijieAuthError


@pytest.fixture
def client():
    return GatewayClient("192.168.1.1", "admin", "password123")


class TestGatewayClientInit:

    def test_defaults(self, client: GatewayClient):
        assert client.host == "192.168.1.1"
        assert client.username == "admin"
        assert client.sid is None
        assert client.serial_number is None

    def test_repr_not_authenticated(self, client: GatewayClient):
        assert "not authenticated" in repr(client)


class TestGatewayClientLogin:

    def test_login_success(self, client: GatewayClient):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"sid": "abc123", "sn": "SERN0000000001"}
        }
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_resp):
            sid = client.login()

        assert sid == "abc123"
        assert client.sid == "abc123"
        assert client.serial_number == "SERN0000000001"

    def test_login_failure_no_data(self, client: GatewayClient):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"error": "bad password"}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_resp):
            with pytest.raises(RuijieAuthError, match="Login failed"):
                client.login()

    def test_login_connection_error(self, client: GatewayClient):
        with patch.object(
            client._session, "post", side_effect=requests.ConnectionError("refused")
        ):
            with pytest.raises(RuijieAuthError, match="Login request failed"):
                client.login()


class TestGatewayClientCmd:

    def test_cmd_requires_auth(self, client: GatewayClient):
        with pytest.raises(RuijieAuthError, match="Not authenticated"):
            client.cmd("devSta.get", "wireguard")

    def test_cmd_sends_correct_payload(self, client: GatewayClient):
        client._sid = "fake_sid"
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"serverlist": []}}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_resp) as mock_post:
            result = client.cmd("devSta.get", "wireguard", {"getype": "1"})

        call_args = mock_post.call_args
        url = call_args[0][0]
        assert "auth=fake_sid" in url
        payload = call_args[1]["json"]
        assert payload["method"] == "devSta.get"
        assert payload["params"]["module"] == "wireguard"
        assert payload["params"]["data"] == {"getype": "1"}
        assert result == {"data": {"serverlist": []}}

    def test_cmd_request_ids_increment(self, client: GatewayClient):
        client._sid = "fake_sid"
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {}}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_resp) as mock_post:
            client.cmd("devSta.get", "wireguard")
            client.cmd("devSta.get", "wireguard")

        ids = [c[1]["json"]["id"] for c in mock_post.call_args_list]
        assert ids[1] > ids[0]


class TestGatewayClientCmdChecked:

    def test_cmd_checked_success(self, client: GatewayClient):
        client._sid = "fake_sid"
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"rcode": "00000000", "message": "Success"}
        }
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_resp):
            result = client.cmd_checked("devConfig.update", "wireguard", {"uuid": "x"})

        assert result["data"]["rcode"] == "00000000"

    def test_cmd_checked_error_rcode(self, client: GatewayClient):
        client._sid = "fake_sid"
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"rcode": "06070001", "message": "Invalid parameters"}
        }
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_resp):
            with pytest.raises(RuijieApiError, match="Invalid parameters"):
                client.cmd_checked("devConfig.update", "wireguard")

    def test_cmd_checked_timeout_treated_as_success(self, client: GatewayClient):
        client._sid = "fake_sid"

        with patch.object(
            client._session,
            "post",
            side_effect=requests.exceptions.ReadTimeout("timeout"),
        ):
            result = client.cmd_checked("devConfig.update", "wireguard")

        assert result["data"]["rcode"] == "00000000"


class TestGatewayClientContextManager:

    def test_context_manager(self, client: GatewayClient):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"sid": "ctx_sid"}}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_resp):
            with patch.object(client, "close") as mock_close:
                with client as gw:
                    assert gw.sid == "ctx_sid"

                mock_close.assert_called_once()
