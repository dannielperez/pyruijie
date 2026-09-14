"""Tests for pyruijie.client — GatewayClient."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
import requests

from pyruijie.exceptions import RuijieApiError, RuijieAuthError
from pyruijie.gateway import GatewayClient


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

    def test_repr_does_not_include_session_id(self, client: GatewayClient):
        client._sid = "SYNTHETIC-SID-AAAA"

        assert "authenticated" in repr(client)
        assert "SYNTHETIC-SID-AAAA" not in repr(client)


class TestGatewayClientLogin:
    def test_login_success(self, client: GatewayClient):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"sid": "abc123", "sn": "SERN0000000001"}}
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

        with (
            patch.object(client._session, "post", return_value=mock_resp),
            pytest.raises(RuijieAuthError, match="Login failed"),
        ):
            client.login()

    def test_login_connection_error(self, client: GatewayClient):
        with (
            patch.object(client._session, "post", side_effect=requests.ConnectionError("refused")),
            pytest.raises(RuijieAuthError, match="Login request failed"),
        ):
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

    def test_cmd_redacts_session_id_from_request_exception(self, client: GatewayClient):
        session_id = "SYNTHETIC-SID-BBBB"
        client._sid = session_id
        request_error = requests.RequestException(
            f"failed for https://gateway.test/cgi-bin/luci/api/cmd?auth={session_id}&mode=config"
        )

        with (
            patch.object(client._session, "post", side_effect=request_error),
            pytest.raises(RuijieApiError) as exc_info,
        ):
            client.cmd("devConfig.update", "wireguard")

        assert session_id not in str(exc_info.value)
        assert "auth=***" in str(exc_info.value)
        assert session_id not in str(exc_info.value.__cause__)

    def test_cmd_redacts_session_id_from_read_timeout(self, client: GatewayClient):
        session_id = "SYNTHETIC-SID-CCCC"
        client._sid = session_id
        timeout_error = requests.exceptions.ReadTimeout(
            f"timed out for https://gateway.test/cgi-bin/luci/api/cmd?auth={session_id}"
        )

        with (
            patch.object(client._session, "post", side_effect=timeout_error),
            pytest.raises(requests.exceptions.ReadTimeout) as exc_info,
        ):
            client.cmd("devConfig.update", "wireguard")

        assert session_id not in str(exc_info.value)
        assert "auth=***" in str(exc_info.value)

    def test_cmd_redacts_mutation_payload_debug_log(
        self,
        client: GatewayClient,
        caplog,
    ):
        client._sid = "SYNTHETIC-SID-DDDD"
        private_key = "SYNTHETIC-PRIVKEY-DDDD"
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"rcode": "00000000"}}
        mock_resp.raise_for_status = MagicMock()
        caplog.set_level(logging.DEBUG, logger="pyruijie.gateway")

        with patch.object(client._session, "post", return_value=mock_resp):
            client.cmd(
                "devConfig.update",
                "wireguard",
                {"peer": {"local_privkey": private_key}, "enabled": True},
            )

        messages = [record.getMessage() for record in caplog.records]
        assert all(private_key not in message for message in messages)
        assert any(
            "devConfig.update" in message and "wireguard" in message for message in messages
        )


class TestGatewayClientCmdChecked:
    def test_cmd_checked_success(self, client: GatewayClient):
        client._sid = "fake_sid"
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"rcode": "00000000", "message": "Success"}}
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

        with (
            patch.object(client._session, "post", return_value=mock_resp),
            pytest.raises(RuijieApiError, match="Invalid parameters"),
        ):
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


class TestGatewayClientInventory:
    def test_get_clients_uses_runtime_user_list_and_normalizes_firmware_aliases(
        self,
        client: GatewayClient,
    ):
        client._sid = "fake_sid"
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "rcode": "00000000",
                "list": [
                    {
                        "hostName": "Fanvil Lobby",
                        "userIp": "10.200.80.130",
                        "mac": "0C:38:3E:2C:9D:84",
                        "vlanId": 80,
                        "ifname": "port 5",
                        "vendorSpecific": "preserved",
                    },
                    {
                        "name": "Fanvil New",
                        "ipAddr": "10.200.80.131",
                        "macAddress": "0C-38-3E-2C-98-3D",
                        "vid": "80",
                    },
                ],
            },
        }
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_resp) as mock_post:
            clients = client.get_clients(timeout=7)

        assert [item.ip for item in clients] == ["10.200.80.130", "10.200.80.131"]
        assert [item.hostname for item in clients] == ["Fanvil Lobby", "Fanvil New"]
        assert [item.mac for item in clients] == [
            "0C:38:3E:2C:9D:84",
            "0C:38:3E:2C:98:3D",
        ]
        assert [item.vlan_id for item in clients] == [80, 80]
        assert clients[0].interface == "port 5"
        assert clients[0].model_dump()["vendorSpecific"] == "preserved"
        call = mock_post.call_args
        assert call.kwargs["json"]["method"] == "devSta.get"
        assert call.kwargs["json"]["params"]["module"] == "user_list"
        assert call.kwargs["timeout"] == 7

    @pytest.mark.parametrize(
        "payload, message",
        [
            ({"data": None}, "malformed data"),
            ({"data": {"rcode": "00000000"}}, "client list"),
            (
                {"data": {"rcode": "00000000", "list": [{"userIp": "10.0.0.1"}]}},
                "invalid client record",
            ),
            (
                {
                    "data": {
                        "rcode": "00000000",
                        "list": [
                            {"mac": "AA:BB:CC:DD:EE:FF"},
                            {"mac": "aabb.ccdd.eeff"},
                        ],
                    },
                },
                "duplicate client MAC",
            ),
        ],
    )
    def test_get_clients_rejects_incomplete_inventory(
        self,
        client: GatewayClient,
        payload,
        message,
    ):
        client._sid = "fake_sid"
        mock_resp = MagicMock()
        mock_resp.json.return_value = payload
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(client._session, "post", return_value=mock_resp),
            pytest.raises(RuijieApiError, match=message),
        ):
            client.get_clients()


class TestGatewayClientContextManager:
    def test_context_manager(self, client: GatewayClient):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"sid": "ctx_sid"}}
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(client._session, "post", return_value=mock_resp),
            patch.object(client, "close") as mock_close,
        ):
            with client as gw:
                assert gw.sid == "ctx_sid"

            mock_close.assert_called_once()
