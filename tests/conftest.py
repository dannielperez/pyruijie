"""Shared test fixtures."""

from __future__ import annotations

import copy
from typing import Any

import pytest
import respx

from pyruijie import RuijieClient

BASE_URL = "https://cloud-us.ruijienetworks.com"


@pytest.fixture()
def mock_api():
    """respx mock router scoped to the Ruijie base URL."""
    with respx.mock(base_url=BASE_URL) as router:
        yield router


def _stub_auth(router: respx.MockRouter) -> None:
    """Add a successful auth response to a respx router."""
    router.post("/service/api/oauth20/client/access_token").respond(
        json={"code": 0, "accessToken": "test-token-abc123"}
    )


@pytest.fixture()
def authed_client(mock_api):
    """Return a RuijieClient that is already authenticated against mocks."""
    _stub_auth(mock_api)
    client = RuijieClient(app_id="test-app", app_secret="test-secret")
    client.authenticate()
    return client, mock_api


# ── Gateway (LuCI JSON-RPC) mock fixtures ─────────────────────────────

SAMPLE_SERVER_POLICY = {
    "uuid": "af8b6d8a82994e6980541ad23e48e0d5",
    "enable": "1",
    "type": "1",
    "desc": "US_CentroCaguas_WG",
    "localAddr": "10.254.250.1/20",
    "localPort": "51820",
    "localPrivkey": "FAKE_PRIVKEY_SERVER==",
    "localPubkey": "u6tlEzHg/qQVZtnslLStHfuqDfMjxkDCsoLOpvEcyFI=",
    "localDns": ["8.8.8.8"],
    "clientlist": [
        {
            "uuid": "peer_uuid_001",
            "desc": "laptop-Danny",
            "ipaddr": "10.254.250.2",
            "peerPubkey": "FAKE_PUBKEY_DANNY==",
            "presharedkey": "FAKE_PSK_DANNY==",
            "allowips": ["10.254.250.2/32"],
        },
        {
            "uuid": "peer_uuid_002",
            "desc": "Caridad Pineiro",
            "ipaddr": "10.254.250.105",
            "peerPubkey": "wFTN1ARryoOvdyf37A0U8K1GA0fspN293guFjYlHRg4=",
            "presharedkey": "riXUgQwPj06rWqQcRC/2U7+OXC+f6xA4od/DeksBo3o=",
            "allowips": ["10.254.250.105/32"],
            "endpoint": "",
            "rxbyte": "1572",
            "txbyte": "2230",
            "updateTime": "1776532498",
        },
        {
            "uuid": "peer_uuid_003",
            "desc": "Caridad Plaza del Carmen",
            "ipaddr": "10.254.250.103",
            "peerPubkey": "v33YrsFefKKu+qluDR5dzD8GVcimDKOaNyWRxoEd4Eo=",
            "presharedkey": "E0K1b7n2/NychN1+W9WCo1wa9WYDuq1O30Nioo7oUME=",
            "allowips": ["10.254.250.103/32"],
        },
    ],
}

SAMPLE_CLIENT_POLICY = {
    "uuid": "Y0evjdu7aenaHTmUh5oLdnW6YI25hOGD",
    "enable": "1",
    "type": "0",
    "desc": "US_WG",
    "allowips": ["0.0.0.0/0"],
    "endpoint": "67.203.206.66",
    "endpointPort": "51820",
    "intf": "all",
    "keepalive": "30",
    "localAddr": "10.254.250.105/32",
    "localPort": "51820",
    "localPrivkey": "FAKE_PRIVKEY_SITE==",
    "localPubkey": "wFTN1ARryoOvdyf37A0U8K1GA0fspN293guFjYlHRg4=",
    "peerPubkey": "u6tlEzHg/qQVZtnslLStHfuqDfMjxkDCsoLOpvEcyFI=",
    "presharedkey": "riXUgQwPj06rWqQcRC/2U7+OXC+f6xA4od/DeksBo3o=",
    "localDns": ["8.8.8.8"],
    "priority": [],
    "strictPriority": "0",
    "localIfname": "wgclt0",
    "metric": "101",
    "rxbyte": "1572",
    "txbyte": "2230",
    "updateTime": "1776532498",
}


class MockGatewayClient:
    """A GatewayClient mock that returns canned responses."""

    def __init__(
        self,
        host: str = "10.200.0.1",
        server_policy: dict | None = None,
        client_policy: dict | None = None,
    ) -> None:
        self.host = host
        self._server_policy = copy.deepcopy(server_policy or SAMPLE_SERVER_POLICY)
        self._client_policy = copy.deepcopy(client_policy or SAMPLE_CLIENT_POLICY)
        self.calls: list[dict] = []
        self._sid = "mock_sid_12345"

    def login(self) -> str:
        return self._sid

    def cmd(
        self,
        method: str,
        module: str,
        data: dict[str, Any] | None = None,
        *,
        timeout: int | None = None,
        device: str = "pc",
    ) -> dict[str, Any]:
        self.calls.append({
            "method": method,
            "module": module,
            "data": data,
            "timeout": timeout,
        })

        if method == "devSta.get" and module == "wireguard":
            getype = (data or {}).get("getype", "0")
            if getype == "1":
                return {"data": {"serverlist": [copy.deepcopy(self._server_policy)]}}
            elif getype == "0":
                return {"data": {"clientlist": [copy.deepcopy(self._client_policy)]}}

        if method == "devConfig.get" and module == "wireguard":
            return {
                "data": {
                    "serverlist": [copy.deepcopy(self._server_policy)],
                    "clientlist": [copy.deepcopy(self._client_policy)],
                    "version": "1.0.0",
                }
            }

        if method == "devConfig.update" and module == "wireguard":
            if data and "clientlist" in data and "type" not in data:
                self._server_policy = copy.deepcopy(data)
            elif data and data.get("type") == "0":
                self._client_policy = copy.deepcopy(data)
            elif data and data.get("type") == "1":
                self._server_policy = copy.deepcopy(data)
            return {
                "data": {"rcode": "00000000", "message": "Success configuration"}
            }

        if method == "devConfig.del":
            return {
                "data": {"rcode": "00000000", "message": "Success configuration"}
            }

        return {"data": {}}

    def cmd_checked(
        self,
        method: str,
        module: str,
        data: dict[str, Any] | None = None,
        *,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        resp = self.cmd(method, module, data, timeout=timeout)
        return resp

    def close(self) -> None:
        pass


@pytest.fixture
def mock_gateway() -> MockGatewayClient:
    """A mock gateway client with sample server and client policies."""
    return MockGatewayClient()


@pytest.fixture
def mock_site_gateway() -> MockGatewayClient:
    """A mock site gateway client (has client policy, no server)."""
    return MockGatewayClient(
        host="10.254.250.105",
        server_policy={"uuid": "", "clientlist": []},
        client_policy=SAMPLE_CLIENT_POLICY,
    )
