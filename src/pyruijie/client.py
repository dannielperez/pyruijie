"""Ruijie Cloud API client."""

from __future__ import annotations

from typing import Any

import httpx

from pyruijie.exceptions import APIError, AuthenticationError, ConnectionError
from pyruijie.models import ClientDevice, Device, GatewayPort, Project, SwitchPort

_REDACT_PARAMS = frozenset({"access_token", "token", "secret"})


def _sanitize_url(text: str) -> str:
    """Remove sensitive query parameters from URLs embedded in error messages."""
    import re

    return re.sub(
        r"(" + "|".join(_REDACT_PARAMS) + r")=[^&'\s]+",
        r"\1=***",
        text,
    )


DEFAULT_BASE_URL = "https://cloud-us.ruijienetworks.com"
_AUTH_PATH = "/service/api/oauth20/client/access_token"
_GROUPS_PATH = "/service/api/group/single/tree"
_DEVICES_PATH = "/service/api/maint/devices"
_CLIENTS_PATH = "/service/api/open/v1/dev/user/current-user"
_GATEWAY_PORTS_PATH = "/service/api/gateway/intf/info"
_SWITCH_PORTS_PATH = "/service/api/conf/switch/device"


class RuijieClient:
    """Synchronous client for the Ruijie Cloud API.

    Args:
        app_id: OAuth2 application ID from the Ruijie Cloud developer portal.
        app_secret: OAuth2 application secret.
        base_url: API base URL.  Defaults to the US region endpoint.
            Use ``"https://cloud-as.ruijienetworks.com"`` for Asia or the
            region-specific URL shown in your Ruijie Cloud console.
        timeout: HTTP request timeout in seconds.

    Usage::

        with RuijieClient(app_id="...", app_secret="...") as client:
            client.authenticate()
            for project in client.get_projects():
                devices = client.get_devices(project.group_id)
    """

    def __init__(
        self,
        *,
        app_id: str,
        app_secret: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
    ) -> None:
        self._app_id = app_id
        self._app_secret = app_secret
        self._base_url = base_url.rstrip("/")
        self._access_token: str | None = None
        self._http = httpx.Client(base_url=self._base_url, timeout=timeout)

    def __repr__(self) -> str:
        return f"RuijieClient(base_url={self._base_url!r}, authenticated={self.is_authenticated})"

    # -- lifecycle -------------------------------------------------------------

    @property
    def base_url(self) -> str:
        """The API base URL this client is configured to use."""
        return self._base_url

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self) -> RuijieClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- authentication --------------------------------------------------------

    def authenticate(self) -> str:
        """Authenticate with the Ruijie Cloud API and return the access token.

        Called automatically on the first API request if not already
        authenticated.  Call explicitly to verify credentials before
        making data requests.

        Returns:
            The OAuth2 access token string.

        Raises:
            AuthenticationError: If credentials are invalid or the auth
                endpoint returns a non-zero error code.
            ConnectionError: If the API is unreachable.
        """
        try:
            resp = self._http.post(
                _AUTH_PATH,
                params={"token": "d63dss0a81e4415a889ac5b78fsc904a"},
                json={"appid": self._app_id, "secret": self._app_secret},
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise AuthenticationError(f"HTTP {exc.response.status_code} during auth") from exc
        except httpx.ConnectError as exc:
            raise ConnectionError(_sanitize_url(str(exc))) from exc

        data = resp.json()
        if data.get("code") != 0:
            raise AuthenticationError(data.get("msg", "Unknown authentication error"))

        self._access_token = data["accessToken"]
        return self._access_token

    @property
    def is_authenticated(self) -> bool:
        return self._access_token is not None

    # -- internal HTTP helpers -------------------------------------------------

    def _ensure_auth(self) -> None:
        if not self._access_token:
            self.authenticate()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        """Execute an authenticated API request and return the JSON body."""
        self._ensure_auth()

        params = kwargs.pop("params", {})
        params["access_token"] = self._access_token

        try:
            resp = self._http.request(method, path, params=params, **kwargs)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = _sanitize_url(str(exc))
            if exc.response.status_code == 404:
                msg = (
                    f"Client error '404 Not Found' for endpoint {path}. "
                    "This endpoint may not be available for your Ruijie Cloud "
                    "account or region."
                )
            raise APIError(exc.response.status_code, msg) from exc
        except httpx.ConnectError as exc:
            raise ConnectionError(_sanitize_url(str(exc))) from exc

        data: dict[str, Any] = resp.json()
        if data.get("code") != 0:
            raise APIError(data.get("code", -1), data.get("msg", "Unknown error"))
        return data

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", path, params=params or {})

    def _post(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> dict[str, Any]:
        return self._request("POST", path, params=params or {}, json=json)

    def _put(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> dict[str, Any]:
        return self._request("PUT", path, params=params or {}, json=json)

    # -- read-only API methods -------------------------------------------------

    def get_projects(self) -> list[Project]:
        """Return all projects (building-level groups) from Ruijie Cloud.

        Projects correspond to physical sites/buildings in the Ruijie
        Cloud hierarchy.  Use ``project.group_id`` as the key for
        subsequent ``get_devices()`` and ``get_clients()`` calls.

        Returns:
            List of :class:`~pyruijie.Project` instances.

        Raises:
            APIError: If the API returns a non-zero error code.
            ConnectionError: If the API is unreachable.
        """
        data = self._get(_GROUPS_PATH, {"depth": "DEVICE"})
        groups = data.get("groups", {})
        return self._collect_projects(groups)

    def get_devices(self, project_id: str, *, per_page: int = 100) -> list[Device]:
        """Return all managed network devices for a project.

        Fetches APs, switches, gateways, and other infrastructure devices.
        Handles pagination automatically.

        Args:
            project_id: The ``group_id`` of the target project.
            per_page: Number of devices per API page (matches upstream
                ``per_page`` parameter name).

        Returns:
            List of :class:`~pyruijie.Device` instances.

        Raises:
            APIError: If the API returns a non-zero error code.
            ConnectionError: If the API is unreachable.
        """
        all_devices: list[Device] = []
        page = 1
        while True:
            data = self._get(
                _DEVICES_PATH,
                {"group_id": project_id, "page": page, "per_page": per_page},
            )
            raw_devices = data.get("deviceList", [])
            if not raw_devices:
                break
            all_devices.extend(Device.model_validate(d) for d in raw_devices)
            if len(raw_devices) < per_page:
                break
            page += 1
        return all_devices

    def get_clients(self, project_id: str, *, page_size: int = 200) -> list[ClientDevice]:
        """Return all connected client devices for a project.

        Returns devices currently online — phones, laptops, cameras,
        intercoms, and other endpoints connected to the network.
        Handles pagination automatically.

        Args:
            project_id: The ``group_id`` of the target project.
            page_size: Number of clients per API page (matches upstream
                ``page_size`` parameter name; default 200 for fewer
                round-trips).

        Returns:
            List of :class:`~pyruijie.ClientDevice` instances.

        Raises:
            APIError: If the API returns a non-zero error code.
            ConnectionError: If the API is unreachable.
        """
        all_clients: list[ClientDevice] = []
        page_index = 1
        while True:
            data = self._get(
                _CLIENTS_PATH,
                {"group_id": project_id, "page_index": page_index, "page_size": page_size},
            )
            raw_clients = data.get("list", [])
            if not raw_clients:
                break
            all_clients.extend(ClientDevice.model_validate(c) for c in raw_clients)
            total = data.get("totalCount", 0)
            if total and len(all_clients) >= total:
                break
            page_index += 1
        return all_clients

    def get_gateway_ports(self, serial_number: str) -> list[GatewayPort]:
        """Return WAN/LAN port details for a gateway device.

        Corresponds to Ruijie Cloud API 2.6.4.

        Args:
            serial_number: Serial number of the gateway device.

        Returns:
            List of :class:`~pyruijie.GatewayPort` instances.

        Raises:
            APIError: If the device is not found or the API returns an error.
            ConnectionError: If the API is unreachable.
        """
        data = self._get(f"{_GATEWAY_PORTS_PATH}/{serial_number}")
        raw_ports = data.get("data", [])
        return [GatewayPort.model_validate(p) for p in raw_ports]

    def get_switch_ports(
        self,
        serial_number: str,
        *,
        page_size: int = 100,
    ) -> list[SwitchPort]:
        """Return port details for a switch device.

        Fetches VLAN assignments, PoE status, uplink flags, and link
        state for every port.  Handles pagination automatically.

        Corresponds to Ruijie Cloud API 2.6.7.  Note: this endpoint
        uses **0-based** page indexing, unlike the clients endpoint.

        Args:
            serial_number: Serial number of the switch device.
            page_size: Number of ports per API page.

        Returns:
            List of :class:`~pyruijie.SwitchPort` instances.

        Raises:
            APIError: If the device is not found or the API returns an error.
            ConnectionError: If the API is unreachable.
        """
        all_ports: list[SwitchPort] = []
        page_index = 0
        while True:
            data = self._get(
                f"{_SWITCH_PORTS_PATH}/{serial_number}/ports",
                {"page_size": page_size, "page_index": page_index},
            )
            raw_ports = data.get("portList", [])
            if not raw_ports:
                break
            all_ports.extend(SwitchPort.model_validate(p) for p in raw_ports)
            if len(raw_ports) < page_size:
                break
            page_index += 1
        return all_ports

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _collect_projects(group: dict[str, Any]) -> list[Project]:
        """Recursively collect BUILDING-type groups as projects."""
        projects: list[Project] = []
        if group.get("type") == "BUILDING":
            projects.append(Project.model_validate(group))
        for sub in group.get("subGroups", []):
            projects.extend(RuijieClient._collect_projects(sub))
        return projects
