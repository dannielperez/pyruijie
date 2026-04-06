"""Ruijie Cloud API client."""

from __future__ import annotations

from typing import Any

import httpx

from pyruijie.exceptions import APIError, AuthenticationError, ConnectionError
from pyruijie.models import Device, Project

DEFAULT_BASE_URL = "https://cloud-us.ruijienetworks.com"
_AUTH_PATH = "/service/api/oauth20/client/access_token"
_GROUPS_PATH = "/service/api/group/single/tree"
_DEVICES_PATH = "/service/api/maint/devices"


class RuijieClient:
    """Synchronous client for the Ruijie Cloud API.

    Usage::

        client = RuijieClient(app_id="...", app_secret="...")
        client.authenticate()
        projects = client.get_projects()
        devices = client.get_devices(projects[0].group_id)
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

    # -- lifecycle -------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self) -> RuijieClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- authentication --------------------------------------------------------

    def authenticate(self) -> str:
        """Authenticate with the Ruijie Cloud API and return the access token."""
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
            raise ConnectionError(str(exc)) from exc

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
            raise APIError(exc.response.status_code, str(exc)) from exc
        except httpx.ConnectError as exc:
            raise ConnectionError(str(exc)) from exc

        data: dict[str, Any] = resp.json()
        if data.get("code") != 0:
            raise APIError(data.get("code", -1), data.get("msg", "Unknown error"))
        return data

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", path, params=params or {})

    # -- read-only API methods -------------------------------------------------

    def get_projects(self) -> list[Project]:
        """Return all projects (building-level groups) from Ruijie Cloud."""
        data = self._get(_GROUPS_PATH, {"depth": "DEVICE"})
        groups = data.get("groups", {})
        return self._collect_projects(groups)

    def get_devices(self, project_id: str, *, per_page: int = 100) -> list[Device]:
        """Return all devices for a given project, handling pagination."""
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
