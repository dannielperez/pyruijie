"""Ruijie Cloud API client."""

from __future__ import annotations

import os
import threading
import time
from typing import Any

import httpx

from pyruijie.exceptions import APIError, AuthenticationError, ConnectionError
from pyruijie.models import ClientDevice, Device, GatewayPort, Project, SwitchPort

_REDACT_PARAMS = frozenset({"access_token", "token", "secret"})

# Refresh tokens this many seconds before they actually expire.
_EXPIRY_BUFFER_SECONDS = 60

# Conservative token lifetime used when the auth response carries no explicit
# expiry (the Ruijie Cloud ``access_token`` endpoint returns only ``accessToken``
# today). Real Ruijie Cloud tokens live materially longer than this — hours — so
# a 30-minute cache stays comfortably inside that window while collapsing the
# re-auth storm. Override with the ``token_ttl`` constructor argument or the
# ``RUIJIE_TOKEN_TTL_SECONDS`` environment variable.
_DEFAULT_TOKEN_TTL_SECONDS = 1800.0
_DEFAULT_FLEET_DEADLINE_SECONDS = 360.0
_DEFAULT_FLEET_MAX_PAGES = 100

# Process-wide token cache, shared across RuijieClient instances.
#
# The whole ~100-site fleet lives under ONE Ruijie Cloud account. A common
# consumer pattern is a short-lived facade: build a client, authenticate, fetch
# one project, close — repeated per project in a fan-out loop. Because each
# facade owns its own client with an empty in-memory token, that pattern
# re-authenticates on *every* project (~109 mints per sweep) against a single
# shared cloud account, which is wasteful and risks tripping Ruijie Cloud's API
# rate limits (throttling the entire fleet's monitoring). This cache lets a
# fresh instance reuse a still-valid token minted by a sibling instance.
#
# Keyed by (base_url, app_id, api_token) — the identity the token is scoped to.
# Values are (access_token, expires_at monotonic seconds). Guarded by a lock so
# the dict stays consistent under a threaded worker pool. A rotated secret/token
# is not reflected until the cached token expires (<= its TTL) or
# ``invalidate()`` is called — acceptable for the token lifetimes in play.
_TOKEN_CACHE: dict[tuple[str, str, str], tuple[str, float]] = {}
_TOKEN_CACHE_LOCK = threading.Lock()


def clear_token_cache() -> None:
    """Drop all cached tokens (test isolation / forced global re-auth)."""
    with _TOKEN_CACHE_LOCK:
        _TOKEN_CACHE.clear()


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
        api_token: Ruijie Cloud OpenAPI gateway token sent with the
            authentication request. Obtain it from your Ruijie Cloud
            developer portal. Falls back to the ``RUIJIE_API_TOKEN``
            environment variable when not passed explicitly.
        base_url: API base URL.  Defaults to the US region endpoint.
            Use ``"https://cloud-as.ruijienetworks.com"`` for Asia or the
            region-specific URL shown in your Ruijie Cloud console.
        timeout: HTTP request timeout in seconds.

    Usage::

        with RuijieClient(app_id="...", app_secret="...", api_token="...") as client:
            client.authenticate()
            for project in client.get_projects():
                devices = client.get_devices(project.group_id)
    """

    def __init__(
        self,
        *,
        app_id: str,
        app_secret: str,
        api_token: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        token_ttl: float | None = None,
    ) -> None:
        self._app_id = app_id
        self._app_secret = app_secret
        self._api_token = api_token or os.environ.get("RUIJIE_API_TOKEN")
        self._base_url = base_url.rstrip("/")
        self._access_token: str | None = None
        self._expires_at: float = 0.0
        self._request_timeout = float(timeout)
        if token_ttl is None:
            token_ttl = float(
                os.environ.get("RUIJIE_TOKEN_TTL_SECONDS", _DEFAULT_TOKEN_TTL_SECONDS)
            )
        self._token_ttl = token_ttl
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

    @property
    def _cache_key(self) -> tuple[str, str, str]:
        return (self._base_url, self._app_id, self._api_token or "")

    def authenticate(self, *, force: bool = False) -> str:
        """Authenticate with the Ruijie Cloud API and return the access token.

        Called automatically on the first API request if not already
        authenticated. May return a still-valid token held by this instance or
        by the process-wide :data:`_TOKEN_CACHE` (so a per-project fan-out reuses
        one token instead of re-minting ~109 per sweep against the shared cloud
        account) rather than making a network round-trip.

        Args:
            force: Skip both caches and always mint a fresh token — e.g. a
                connection tester that must verify credentials live.

        Returns:
            The OAuth2 access token string.

        Raises:
            AuthenticationError: If credentials are invalid or the auth
                endpoint returns a non-zero error code.
            ConnectionError: If the API is unreachable.
        """
        if not force:
            # Fast path: this instance already holds a live token.
            if self._access_token and time.monotonic() < self._expires_at:
                return self._access_token
            # Cross-instance cache: reuse a token a sibling instance minted
            # against the same Ruijie Cloud account.
            with _TOKEN_CACHE_LOCK:
                cached = _TOKEN_CACHE.get(self._cache_key)
                if cached is not None and time.monotonic() < cached[1]:
                    self._access_token, self._expires_at = cached
                    return self._access_token

        return self._fetch_token()

    def _fetch_token(self) -> str:
        """Mint a fresh token from the auth endpoint and publish it to the cache."""
        if not self._api_token:
            raise AuthenticationError(
                "No Ruijie Cloud API token configured. Pass api_token=... to "
                "RuijieClient or set the RUIJIE_API_TOKEN environment variable."
            )
        try:
            resp = self._http.post(
                _AUTH_PATH,
                params={"token": self._api_token},
                json={"appid": self._app_id, "secret": self._app_secret},
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise AuthenticationError(f"HTTP {exc.response.status_code} during auth") from exc
        except httpx.ConnectError as exc:
            raise ConnectionError(_sanitize_url(str(exc))) from exc
        except httpx.TimeoutException as exc:
            raise ConnectionError(_sanitize_url(str(exc))) from exc

        data = resp.json()
        if data.get("code") != 0:
            raise AuthenticationError(data.get("msg", "Unknown authentication error"))

        self._access_token = data["accessToken"]
        # The endpoint returns only ``accessToken`` today; honor an ``expiresIn``
        # (seconds) if a future/region response ever includes one, else fall back
        # to the conservative configured TTL.
        expires_in = data.get("expiresIn")
        ttl = float(expires_in) if expires_in else self._token_ttl
        self._expires_at = time.monotonic() + max(ttl - _EXPIRY_BUFFER_SECONDS, 0.0)

        with _TOKEN_CACHE_LOCK:
            _TOKEN_CACHE[self._cache_key] = (self._access_token, self._expires_at)
        return self._access_token

    def invalidate(self) -> None:
        """Force the next :meth:`authenticate` call to mint a fresh token."""
        self._access_token = None
        self._expires_at = 0.0
        with _TOKEN_CACHE_LOCK:
            _TOKEN_CACHE.pop(self._cache_key, None)

    @property
    def is_authenticated(self) -> bool:
        return self._access_token is not None

    # -- internal HTTP helpers -------------------------------------------------

    def _ensure_auth(self) -> None:
        if not self._access_token or time.monotonic() >= self._expires_at:
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
        except httpx.TimeoutException as exc:
            raise ConnectionError(_sanitize_url(str(exc))) from exc

        data: dict[str, Any] = resp.json()
        if data.get("code") != 0:
            raise APIError(data.get("code", -1), data.get("msg", "Unknown error"))
        return data

    def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"params": params or {}}
        if timeout is not None:
            kwargs["timeout"] = timeout
        return self._request("GET", path, **kwargs)

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

    def _get_group_tree(self, *, timeout: float | None = None) -> dict[str, Any]:
        """Return the validated Ruijie account hierarchy root."""
        data = self._get(_GROUPS_PATH, {"depth": "DEVICE"}, timeout=timeout)
        groups = data.get("groups", {})
        if not isinstance(groups, dict):
            raise APIError(-1, "Ruijie group tree response is not an object")
        return groups

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
        return self._collect_projects(self._get_group_tree())

    def get_fleet_devices(
        self,
        *,
        per_page: int = 100,
        max_pages: int = _DEFAULT_FLEET_MAX_PAGES,
        deadline_seconds: float = _DEFAULT_FLEET_DEADLINE_SECONDS,
    ) -> list[Device]:
        """Return all account devices with their owning building/project.

        Ruijie Cloud's device-list API accepts a hierarchy ``group_id`` and
        returns each device's concrete ``groupId``. Fetching at the account
        root therefore replaces one request per building with one paginated
        root-scoped collection. The hierarchy is used to resolve nested device
        groups to their nearest BUILDING ancestor before typed results leave
        the SDK boundary.

        The method fails closed when hierarchy identity is incomplete. A
        caller must never apply an unpartitionable fleet snapshot to per-site
        inventory.

        Args:
            per_page: Devices requested per Ruijie page.
            max_pages: Defensive upper bound for vendor page requests.
            deadline_seconds: Aggregate hierarchy/device collection deadline.

        Raises:
            APIError: If hierarchy identity or pagination completeness is invalid.
            ConnectionError: If transport fails or the aggregate deadline expires.
            ValueError: If a pagination bound is not positive.
        """
        if per_page < 1 or max_pages < 1 or deadline_seconds <= 0:
            raise ValueError("Fleet pagination bounds must be positive")

        deadline = time.monotonic() + deadline_seconds
        groups = self._get_group_tree(timeout=self._fleet_request_timeout(deadline))
        root_group_id = str(groups.get("groupId") or "")
        if not root_group_id:
            raise APIError(-1, "Ruijie group tree is missing its root group ID")

        project_by_group: dict[str, Project] = {}
        self._index_group_projects(groups, project_by_group=project_by_group)
        devices = self._get_complete_fleet_devices(
            root_group_id,
            per_page=per_page,
            max_pages=max_pages,
            deadline=deadline,
        )

        enriched: list[Device] = []
        for device in devices:
            project = project_by_group.get(device.group_id or "")
            if project is None:
                raise APIError(
                    -1,
                    "Ruijie fleet device group is outside the fetched hierarchy",
                )
            enriched.append(
                device.model_copy(
                    update={
                        "project_id": project.group_id,
                        "project_name": project.name,
                    },
                ),
            )
        return enriched

    def _get_complete_fleet_devices(
        self,
        root_group_id: str,
        *,
        per_page: int,
        max_pages: int,
        deadline: float,
    ) -> list[Device]:
        """Collect a count-validated, duplicate-free fleet within hard bounds."""
        all_devices: list[Device] = []
        seen_serials: set[str] = set()
        expected_total: int | None = None

        for page in range(1, max_pages + 1):
            data = self._get(
                _DEVICES_PATH,
                {"group_id": root_group_id, "page": page, "per_page": per_page},
                timeout=self._fleet_request_timeout(deadline),
            )
            raw_devices = data.get("deviceList")
            if not isinstance(raw_devices, list):
                raise APIError(-1, "Ruijie fleet response is missing deviceList")

            raw_total = data.get("totalCount")
            try:
                page_total = int(raw_total)
            except (TypeError, ValueError) as exc:
                raise APIError(
                    -1,
                    "Ruijie fleet response is missing a valid totalCount",
                ) from exc
            if page_total < 0:
                raise APIError(-1, "Ruijie fleet totalCount cannot be negative")
            if expected_total is None:
                expected_total = page_total
                if expected_total > per_page * max_pages:
                    raise APIError(
                        -1,
                        "Ruijie fleet exceeds the defensive pagination limit",
                    )
            elif page_total != expected_total:
                raise APIError(-1, "Ruijie fleet totalCount changed during pagination")

            page_devices = [Device.model_validate(item) for item in raw_devices]
            page_serials = {device.serial_number for device in page_devices}
            if len(page_serials) != len(page_devices) or seen_serials & page_serials:
                raise APIError(-1, "Ruijie fleet pagination returned duplicate devices")
            seen_serials.update(page_serials)
            all_devices.extend(page_devices)

            if len(all_devices) == expected_total:
                return all_devices
            if len(all_devices) > expected_total:
                raise APIError(-1, "Ruijie fleet returned more devices than totalCount")
            if not raw_devices or len(raw_devices) < per_page:
                raise APIError(-1, "Ruijie fleet snapshot is incomplete")

        raise APIError(-1, "Ruijie fleet pagination exceeded its page limit")

    def _fleet_request_timeout(self, deadline: float) -> float:
        """Cap the next request so the fleet operation respects its deadline."""
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConnectionError("Ruijie fleet listing exceeded its deadline")
        return min(self._request_timeout, remaining)

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

    @staticmethod
    def _index_group_projects(
        group: dict[str, Any],
        *,
        project_by_group: dict[str, Project],
        owning_project: Project | None = None,
    ) -> None:
        """Map every hierarchy group to its nearest BUILDING ancestor."""
        if group.get("type") == "BUILDING":
            owning_project = Project.model_validate(group)

        group_id = str(group.get("groupId") or "")
        if group_id and owning_project is not None:
            project_by_group[group_id] = owning_project

        for sub in group.get("subGroups", []):
            RuijieClient._index_group_projects(
                sub,
                project_by_group=project_by_group,
                owning_project=owning_project,
            )
