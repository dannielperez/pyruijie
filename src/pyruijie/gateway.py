"""Low-level Ruijie/Reyee gateway LuCI JSON-RPC client.

Reverse-engineered from the Reyee web GUI (ReyeeOS 2.x).
Tested on EG1510XS (central hub) and EG310GH-P-E (site gateways).

Authentication
--------------
POST ``/cgi-bin/luci/api/auth`` with JSON-RPC login method.
Returns a session ID (``sid``) used as ``?auth=<sid>`` query param
on subsequent requests.  A cookie ``<SN>=<SID>`` is also set.

API Dispatch
------------
All configuration and status queries go through a single endpoint:
POST ``/cgi-bin/luci/api/cmd?auth=<sid>``

The payload is JSON-RPC with ``method`` being one of:
- ``devSta.get`` — read runtime state
- ``devConfig.get`` — read persisted config
- ``devConfig.update`` — write config changes
- ``devConfig.add`` — add config entries (limited support)
- ``devConfig.del`` — delete config entries

The ``params`` dict always includes ``module`` and ``device`` ("pc").

Success is indicated by ``rcode: "00000000"`` in the response data.
Any other rcode is an error.
"""

from __future__ import annotations

import logging
from typing import Any

import requests
import urllib3

from pyruijie.exceptions import RuijieApiError, RuijieAuthError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class GatewayClient:
    """Low-level client for the Ruijie EG gateway LuCI JSON-RPC API.

    Usage::

        gw = GatewayClient("10.200.0.1", "admin", "Unique2025@")
        gw.login()
        result = gw.cmd("devSta.get", "wireguard", data={"getype": "1"})
    """

    def __init__(
        self,
        host: str,
        username: str = "admin",
        password: str = "",
        *,
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self._base_url = f"https://{host}"
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._sid: str | None = None
        self._sn: str | None = None
        self._request_id = 0

    @property
    def sid(self) -> str | None:
        """Current session ID, or None if not authenticated."""
        return self._sid

    @property
    def serial_number(self) -> str | None:
        """Gateway serial number, populated after login."""
        return self._sn

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def login(self) -> str:
        """Authenticate to the gateway and store the session ID.

        Returns:
            The session ID string.

        Raises:
            RuijieAuthError: If login fails.
        """
        try:
            r = self._session.post(
                f"{self._base_url}/cgi-bin/luci/api/auth",
                json={
                    "id": self._next_id(),
                    "method": "login",
                    "params": {
                        "username": self.username,
                        "password": self.password,
                    },
                },
                timeout=self.timeout,
            )
            r.raise_for_status()
        except requests.RequestException as exc:
            raise RuijieAuthError(f"Login request failed for {self.host}: {exc}") from exc

        data = r.json()
        if data.get("data") is None:
            raise RuijieAuthError(
                f"Login failed for {self.host}: {data.get('error') or data}"
            )

        self._sid = data["data"]["sid"]
        self._sn = data["data"].get("sn")
        logger.debug("Authenticated to %s (SN: %s)", self.host, self._sn)
        return self._sid

    def _ensure_auth(self) -> None:
        if not self._sid:
            raise RuijieAuthError("Not authenticated — call login() first")

    def cmd(
        self,
        method: str,
        module: str,
        data: dict[str, Any] | None = None,
        *,
        timeout: int | None = None,
        device: str = "pc",
    ) -> dict[str, Any]:
        """Execute a JSON-RPC command on the gateway.

        Args:
            method: API method (e.g. "devSta.get", "devConfig.update").
            module: Config module name (e.g. "wireguard").
            data: Optional data dict for the command.
            timeout: Override request timeout (seconds).
            device: Device target, always "pc" for gateway management.

        Returns:
            Full JSON response dict from the gateway.

        Raises:
            RuijieAuthError: If not authenticated.
            RuijieApiError: If the gateway returns an error rcode.
        """
        self._ensure_auth()
        url = f"{self._base_url}/cgi-bin/luci/api/cmd?auth={self._sid}"
        params: dict[str, Any] = {"module": module, "device": device}
        if data is not None:
            params["data"] = data

        payload = {
            "id": self._next_id(),
            "method": method,
            "params": params,
        }

        logger.debug("CMD %s %s data=%s", method, module, data)

        try:
            r = self._session.post(
                url,
                json=payload,
                timeout=timeout or self.timeout,
            )
            r.raise_for_status()
        except requests.exceptions.ReadTimeout:
            # Timeouts on config updates usually mean the gateway is applying
            # the change.  Callers should handle this explicitly.
            raise
        except requests.RequestException as exc:
            raise RuijieApiError(f"Request failed: {exc}") from exc

        return r.json()

    def cmd_checked(
        self,
        method: str,
        module: str,
        data: dict[str, Any] | None = None,
        *,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Execute a command and raise on non-success rcode.

        Same as :meth:`cmd` but automatically checks the ``rcode``
        field and raises :exc:`RuijieApiError` on failure.

        Config update timeouts (ReadTimeout) are treated as success
        since the gateway applies config asynchronously.
        """
        try:
            resp = self.cmd(method, module, data, timeout=timeout)
        except requests.exceptions.ReadTimeout:
            logger.debug("CMD %s %s timed out (config likely applied)", method, module)
            return {"data": {"rcode": "00000000", "message": "Timeout (config applied)"}}

        resp_data = resp.get("data", {})
        if isinstance(resp_data, dict):
            rcode = resp_data.get("rcode", "")
            if rcode and rcode != "00000000":
                raise RuijieApiError(
                    f"{method} {module} failed: {resp_data.get('message', rcode)}",
                    rcode=rcode,
                    raw=resp,
                )
        return resp

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self) -> GatewayClient:
        self.login()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        auth = "authenticated" if self._sid else "not authenticated"
        return f"GatewayClient({self.host!r}, {auth})"
