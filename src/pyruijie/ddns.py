"""Ruijie Cloud DDNS (Dynamic DNS) over the web-SSO session.

The DDNS config for a gateway is NOT exposed by the open/service API
(appid/secret oauth); it is served through the cloud web UI's ``/webproxy``
pass-through, authenticated by the SSO browser session. The native Ruijie DDNS
(``*.ruijieddnsd.com``) is backed by the cloud's *aliyun* domain service:

    read:  POST /webproxy/common/api?/aliyun/device/domain/info?sn=<SN>
           module="3rdservice"  -> {rr, domainName, ip, bindIpType, bindEgPort}
    (No-IP / DynDNS providers live under /egw/conf/dydns/<SN>/<type>.)

This module reuses an authenticated :class:`RuijieWebSession` (the same SSO flow
the cloud UI uses) and exposes DDNS read/enumerate. Discovered + verified live
2026-07-02 against 40 US gateways (35 already had DDNS).

Auth env: ``RC_URL`` / ``RC_username`` / ``RC_password``.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

DEFAULT_BASE_URL = "https://cloud-us.ruijienetworks.com"
# RSA public key the login page uses to encrypt the password (prod cloud).
_LOGIN_PUBLIC_KEY = (
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKjeUvf/EGSrhYUApZlJRYYsYIkWQu5tcPc8bkWV"
    "qnlAFrJlVWmvgD5zd9Sevi7qNIl9+1NvNlFcqiUGgsevCNMCAwEAAQ=="
)
_SUFFIX = "ruijieddnsd.com"


class DdnsError(RuntimeError):
    """Raised when the SSO login or a DDNS webproxy call fails."""


@dataclass(slots=True)
class DdnsRecord:
    """A gateway's native Ruijie DDNS binding."""

    sn: str
    hostname: str | None  # e.g. "terracayey.ruijieddnsd.com" or None
    ip: str | None  # current mapped public IP
    bind_ip_type: str | None  # "WAN" | "PUBLIC"
    bind_eg_port: str | None  # egress WAN port, usually "default"
    rr: str | None  # the subdomain label ("terracayey")

    @property
    def configured(self) -> bool:
        return bool(self.rr)


class RuijieWebSession:
    """Authenticated Ruijie Cloud *web* session (SSO), for /webproxy calls.

    Separate from :class:`pyruijie.RuijieClient` (which uses the appid/secret
    open API). Use this for features only the web UI exposes, like DDNS.
    """

    def __init__(
        self, *, base_url: str, username: str, password: str, timeout: float = 30.0
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self._authed = False

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> RuijieWebSession:
        import os

        e = env or os.environ
        base = (e.get("RC_URL") or DEFAULT_BASE_URL).strip()
        user = (e.get("RC_username") or "").strip()
        pw = (e.get("RC_password") or "").strip()
        if not user or not pw:
            raise DdnsError("Missing RC_username / RC_password")
        return cls(base_url=base, username=user, password=pw)

    def _encrypt_password(self, raw: str) -> str:
        key = serialization.load_der_public_key(base64.b64decode(_LOGIN_PUBLIC_KEY))
        return base64.b64encode(key.encrypt(raw.encode(), padding.PKCS1v15())).decode("ascii")

    def login(self) -> None:
        """Perform the CAS/SSO login the web UI uses. Idempotent."""
        if self._authed:
            return
        page = self.session.get(f"{self.base_url}/sso/login", timeout=self.timeout)
        page.raise_for_status()
        hidden = dict(
            re.findall(
                r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)',
                page.text,
                re.IGNORECASE,
            )
        )
        if "lt" not in hidden or "execution" not in hidden:
            raise DdnsError("Could not extract CAS login fields from /sso/login")
        enc = self._encrypt_password(self.password)
        pre = self.session.post(
            f"{self.base_url}/sso/validate/password",
            json={"account": self.username, "password": enc},
            timeout=self.timeout,
        )
        pre.raise_for_status()
        pj = pre.json()
        if pj.get("code") != 0:
            raise DdnsError(pj.get("msg", "Credential validation failed"))
        if pj.get("isOpen2FA"):
            raise DdnsError("Account requires 2FA — not automated")
        resp = self.session.post(
            f"{self.base_url}/sso/login",
            data={
                "username": self.username,
                "originalPassword": "",
                "password": enc,
                "lt": hidden.get("lt", ""),
                "execution": hidden.get("execution", ""),
                "sign": hidden.get("sign", ""),
                "action": hidden.get("action", ""),
                "_eventId": hidden.get("_eventId", "submit") or "submit",
                "timeZone": hidden.get("timeZone", ""),
                "selectedCloud": pj.get("area", ""),
                "googleTotpCode": "",
                "disposableCode": "",
                "submit": "Login",
            },
            timeout=self.timeout,
            allow_redirects=True,
        )
        resp.raise_for_status()
        if "/macc5/adminIntl/" not in resp.url:
            raise DdnsError(f"Unexpected post-login landing URL: {resp.url}")
        self._authed = True

    def webproxy(
        self, api: str, *, method: str = "GET", module: str = "default"
    ) -> dict[str, Any]:
        """Call the cloud web UI's /webproxy pass-through (the SPA's transport)."""
        self.login()
        body = {
            "api": api,
            "method": method,
            "module": module,
            "querys": {"lang": "en"},
            "authParams": {"api": api, "method": method},
        }
        r = self.session.post(
            f"{self.base_url}/webproxy/common/api?{api}",
            json=body,
            timeout=self.timeout,
            headers={"Content-Type": "application/json"},
        )
        r.raise_for_status()
        return r.json()

    # --- DDNS (native Ruijie *.ruijieddnsd.com via the aliyun domain service) ---

    def get_ddns(self, sn: str) -> DdnsRecord:
        """Read a gateway's native Ruijie DDNS binding (empty rr => unconfigured)."""
        j = self.webproxy(f"/aliyun/device/domain/info?sn={sn}", method="GET", module="3rdservice")
        d = j.get("data") or {}
        rr = d.get("rr") or None
        dom = d.get("domainName") or _SUFFIX
        return DdnsRecord(
            sn=sn,
            hostname=f"{rr}.{dom}" if rr else None,
            ip=d.get("ip") or None,
            bind_ip_type=d.get("bindIpType"),
            bind_eg_port=d.get("bindEgPort"),
            rr=rr,
        )

    def enumerate_ddns(self, sns: list[str]) -> dict[str, DdnsRecord]:
        """Read DDNS for many gateways. Returns {sn: DdnsRecord}; skips failures."""
        out: dict[str, DdnsRecord] = {}
        for sn in sns:
            try:
                out[sn] = self.get_ddns(sn)
            except (requests.HTTPError, DdnsError, ValueError):
                continue
        return out

    def list_domain_suffixes(self) -> list[str]:
        """Available DDNS suffixes (e.g. ['ruijieddnsd.com'])."""
        j = self.webproxy("/aliyun/suffix/domain/list", method="GET", module="3rdservice")
        data = j.get("data") or []
        return [d.get("domainName", d) if isinstance(d, dict) else d for d in data]

    def set_ddns(
        self,
        sn: str,
        rr: str,
        *,
        bind_ip_type: str = "PUBLIC",
        bind_eg_port: str = "default",
        suffix: str = _SUFFIX,
    ) -> dict[str, Any]:
        """Create/update a gateway's native Ruijie DDNS binding to ``rr.suffix``.

        WRITE PATH — the exact create endpoint/payload is captured from a live
        Save in the web UI before enabling this in production (the UI POSTs to
        the /aliyun/device/domain service). Until verified against a live create,
        callers should treat this as experimental and confirm with get_ddns().
        """
        raise NotImplementedError(
            "set_ddns write path pending live capture of the UI Save call "
            "(POST /webproxy/common/api?/aliyun/device/domain/... ). "
            "Use the web GUI to create, then get_ddns() to verify."
        )
