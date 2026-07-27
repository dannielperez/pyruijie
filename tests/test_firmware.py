"""Tests for read-only local firmware recognition and policy evaluation."""

from __future__ import annotations

import hashlib
import json
import socket
from http.client import HTTPResponse, IncompleteRead
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pyruijie.firmware import (
    FirmwareCatalog,
    FirmwareCatalogError,
    _set_response_timeout,
    probe_firmware,
    scan_firmware,
)

B11P96 = "AP_3.0(1)B11P96,Release(11132319)"
B11P320 = "AP_3.0(1)B11P320,Release(12152011)"
B11P380 = "AP_3.0(1)B11P380,Release(12231910)"


def _catalog_data(*, approved: bool = False, sha256: str | None = None) -> dict:
    return {
        "schema_version": 1,
        "artifacts": [
            {
                "id": "est100-e-b11p320-cloud",
                "model": "EST100-E",
                "version": B11P320,
                "filename": "est100-e-b11p320.tar" if approved else None,
                "sha256": sha256,
                "state": "approved" if approved else "metadata-only",
            },
            {
                "id": "est100-e-b11p380-observed",
                "model": "EST100-E",
                "version": B11P380,
                "filename": None,
                "sha256": None,
                "state": "observed",
            },
        ],
        "rules": [
            {
                "id": "est100-e-b11p96-to-b11p320",
                "model": "EST100-E",
                "source_versions": [B11P96],
                "target_artifact": "est100-e-b11p320-cloud",
                "reason": "cloud compatibility update required",
            }
        ],
    }


def _write_catalog(tmp_path: Path, data: dict | None = None) -> Path:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data or _catalog_data()), encoding="utf-8")
    return path


def _login_page(version: str, model: str = "EST100-E") -> bytes:
    return f"""
    <html>
      <title>Ruijie Networks-EWEB</title>
      <body>Hi, {model}</body>
      <iframe src="/luci-static/eweb-est/cache.htm?v={version}\\n"></iframe>
    </html>
    """.encode()


class _FakeResponse:
    def __init__(self, body: bytes, url: str = "http://10.40.4.7/cgi-bin/luci/") -> None:
        self.body = body
        self.url = url
        self.offset = 0
        self.timeouts: list[float] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, amount: int) -> bytes:
        chunk = self.body[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)


class _SocketRecorder:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)


def _response_with_socket_at_path(path: tuple[str, ...], sock):
    nested = sock
    for attribute in reversed(path):
        nested = SimpleNamespace(**{attribute: nested})
    return nested


def _redirecting_transport(routes: dict[str, bytes | str], requested_urls: list[str]):
    def open_request(request, *, timeout, redirect_handler):
        class FakeRedirectResponse:
            def read(self):
                raise AssertionError("redirect response body must not be drained")

            def close(self):
                return None

        class FakeOpener:
            def open(self, current_request, timeout):
                requested_urls.append(current_request.full_url)
                route = routes[current_request.full_url]
                if isinstance(route, bytes):
                    return _FakeResponse(route, current_request.full_url)
                return redirect_handler.http_error_302(
                    current_request,
                    FakeRedirectResponse(),
                    302,
                    "Found",
                    {"location": route},
                )

        opener = FakeOpener()
        redirect_handler.add_parent(opener)
        return opener.open(request, timeout)

    return open_request


def test_catalog_marks_exact_old_est100_version_for_update(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    decision = catalog.evaluate("est100-e", B11P96)

    assert decision.status == "update_required"
    assert decision.target_version == B11P320
    assert decision.upload_ready is False


def test_catalog_marks_target_version_compliant(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    decision = catalog.evaluate("EST100-E", B11P320)

    assert decision.status == "compliant"


def test_catalog_recognizes_newer_cloud_version_without_selecting_it_as_target(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    current = catalog.evaluate("EST100-E", B11P380)
    bootstrap = catalog.evaluate("EST100-E", B11P96)

    assert current.status == "compliant"
    assert bootstrap.target_version == B11P320


def test_catalog_does_not_guess_for_other_known_model_version(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    decision = catalog.evaluate("EST100-E", "AP_3.0(1)B11P999,Release(99999999)")

    assert decision.status == "manual_review"


def test_probe_reads_model_and_version_without_login(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    response = _FakeResponse(_login_page(B11P96))

    with patch("pyruijie.firmware._open_request", return_value=response):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.reachable is True
    assert result.is_ruijie is True
    assert result.model == "EST100-E"
    assert result.version == B11P96
    assert result.status == "update_required"
    assert result.url == "http://10.40.4.7/cgi-bin/luci/"


def test_probe_rejects_unrelated_web_page(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    response = _FakeResponse(
        b"<html><title>Camera</title></html>",
        "http://10.40.4.8/cgi-bin/luci/",
    )

    with patch("pyruijie.firmware._open_request", return_value=response):
        result = probe_firmware("10.40.4.8", catalog=catalog)

    assert result.status == "not_ruijie"
    assert result.is_ruijie is False


def test_probe_requires_manual_review_when_new_login_page_hides_version(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    response = _FakeResponse(
        b"<html><title>Ruijie Networks-EWEB</title><p>Hi, EST100-E</p></html>"
    )

    with patch("pyruijie.firmware._open_request", return_value=response):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.status == "manual_review"
    assert result.model == "EST100-E"
    assert result.version is None


def test_probe_reports_invalid_target_without_crashing_scan(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    result = probe_firmware("not a host / path", catalog=catalog)

    assert result.status == "invalid_target"
    assert result.reachable is False


def test_scan_preserves_order_and_removes_duplicate_targets(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    responses = {
        "10.40.4.7": _FakeResponse(_login_page(B11P96), "http://10.40.4.7/cgi-bin/luci/"),
        "10.40.4.8": _FakeResponse(_login_page(B11P320), "http://10.40.4.8/cgi-bin/luci/"),
    }

    def fake_open_request(request, *, timeout, redirect_handler):
        for host, response in responses.items():
            if host in request.full_url:
                return response
        raise AssertionError(request.full_url)

    with patch("pyruijie.firmware._open_request", side_effect=fake_open_request):
        results = scan_firmware(
            ["10.40.4.7", "10.40.4.8", "10.40.4.7"],
            catalog=catalog,
            workers=2,
        )

    assert [item.target for item in results] == ["10.40.4.7", "10.40.4.8"]
    assert [item.status for item in results] == ["update_required", "compliant"]


@pytest.mark.parametrize(
    "redirect_url",
    [
        "http://169.254.169.254/",
        "http://127.0.0.1/",
    ],
)
def test_probe_contains_redirects_to_other_hosts(tmp_path, redirect_url):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    start_url = "http://10.40.4.7/cgi-bin/luci/"
    requested_urls: list[str] = []
    transport = _redirecting_transport(
        {
            start_url: redirect_url,
            redirect_url: _login_page(B11P96),
        },
        requested_urls,
    )

    with patch("pyruijie.firmware._open_request", side_effect=transport):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.reachable is False
    assert result.status == "unreachable"
    assert "redirect left the target host" in result.reason
    assert redirect_url not in requested_urls


def test_probe_follows_same_host_https_upgrade(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    start_url = "http://10.40.4.7/cgi-bin/luci/"
    secure_url = "https://10.40.4.7/login"
    requested_urls: list[str] = []
    transport = _redirecting_transport(
        {
            start_url: secure_url,
            secure_url: _login_page(B11P96),
        },
        requested_urls,
    )

    with patch("pyruijie.firmware._open_request", side_effect=transport):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert requested_urls == [start_url, secure_url]
    assert result.reachable is True
    assert result.is_ruijie is True
    assert result.status == "update_required"
    assert result.url == secure_url


def test_probe_rejects_non_http_redirect_scheme(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    start_url = "http://10.40.4.7/cgi-bin/luci/"
    redirect_url = "ftp://10.40.4.7/login"
    requested_urls: list[str] = []
    transport = _redirecting_transport(
        {
            start_url: redirect_url,
            redirect_url: _login_page(B11P96),
        },
        requested_urls,
    )

    with patch("pyruijie.firmware._open_request", side_effect=transport):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.reachable is False
    assert result.status == "unreachable"
    assert "unsupported scheme" in result.reason
    assert redirect_url not in requested_urls


def test_probe_validates_final_url_after_same_host_redirect(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    start_url = "http://10.40.4.7/cgi-bin/luci/"
    same_host_url = "https://10.40.4.7/login"
    requested_urls: list[str] = []

    def transport(request, *, timeout, redirect_handler):
        requested_urls.append(request.full_url)
        redirect_handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            same_host_url,
        )
        return _FakeResponse(_login_page(B11P96), "http://169.254.169.254/")

    with patch("pyruijie.firmware._open_request", side_effect=transport):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert requested_urls == [start_url]
    assert result.reachable is False
    assert result.status == "unreachable"
    assert "redirect left the target host" in result.reason


def test_probe_stops_redirect_loop_at_hop_cap(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    first_url = "http://10.40.4.7/cgi-bin/luci/"
    second_url = "http://10.40.4.7/login"
    requested_urls: list[str] = []
    transport = _redirecting_transport(
        {
            first_url: second_url,
            second_url: first_url,
        },
        requested_urls,
    )

    with patch("pyruijie.firmware._open_request", side_effect=transport):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.reachable is False
    assert result.status == "unreachable"
    assert result.reason == "redirect hop limit exceeded"
    assert requested_urls == [first_url, second_url, first_url, second_url]


def test_set_response_timeout_handles_httpresponse_shape():
    sock = _SocketRecorder()
    response = SimpleNamespace(fp=SimpleNamespace(raw=SimpleNamespace(_sock=sock)))

    _set_response_timeout(response, 2.5)

    assert sock.timeouts == [2.5]


@pytest.mark.parametrize(
    "path",
    [
        ("fp", "fp", "raw", "_sock"),
        ("fp", "_sock"),
        ("raw", "_sock"),
        ("_sock",),
    ],
)
def test_set_response_timeout_handles_declared_fallback_paths(path):
    sock = _SocketRecorder()
    response = _response_with_socket_at_path(path, sock)

    _set_response_timeout(response, 2.5)

    assert sock.timeouts == [2.5]


def test_set_response_timeout_handles_real_httpresponse():
    client, server = socket.socketpair()
    with client, server:
        server.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        response = HTTPResponse(client)
        response.begin()
        try:
            _set_response_timeout(response, 2.5)

            assert response.fp.raw._sock is client
            assert client.gettimeout() == 2.5
        finally:
            response.close()


def test_probe_normalizes_missing_response_socket_path(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    class ResponseWithoutSocketPath:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def geturl(self):
            return "http://10.40.4.7/cgi-bin/luci/"

        def read(self, amount):
            raise AssertionError("body must not be read without an enforced timeout")

    with patch(
        "pyruijie.firmware._open_request",
        return_value=ResponseWithoutSocketPath(),
    ):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.reachable is False
    assert result.status == "unreachable"
    assert result.error == "could not enforce aggregate deadline on response body"


def test_probe_enforces_decreasing_deadline_through_response_socket(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    class FakeClock:
        now = 0.0

        def monotonic(self):
            return self.now

    class DeadlineSocket:
        def __init__(self, clock):
            self.clock = clock
            self.calls = []

        def settimeout(self, timeout):
            self.calls.append((timeout, self.clock.now))

    class SlowSocketResponse:
        def __init__(self, clock):
            self.clock = clock
            self.socket = DeadlineSocket(clock)
            self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=self.socket))
            self.read_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def geturl(self):
            return "http://10.40.4.7/cgi-bin/luci/"

        def read(self, amount):
            self.read_calls += 1
            self.clock.now += 0.4
            return b"x"

    clock = FakeClock()
    response = SlowSocketResponse(clock)
    with (
        patch("pyruijie.firmware.time.monotonic", side_effect=clock.monotonic),
        patch("pyruijie.firmware._open_request", return_value=response),
    ):
        result = probe_firmware("10.40.4.7", catalog=catalog, timeout=1.0)

    timeouts = [timeout for timeout, _ in response.socket.calls]
    assert result.reachable is False
    assert result.status == "unreachable"
    assert "aggregate deadline" in (result.error or "")
    assert timeouts == pytest.approx([1.0, 0.6, 0.2])
    assert all(
        current > following for current, following in zip(timeouts, timeouts[1:], strict=False)
    )
    assert all(timeout <= 1.0 - called_at for timeout, called_at in response.socket.calls)


def test_probe_uses_one_aggregate_deadline_for_slow_body(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    class FakeClock:
        now = 0.0

        def monotonic(self):
            return self.now

    class SlowDripResponse(_FakeResponse):
        def __init__(self, clock):
            super().__init__(b"x" * 10)
            self.clock = clock
            self.read_calls = 0

        def read(self, amount):
            self.read_calls += 1
            self.clock.now += 0.4
            return super().read(1)

    clock = FakeClock()
    response = SlowDripResponse(clock)
    with (
        patch("pyruijie.firmware.time.monotonic", side_effect=clock.monotonic),
        patch("pyruijie.firmware._open_request", return_value=response),
    ):
        result = probe_firmware("10.40.4.7", catalog=catalog, timeout=1.0)

    assert result.reachable is False
    assert result.status == "unreachable"
    assert "aggregate deadline" in (result.error or "")
    assert response.read_calls == 3
    assert clock.now < 10 * 0.4


def test_probe_normalizes_incomplete_body_read(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))

    class IncompleteResponse(_FakeResponse):
        def read(self, amount):
            if self.offset:
                raise IncompleteRead(partial=b"partial")
            return super().read(7)

    response = IncompleteResponse(_login_page(B11P96))
    with patch("pyruijie.firmware._open_request", return_value=response):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.reachable is False
    assert result.status == "unreachable"


def test_probe_preserves_safe_read_limit_outcome(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    response = _FakeResponse(b"x" * (512 * 1024 + 1))

    with patch("pyruijie.firmware._open_request", return_value=response):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.reachable is True
    assert result.status == "unrecognized"
    assert result.reason == "login page exceeded the safe read limit"


def test_repository_verification_requires_matching_sha256(tmp_path):
    image = tmp_path / "est100-e-b11p320.tar"
    image.write_bytes(b"approved test firmware")
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    catalog = FirmwareCatalog.load(
        _write_catalog(tmp_path, _catalog_data(approved=True, sha256=digest))
    )

    result = catalog.verify_repository(tmp_path)

    by_id = {item["artifact_id"]: item for item in result}
    assert by_id["est100-e-b11p320-cloud"]["valid"] is True
    assert by_id["est100-e-b11p320-cloud"]["reason"] == "checksum verified"
    assert by_id["est100-e-b11p380-observed"]["valid"] is True
    assert "no repository image required" in by_id["est100-e-b11p380-observed"]["reason"]


def test_catalog_rejects_invalid_sha256(tmp_path):
    path = _write_catalog(tmp_path, _catalog_data(approved=True, sha256="not-a-digest"))

    with pytest.raises(FirmwareCatalogError, match="sha256"):
        FirmwareCatalog.load(path)


def test_catalog_rejects_approved_artifact_without_checksum(tmp_path):
    path = _write_catalog(tmp_path, _catalog_data(approved=True, sha256=None))

    with pytest.raises(FirmwareCatalogError, match="requires a filename and SHA-256"):
        FirmwareCatalog.load(path)
