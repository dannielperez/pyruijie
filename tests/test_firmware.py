"""Tests for read-only local firmware recognition and policy evaluation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pyruijie.firmware import (
    FirmwareCatalog,
    FirmwareCatalogError,
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

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


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

    with patch("pyruijie.firmware.urlopen", return_value=response):
        result = probe_firmware("10.40.4.7", catalog=catalog)

    assert result.reachable is True
    assert result.is_ruijie is True
    assert result.model == "EST100-E"
    assert result.version == B11P96
    assert result.status == "update_required"
    assert result.url == "http://10.40.4.7/cgi-bin/luci/"


def test_probe_rejects_unrelated_web_page(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    response = _FakeResponse(b"<html><title>Camera</title></html>")

    with patch("pyruijie.firmware.urlopen", return_value=response):
        result = probe_firmware("10.40.4.8", catalog=catalog)

    assert result.status == "not_ruijie"
    assert result.is_ruijie is False


def test_probe_requires_manual_review_when_new_login_page_hides_version(tmp_path):
    catalog = FirmwareCatalog.load(_write_catalog(tmp_path))
    response = _FakeResponse(
        b"<html><title>Ruijie Networks-EWEB</title><p>Hi, EST100-E</p></html>"
    )

    with patch("pyruijie.firmware.urlopen", return_value=response):
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

    def fake_urlopen(request, timeout):
        for host, response in responses.items():
            if host in request.full_url:
                return response
        raise AssertionError(request.full_url)

    with patch("pyruijie.firmware.urlopen", side_effect=fake_urlopen):
        results = scan_firmware(
            ["10.40.4.7", "10.40.4.8", "10.40.4.7"],
            catalog=catalog,
            workers=2,
        )

    assert [item.target for item in results] == ["10.40.4.7", "10.40.4.8"]
    assert [item.status for item in results] == ["update_required", "compliant"]


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
