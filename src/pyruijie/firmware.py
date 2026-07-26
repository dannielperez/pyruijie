"""Ruijie/Reyee local-device firmware inventory and policy evaluation.

The EST bridge login page exposes the model and current software version before
authentication.  This module uses only that read-only surface to identify
devices which need an approved cloud-compatibility update.  It intentionally
does not implement firmware upload: an artifact must first be registered with a
SHA-256 digest and the authenticated device API must be validated separately.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

_MODEL_PATTERNS = (
    re.compile(r"\bHi,\s*([A-Z][A-Z0-9-]{2,})\b", re.IGNORECASE),
    re.compile(r">\s*(EST[0-9A-Z-]+)\s*<", re.IGNORECASE),
)
_VERSION_PATTERN = re.compile(
    r"cache\.htm\?v=([^\"'<>\r\n]+)",
    re.IGNORECASE,
)
_RUIJIE_MARKERS = ("Ruijie Networks", "eweb-est", "cache.htm?v=")
_MAX_LOGIN_PAGE_BYTES = 512 * 1024


class FirmwareCatalogError(ValueError):
    """The firmware catalog is missing, malformed, or internally inconsistent."""


@dataclass(frozen=True)
class FirmwareArtifact:
    """One versioned firmware image known to the local repository."""

    artifact_id: str
    model: str
    version: str
    filename: str | None
    sha256: str | None
    state: str
    notes: str = ""

    @property
    def upload_ready(self) -> bool:
        """Whether an actual, checksum-pinned image is expected in the repository."""
        return self.state == "approved" and bool(self.filename and self.sha256)


@dataclass(frozen=True)
class FirmwareRule:
    """An explicitly approved source-to-target upgrade path."""

    rule_id: str
    model: str
    source_versions: tuple[str, ...]
    target_artifact_id: str
    reason: str


@dataclass(frozen=True)
class FirmwareDecision:
    """Policy result for a successfully identified local device."""

    status: str
    reason: str
    target_artifact_id: str | None = None
    target_version: str | None = None
    upload_ready: bool = False


@dataclass(frozen=True)
class FirmwareProbeResult:
    """Read-only probe plus catalog policy result for one target."""

    target: str
    url: str
    reachable: bool
    is_ruijie: bool
    model: str | None
    version: str | None
    status: str
    reason: str
    target_artifact_id: str | None = None
    target_version: str | None = None
    upload_ready: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FirmwareCatalog:
    """Model-specific firmware artifacts and approved upgrade paths."""

    def __init__(
        self,
        *,
        artifacts: Iterable[FirmwareArtifact],
        rules: Iterable[FirmwareRule],
    ) -> None:
        artifact_list = list(artifacts)
        rule_list = list(rules)
        self.artifacts = {item.artifact_id: item for item in artifact_list}
        self.rules = tuple(rule_list)

        if len(self.artifacts) != len(artifact_list):
            raise FirmwareCatalogError("duplicate artifact id")
        for artifact in self.artifacts.values():
            if artifact.state not in {"metadata-only", "approved", "observed"}:
                raise FirmwareCatalogError(
                    f"artifact {artifact.artifact_id!r} has unsupported state {artifact.state!r}"
                )
            if artifact.state == "approved" and not artifact.upload_ready:
                raise FirmwareCatalogError(
                    f"approved artifact {artifact.artifact_id!r} requires a filename and SHA-256"
                )
        for rule in self.rules:
            artifact = self.artifacts.get(rule.target_artifact_id)
            if artifact is None:
                raise FirmwareCatalogError(
                    f"rule {rule.rule_id!r} references unknown artifact "
                    f"{rule.target_artifact_id!r}"
                )
            if _normalize_model(artifact.model) != _normalize_model(rule.model):
                raise FirmwareCatalogError(
                    f"rule {rule.rule_id!r} model does not match its target artifact"
                )

    @classmethod
    def load(cls, path: str | Path) -> FirmwareCatalog:
        """Load and validate a JSON catalog."""
        catalog_path = Path(path)
        try:
            raw = json.loads(catalog_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise FirmwareCatalogError(f"catalog not found: {catalog_path}") from exc
        except json.JSONDecodeError as exc:
            raise FirmwareCatalogError(f"invalid catalog JSON: {exc}") from exc

        if raw.get("schema_version") != 1:
            raise FirmwareCatalogError("unsupported firmware catalog schema")
        try:
            artifacts = [
                FirmwareArtifact(
                    artifact_id=item["id"],
                    model=_normalize_model(item["model"]),
                    version=_normalize_version(item["version"]),
                    filename=item.get("filename"),
                    sha256=_normalize_sha256(item.get("sha256")),
                    state=item.get("state", "metadata-only"),
                    notes=item.get("notes", ""),
                )
                for item in raw.get("artifacts", [])
            ]
            rules = [
                FirmwareRule(
                    rule_id=item["id"],
                    model=_normalize_model(item["model"]),
                    source_versions=tuple(
                        _normalize_version(value) for value in item["source_versions"]
                    ),
                    target_artifact_id=item["target_artifact"],
                    reason=item["reason"],
                )
                for item in raw.get("rules", [])
            ]
        except (KeyError, TypeError) as exc:
            raise FirmwareCatalogError(f"malformed catalog entry: {exc}") from exc
        return cls(artifacts=artifacts, rules=rules)

    def evaluate(self, model: str, version: str) -> FirmwareDecision:
        """Evaluate one identified device against exact, approved paths."""
        normalized_model = _normalize_model(model)
        normalized_version = _normalize_version(version)

        for artifact in self.artifacts.values():
            if (
                _normalize_model(artifact.model) == normalized_model
                and _normalize_version(artifact.version) == normalized_version
            ):
                return FirmwareDecision(
                    status="compliant",
                    reason=f"already running catalog target {artifact.artifact_id}",
                    target_artifact_id=artifact.artifact_id,
                    target_version=artifact.version,
                    upload_ready=artifact.upload_ready,
                )

        for rule in self.rules:
            if (
                _normalize_model(rule.model) == normalized_model
                and normalized_version in rule.source_versions
            ):
                artifact = self.artifacts[rule.target_artifact_id]
                return FirmwareDecision(
                    status="update_required",
                    reason=rule.reason,
                    target_artifact_id=artifact.artifact_id,
                    target_version=artifact.version,
                    upload_ready=artifact.upload_ready,
                )

        known_model = any(
            _normalize_model(item.model) == normalized_model for item in self.artifacts.values()
        )
        if known_model:
            return FirmwareDecision(
                status="manual_review",
                reason="model is known but this source version has no approved upgrade path",
            )
        return FirmwareDecision(
            status="unsupported",
            reason="model is not present in the firmware catalog",
        )

    def verify_repository(self, repository: str | Path) -> list[dict[str, Any]]:
        """Verify every catalog artifact against files in a local repository."""
        root = Path(repository).resolve()
        results: list[dict[str, Any]] = []
        for artifact in self.artifacts.values():
            item: dict[str, Any] = {
                "artifact_id": artifact.artifact_id,
                "model": artifact.model,
                "version": artifact.version,
                "filename": artifact.filename,
                "state": artifact.state,
                "valid": False,
            }
            if artifact.state == "observed":
                item["valid"] = True
                item["reason"] = "recognition-only version; no repository image required"
            elif not artifact.upload_ready:
                item["reason"] = "metadata only; filename/SHA-256 approval is incomplete"
            else:
                path = (root / str(artifact.filename)).resolve()
                if not path.is_relative_to(root):
                    item["reason"] = "artifact filename escapes the repository directory"
                elif not path.is_file():
                    item["reason"] = f"missing file: {path}"
                else:
                    actual = _sha256_file(path)
                    item["actual_sha256"] = actual
                    item["valid"] = actual == artifact.sha256
                    item["reason"] = "checksum verified" if item["valid"] else "checksum mismatch"
            results.append(item)
        return results


def probe_firmware(
    target: str,
    *,
    catalog: FirmwareCatalog,
    timeout: float = 5.0,
) -> FirmwareProbeResult:
    """Read the unauthenticated login page and classify its firmware."""
    try:
        url = _target_url(target)
    except ValueError as exc:
        return FirmwareProbeResult(
            target=target,
            url="",
            reachable=False,
            is_ruijie=False,
            model=None,
            version=None,
            status="invalid_target",
            reason="target is not a valid HTTP device address",
            error=str(exc),
        )
    request = Request(
        url,
        headers={"User-Agent": "pyruijie-firmware-audit/1"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            body = response.read(_MAX_LOGIN_PAGE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        return FirmwareProbeResult(
            target=target,
            url=url,
            reachable=False,
            is_ruijie=False,
            model=None,
            version=None,
            status="unreachable",
            reason="could not read the device login page",
            error=str(exc),
        )

    if len(body) > _MAX_LOGIN_PAGE_BYTES:
        return FirmwareProbeResult(
            target=target,
            url=final_url,
            reachable=True,
            is_ruijie=False,
            model=None,
            version=None,
            status="unrecognized",
            reason="login page exceeded the safe read limit",
        )

    text = body.decode("utf-8", errors="replace")
    is_ruijie = any(marker.lower() in text.lower() for marker in _RUIJIE_MARKERS)
    model = _extract_model(text)
    version = _extract_version(text)
    if not is_ruijie:
        return FirmwareProbeResult(
            target=target,
            url=final_url,
            reachable=True,
            is_ruijie=False,
            model=model,
            version=version,
            status="not_ruijie",
            reason="page does not match the Ruijie/Reyee EST login signature",
        )
    if not model:
        return FirmwareProbeResult(
            target=target,
            url=final_url,
            reachable=True,
            is_ruijie=True,
            model=model,
            version=version,
            status="unrecognized",
            reason="Ruijie device found but its model could not be parsed",
        )
    if not version:
        return FirmwareProbeResult(
            target=target,
            url=final_url,
            reachable=True,
            is_ruijie=True,
            model=model,
            version=None,
            status="manual_review",
            reason=(
                "model identified but this login-page generation does not expose "
                "a firmware version before authentication"
            ),
        )

    decision = catalog.evaluate(model, version)
    return FirmwareProbeResult(
        target=target,
        url=final_url,
        reachable=True,
        is_ruijie=True,
        model=model,
        version=version,
        status=decision.status,
        reason=decision.reason,
        target_artifact_id=decision.target_artifact_id,
        target_version=decision.target_version,
        upload_ready=decision.upload_ready,
    )


def scan_firmware(
    targets: Iterable[str],
    *,
    catalog: FirmwareCatalog,
    timeout: float = 5.0,
    workers: int = 8,
) -> list[FirmwareProbeResult]:
    """Probe targets concurrently while preserving input order."""
    target_list = list(
        dict.fromkeys(str(target).strip() for target in targets if str(target).strip())
    )
    if workers < 1:
        raise ValueError("workers must be at least 1")
    with ThreadPoolExecutor(max_workers=min(workers, max(len(target_list), 1))) as pool:
        return list(
            pool.map(
                lambda target: probe_firmware(target, catalog=catalog, timeout=timeout),
                target_list,
            )
        )


def _extract_model(text: str) -> str | None:
    for pattern in _MODEL_PATTERNS:
        match = pattern.search(text)
        if match:
            return _normalize_model(match.group(1))
    return None


def _extract_version(text: str) -> str | None:
    match = _VERSION_PATTERN.search(text)
    return _normalize_version(match.group(1)) if match else None


def _normalize_model(value: str) -> str:
    return str(value).strip().upper()


def _normalize_version(value: str) -> str:
    # Some EST login pages terminate the iframe query value with an actual
    # newline; test captures and proxies may preserve it as the two characters
    # ``\n`` instead.
    return re.sub(r"(?:\\[rn]|[\r\n])+$", "", str(value)).strip()


def _normalize_sha256(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise FirmwareCatalogError("artifact sha256 must be 64 hexadecimal characters")
    return normalized


def _target_url(target: str) -> str:
    value = str(target).strip()
    if "://" not in value:
        value = f"http://{value}/"
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or any(char.isspace() for char in parsed.netloc)
    ):
        raise ValueError(f"invalid HTTP target: {target!r}")
    if parsed.path and parsed.path != "/":
        return value
    return urljoin(value if value.endswith("/") else f"{value}/", "cgi-bin/luci/")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
