"""Endpoint update workflow: switch hub endpoint on site gateways.

Formalises the batch endpoint-update path used during DDNS/public-IP
changes at the hub. Wraps
:meth:`pyruijie.WireGuardManager.update_client_endpoint` so the
calling application, scheduled jobs, and the ``pyruijie workflow``
CLI can call the same function.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field

from pyruijie.exceptions import RuijieAuthError, RuijieWireGuardError
from pyruijie.gateway import GatewayClient
from pyruijie.wireguard import WireGuardManager

from .exceptions import WorkflowPrecheckError
from .progress import NullProgressSink, ProgressEvent, ProgressSink

SiteClientFactory = Callable[[str], GatewayClient]
"""Returns an authenticated :class:`GatewayClient` for a site IP.

The caller owns credential handling to avoid leaking secrets into
workflow inputs. Raising any exception is treated as an unreachable
site.
"""


@dataclass(frozen=True)
class EndpointTarget:
    """One site gateway in the batch."""

    ip: str
    name: str = ""


@dataclass(frozen=True)
class EndpointUpdateOutcome:
    """Per-site outcome."""

    ip: str
    name: str
    status: str  # "updated" | "already-configured" | "planned" |
    # "wrong-old-endpoint" | "unreachable" | "failed"
    previous_endpoint: str = ""
    new_endpoint: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class EndpointUpdateBatchResult:
    """Aggregate outcome across all sites."""

    new_endpoint: str
    dry_run: bool
    sites_total: int = 0
    sites_updated: int = 0
    sites_already_configured: int = 0
    sites_unreachable: int = 0
    sites_failed: int = 0
    results: list[EndpointUpdateOutcome] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.sites_failed == 0 and self.sites_unreachable == 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["success"] = self.success
        return d


def update_site_endpoints(
    targets: Iterable[EndpointTarget],
    *,
    new_endpoint: str,
    site_client_factory: SiteClientFactory,
    expected_old_endpoint: str | None = None,
    new_endpoint_port: str | None = None,
    apply: bool = False,
    progress: ProgressSink | None = None,
) -> EndpointUpdateBatchResult:
    """Update the hub endpoint configured on a batch of site gateways.

    Idempotent: sites already pointing at ``new_endpoint`` are
    reported as ``already-configured`` and skipped.

    Safety: when ``expected_old_endpoint`` is supplied, sites whose
    current endpoint does not match are reported as
    ``wrong-old-endpoint`` and NOT modified — even when ``apply`` is
    True. This prevents accidentally rewriting sites that are already
    on a different hub.

    Args:
        targets: Iterable of :class:`EndpointTarget` — each with the
            site gateway IP and a display name.
        new_endpoint: Replacement hub endpoint (IP or DNS hostname).
        site_client_factory: Called with the target IP to obtain an
            authenticated :class:`GatewayClient`.
        expected_old_endpoint: If set, only rewrite sites whose
            current endpoint equals this value.
        new_endpoint_port: Optional replacement port. ``None`` keeps
            the existing port.
        apply: If ``False`` (default), probe and report only.
        progress: Optional :class:`ProgressSink` for streaming events.

    Returns:
        :class:`EndpointUpdateBatchResult`.

    Raises:
        WorkflowPrecheckError: ``new_endpoint`` is empty.
    """
    if not new_endpoint:
        raise WorkflowPrecheckError("new_endpoint is required")

    sink: ProgressSink = progress or NullProgressSink()
    target_list = list(targets)

    sink.emit(
        ProgressEvent(
            "info",
            "workflow.start",
            f"Endpoint update on {len(target_list)} site(s) -> "
            f"{new_endpoint} ({'DRY-RUN' if not apply else 'APPLY'})",
            context={
                "sites_in_scope": len(target_list),
                "new_endpoint": new_endpoint,
                "apply": apply,
            },
        )
    )

    results: list[EndpointUpdateOutcome] = []
    updated = already = unreachable = failed = 0

    for tgt in target_list:
        label = f"{tgt.name or tgt.ip} ({tgt.ip})"
        try:
            site_client = site_client_factory(tgt.ip)
        except Exception as exc:  # noqa: BLE001
            unreachable += 1
            results.append(
                EndpointUpdateOutcome(
                    ip=tgt.ip,
                    name=tgt.name,
                    status="unreachable",
                    error=f"site connect failed: {exc}",
                )
            )
            sink.emit(
                ProgressEvent(
                    "warning",
                    "site.unreachable",
                    f"{label}: unreachable — {exc}",
                )
            )
            continue

        try:
            wg = WireGuardManager(site_client)
            policy = wg.get_client_policy()
        except (RuijieAuthError, RuijieWireGuardError) as exc:
            unreachable += 1
            results.append(
                EndpointUpdateOutcome(
                    ip=tgt.ip,
                    name=tgt.name,
                    status="unreachable",
                    error=str(exc),
                )
            )
            sink.emit(
                ProgressEvent(
                    "warning",
                    "site.query_failed",
                    f"{label}: {exc}",
                )
            )
            continue

        current = policy.endpoint

        if current == new_endpoint:
            already += 1
            results.append(
                EndpointUpdateOutcome(
                    ip=tgt.ip,
                    name=tgt.name,
                    status="already-configured",
                    previous_endpoint=current,
                    new_endpoint=new_endpoint,
                )
            )
            sink.emit(
                ProgressEvent(
                    "info",
                    "site.already_configured",
                    f"{label}: already on {new_endpoint}",
                )
            )
            continue

        if expected_old_endpoint and current != expected_old_endpoint:
            failed += 1
            results.append(
                EndpointUpdateOutcome(
                    ip=tgt.ip,
                    name=tgt.name,
                    status="wrong-old-endpoint",
                    previous_endpoint=current,
                    new_endpoint=new_endpoint,
                    error=(f"current endpoint {current!r} != expected {expected_old_endpoint!r}"),
                )
            )
            sink.emit(
                ProgressEvent(
                    "warning",
                    "site.unexpected_endpoint",
                    f"{label}: current={current!r} != expected={expected_old_endpoint!r}; skipped",
                )
            )
            continue

        if not apply:
            results.append(
                EndpointUpdateOutcome(
                    ip=tgt.ip,
                    name=tgt.name,
                    status="planned",
                    previous_endpoint=current,
                    new_endpoint=new_endpoint,
                )
            )
            sink.emit(
                ProgressEvent(
                    "info",
                    "site.planned",
                    f"[DRY-RUN] {label}: {current} -> {new_endpoint}",
                )
            )
            continue

        try:
            wg.update_client_endpoint(new_endpoint, endpoint_port=new_endpoint_port)
            updated += 1
            results.append(
                EndpointUpdateOutcome(
                    ip=tgt.ip,
                    name=tgt.name,
                    status="updated",
                    previous_endpoint=current,
                    new_endpoint=new_endpoint,
                )
            )
            sink.emit(
                ProgressEvent(
                    "success",
                    "site.updated",
                    f"{label}: {current} -> {new_endpoint}",
                )
            )
        except (RuijieAuthError, RuijieWireGuardError) as exc:
            failed += 1
            results.append(
                EndpointUpdateOutcome(
                    ip=tgt.ip,
                    name=tgt.name,
                    status="failed",
                    previous_endpoint=current,
                    new_endpoint=new_endpoint,
                    error=str(exc),
                )
            )
            sink.emit(
                ProgressEvent(
                    "error",
                    "site.update_failed",
                    f"{label}: {exc}",
                )
            )

    sink.emit(
        ProgressEvent(
            "success" if (failed == 0 and unreachable == 0) else "warning",
            "workflow.done",
            (
                f"Done: updated={updated} already={already} "
                f"unreachable={unreachable} failed={failed}"
            ),
        )
    )

    return EndpointUpdateBatchResult(
        new_endpoint=new_endpoint,
        dry_run=not apply,
        sites_total=len(target_list),
        sites_updated=updated,
        sites_already_configured=already,
        sites_unreachable=unreachable,
        sites_failed=failed,
        results=results,
    )
