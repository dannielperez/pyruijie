"""Drift-detection workflow: compare hub-declared state to site reality.

Wraps :meth:`pyruijie.WireGuardManager.detect_drift` with a
multi-site, progress-streaming orchestrator that returns a frozen
structured result. The underlying manager still owns the diff logic.

This workflow is **strictly read-only** — it never mutates the hub or
any site and therefore has no ``apply`` flag.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from pyruijie.exceptions import RuijieAuthError, RuijieWireGuardError
from pyruijie.gateway import GatewayClient
from pyruijie.models import WireGuardPeer
from pyruijie.wireguard import DriftReport, WireGuardManager

from .progress import NullProgressSink, ProgressEvent, ProgressSink

SiteClientFactory = Callable[[str], GatewayClient]
"""Callable that produces an authenticated :class:`GatewayClient` for
a site IP. The caller supplies this to avoid hard-coding credential
handling inside the workflow."""


@dataclass(frozen=True)
class PeerDriftOutcome:
    """Per-peer diff outcome, suitable for GUI tables and JSON export."""

    peer_desc: str
    peer_ip: str
    reachable: bool
    has_drift: bool
    drift_fields: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DriftScanResult:
    """Aggregate outcome of a hub-wide drift scan."""

    hub_host: str
    server_uuid: str
    peers_total: int = 0
    peers_unreachable: int = 0
    peers_in_drift: int = 0
    results: list[PeerDriftOutcome] = field(default_factory=list)
    error: str = ""

    @property
    def success(self) -> bool:
        """Scan itself completed; presence of drift does NOT fail the scan."""
        return not self.error

    @property
    def ok(self) -> bool:
        """No drift and no unreachable peers."""
        return not self.error and self.peers_in_drift == 0 and self.peers_unreachable == 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ok"] = self.ok
        d["success"] = self.success
        return d


def _drift_fields(report: DriftReport) -> list[str]:
    return [d.field for d in report.drifts]


def detect_hub_drift(
    hub_manager: WireGuardManager,
    *,
    site_client_factory: SiteClientFactory,
    server_uuid: str | None = None,
    expected_endpoint: str | None = None,
    peer_filter: list[str] | None = None,
    progress: ProgressSink | None = None,
) -> DriftScanResult:
    """Scan every hub peer and report configuration drift at the site.

    Args:
        hub_manager: :class:`WireGuardManager` over an authenticated hub.
        site_client_factory: Called with a site IP; must return an
            authenticated :class:`GatewayClient` for that site. Raising
            any exception is treated as an unreachable site.
        server_uuid: Target hub server policy UUID, ``None`` = default.
        expected_endpoint: Expected hub endpoint on the site side. If
            given, drift in ``endpoint`` is flagged.
        peer_filter: Optional list of peer IPs; only those are scanned.
            ``None`` scans all peers.
        progress: Optional sink for streaming events.

    Returns:
        :class:`DriftScanResult`. Individual site connection/auth
        failures are recorded per-peer and do NOT cause the scan to
        raise.
    """
    sink: ProgressSink = progress or NullProgressSink()
    hub_host = getattr(hub_manager.client, "host", "?")

    try:
        policy = hub_manager.get_server_policy(server_uuid)
    except RuijieWireGuardError as exc:
        return DriftScanResult(
            hub_host=hub_host,
            server_uuid=server_uuid or "",
            error=f"get_server_policy failed: {exc}",
        )

    peers: list[WireGuardPeer] = list(policy.peers)
    if peer_filter is not None:
        wanted = set(peer_filter)
        peers = [p for p in peers if p.ipaddr in wanted]

    sink.emit(
        ProgressEvent(
            "info",
            "workflow.start",
            f"Drift scan on {hub_host}: {len(peers)} peer(s) in scope",
            context={"hub_host": hub_host, "peers_in_scope": len(peers)},
        )
    )

    outcomes: list[PeerDriftOutcome] = []
    unreachable = in_drift = 0

    for peer in peers:
        # Site connection is caller-controlled — they may skip or time out
        # however they like via their factory.
        try:
            site = site_client_factory(peer.ipaddr)
        except Exception as exc:  # noqa: BLE001 — caller-supplied factory
            unreachable += 1
            outcomes.append(
                PeerDriftOutcome(
                    peer_desc=peer.desc,
                    peer_ip=peer.ipaddr,
                    reachable=False,
                    has_drift=False,
                    error=f"site connect failed: {exc}",
                )
            )
            sink.emit(
                ProgressEvent(
                    "warning",
                    "peer.unreachable",
                    f"{peer.desc} ({peer.ipaddr}): unreachable — {exc}",
                )
            )
            continue

        try:
            site_wg = WireGuardManager(site)
            client_policy = site_wg.get_client_policy()
            report = hub_manager.detect_drift(
                peer,
                client_policy,
                expected_endpoint=expected_endpoint,
            )
        except (RuijieAuthError, RuijieWireGuardError) as exc:
            unreachable += 1
            outcomes.append(
                PeerDriftOutcome(
                    peer_desc=peer.desc,
                    peer_ip=peer.ipaddr,
                    reachable=False,
                    has_drift=False,
                    error=str(exc),
                )
            )
            sink.emit(
                ProgressEvent(
                    "warning",
                    "peer.query_failed",
                    f"{peer.desc} ({peer.ipaddr}): {exc}",
                )
            )
            continue

        drift_fields = _drift_fields(report)
        if report.has_drift:
            in_drift += 1
            sink.emit(
                ProgressEvent(
                    "warning",
                    "peer.drift",
                    f"{peer.desc} ({peer.ipaddr}): drift in {', '.join(drift_fields)}",
                    context={"peer_ip": peer.ipaddr, "fields": drift_fields},
                )
            )
        else:
            sink.emit(
                ProgressEvent(
                    "success",
                    "peer.in_sync",
                    f"{peer.desc} ({peer.ipaddr}): in sync",
                )
            )

        outcomes.append(
            PeerDriftOutcome(
                peer_desc=peer.desc,
                peer_ip=peer.ipaddr,
                reachable=True,
                has_drift=report.has_drift,
                drift_fields=drift_fields,
            )
        )

    sink.emit(
        ProgressEvent(
            "success" if (unreachable == 0 and in_drift == 0) else "warning",
            "workflow.done",
            f"Scan complete: drift={in_drift} unreachable={unreachable} total={len(peers)}",
        )
    )

    return DriftScanResult(
        hub_host=hub_host,
        server_uuid=policy.uuid,
        peers_total=len(peers),
        peers_unreachable=unreachable,
        peers_in_drift=in_drift,
        results=outcomes,
    )
