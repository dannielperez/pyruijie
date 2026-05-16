"""WireGuard hub peer management workflows.

Thin orchestration layer over :class:`pyruijie.WireGuardManager`. The
manager owns the LuCI transport; these workflows add ProgressSink
events, dry-run semantics, structured frozen-dataclass results, and
secret scrubbing so UniqueOS and scheduled jobs can call identical
code.

Nothing here reimplements gateway protocol logic — the existing
library is authoritative.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable

from pyruijie.exceptions import (
    RuijieWireGuardConflictError,
    RuijieWireGuardError,
)
from pyruijie.models import WireGuardPeer
from pyruijie.wireguard import WireGuardManager

from .exceptions import WorkflowError, WorkflowPrecheckError
from .progress import NullProgressSink, ProgressEvent, ProgressSink


@dataclass(frozen=True)
class PeerAddRequest:
    """Declarative input for one peer-add operation.

    Only the public key is ever transmitted to the hub; preshared keys
    are passed through but never echoed back in results or progress
    events.
    """

    desc: str
    interface_ip: str
    peer_pubkey: str
    preshared_key: str = ""  # Never included in to_dict output.
    allow_ips: tuple[str, ...] = ()

    def _allow_ips_list(self) -> list[str] | None:
        return list(self.allow_ips) if self.allow_ips else None


@dataclass(frozen=True)
class PeerAddOutcome:
    """Outcome of one ``add_site_peer`` attempt."""

    desc: str
    interface_ip: str
    status: str  # "added" | "already-exists" | "planned" | "failed"
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class PeerAddBatchResult:
    """Aggregate outcome of a batch peer-add run."""

    hub_host: str
    server_uuid: str
    dry_run: bool
    peers_total: int = 0
    peers_added: int = 0
    peers_skipped: int = 0
    peers_failed: int = 0
    results: list[PeerAddOutcome] = field(default_factory=list)
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error and self.peers_failed == 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["success"] = self.success
        return d


def add_hub_peers(
    manager: WireGuardManager,
    peers: Iterable[PeerAddRequest],
    *,
    server_uuid: str | None = None,
    apply: bool = False,
    progress: ProgressSink | None = None,
) -> PeerAddBatchResult:
    """Add one or more peers to the hub's WireGuard server policy.

    Idempotent: if a peer with the same interface IP already exists on
    the hub, that entry is reported as ``already-exists`` and skipped.

    Args:
        manager: A :class:`WireGuardManager` built from an authenticated
            hub :class:`~pyruijie.GatewayClient`.
        peers: Declarative peer add requests. Preshared keys are
            passed to the manager but never returned in results.
        server_uuid: Target server policy UUID. ``None`` uses the
            default/first server on the hub.
        apply: If ``False`` (default), report what would happen
            without mutating the hub.
        progress: Optional sink for streaming step events.

    Returns:
        :class:`PeerAddBatchResult` with per-peer outcomes. Per-peer
        failures are recorded — orchestration errors (login, server
        lookup) are surfaced via the ``error`` field.

    Raises:
        WorkflowPrecheckError: Invalid peer inputs (e.g. missing
            pubkey).
    """
    sink: ProgressSink = progress or NullProgressSink()
    peer_list = list(peers)

    for p in peer_list:
        if not p.peer_pubkey:
            raise WorkflowPrecheckError(
                f"peer '{p.desc}' ({p.interface_ip}) missing public key"
            )
        if not p.interface_ip:
            raise WorkflowPrecheckError(
                f"peer '{p.desc}' missing interface_ip"
            )

    hub_host = getattr(manager.client, "host", "?")

    try:
        server = manager.get_server_policy(server_uuid)
    except RuijieWireGuardError as exc:
        return PeerAddBatchResult(
            hub_host=hub_host,
            server_uuid=server_uuid or "",
            dry_run=not apply,
            peers_total=len(peer_list),
            error=f"get_server_policy failed: {exc}",
        )

    existing_ips = {p.ipaddr for p in server.peers}

    sink.emit(
        ProgressEvent(
            level="info",
            code="workflow.start",
            message=(
                f"Adding {len(peer_list)} peer(s) to hub {hub_host} "
                f"(server {server.desc}, "
                f"{'DRY-RUN' if not apply else 'APPLY'})"
            ),
            context={
                "hub_host": hub_host,
                "server_uuid": server.uuid,
                "peers_in_scope": len(peer_list),
                "apply": apply,
            },
        )
    )

    results: list[PeerAddOutcome] = []
    added = skipped = failed = 0

    for req in peer_list:
        if req.interface_ip in existing_ips:
            results.append(
                PeerAddOutcome(
                    desc=req.desc,
                    interface_ip=req.interface_ip,
                    status="already-exists",
                )
            )
            skipped += 1
            sink.emit(
                ProgressEvent(
                    "info", "peer.exists",
                    f"{req.desc} ({req.interface_ip}): already on hub",
                    context={"desc": req.desc, "interface_ip": req.interface_ip},
                )
            )
            continue

        if not apply:
            results.append(
                PeerAddOutcome(
                    desc=req.desc,
                    interface_ip=req.interface_ip,
                    status="planned",
                )
            )
            sink.emit(
                ProgressEvent(
                    "info", "peer.planned",
                    f"[DRY-RUN] would add {req.desc} ({req.interface_ip})",
                    context={"desc": req.desc, "interface_ip": req.interface_ip},
                )
            )
            continue

        try:
            manager.add_site_peer(
                desc=req.desc,
                interface_ip=req.interface_ip,
                peer_pubkey=req.peer_pubkey,
                preshared_key=req.preshared_key,
                allow_ips=req._allow_ips_list(),
                server_uuid=server.uuid,
            )
            results.append(
                PeerAddOutcome(
                    desc=req.desc,
                    interface_ip=req.interface_ip,
                    status="added",
                )
            )
            added += 1
            existing_ips.add(req.interface_ip)
            sink.emit(
                ProgressEvent(
                    "success", "peer.added",
                    f"{req.desc} ({req.interface_ip}) added",
                    context={"desc": req.desc, "interface_ip": req.interface_ip},
                )
            )
        except RuijieWireGuardConflictError as exc:
            results.append(
                PeerAddOutcome(
                    desc=req.desc,
                    interface_ip=req.interface_ip,
                    status="already-exists",
                    error=str(exc),
                )
            )
            skipped += 1
            sink.emit(
                ProgressEvent(
                    "warning", "peer.conflict",
                    f"{req.desc} ({req.interface_ip}): {exc}",
                )
            )
        except RuijieWireGuardError as exc:
            results.append(
                PeerAddOutcome(
                    desc=req.desc,
                    interface_ip=req.interface_ip,
                    status="failed",
                    error=str(exc),
                )
            )
            failed += 1
            sink.emit(
                ProgressEvent(
                    "error", "peer.failed",
                    f"{req.desc} ({req.interface_ip}): {exc}",
                )
            )

    sink.emit(
        ProgressEvent(
            "success" if failed == 0 else "warning",
            "workflow.done",
            f"Done: added={added} skipped={skipped} failed={failed}",
            context={"added": added, "skipped": skipped, "failed": failed},
        )
    )

    return PeerAddBatchResult(
        hub_host=hub_host,
        server_uuid=server.uuid,
        dry_run=not apply,
        peers_total=len(peer_list),
        peers_added=added,
        peers_skipped=skipped,
        peers_failed=failed,
        results=results,
    )
