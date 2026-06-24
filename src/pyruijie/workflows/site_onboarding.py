"""Site-onboarding workflow: attach a new site to the WireGuard hub.

Formalises the logic from ``pyruijie.cli.cmd_onboard_site`` into a
progress-streaming, frozen-result function callable from the UniqueOS
GUI, scheduled jobs, or the new ``pyruijie workflow`` CLI.

Two modes:

* **hub-only** — add a peer entry to the hub server policy. The site
  gateway is configured out-of-band (manual, or via
  :func:`configure_site_client`).
* **hub+site** — do the hub add and then create the matching client
  policy on the site gateway.

Secrets policy
--------------
- Peer public keys and interface IPs appear in results and progress
  events (they are not secret).
- Preshared keys and site private keys are accepted as parameters but
  never appear in any result field or event.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from pyruijie.exceptions import (
    RuijieAuthError,
    RuijieWireGuardConflictError,
    RuijieWireGuardError,
)
from pyruijie.gateway import GatewayClient
from pyruijie.wireguard import WireGuardManager

from .exceptions import WorkflowPrecheckError
from .progress import NullProgressSink, ProgressEvent, ProgressSink


@dataclass(frozen=True)
class SiteOnboardingResult:
    """Aggregate outcome of a single-site onboarding run.

    Attributes:
        site_name: Human-readable identifier for the site.
        hub_host: Hub gateway host/IP that was mutated.
        server_uuid: Hub server-policy UUID the peer was added to.
        peer_ip: VPN interface IP allocated/assigned to the site.
        peer_desc: Peer description stored on the hub (typically
            ``"<site name> GW"``).
        hub_action: ``"added"`` | ``"already-exists"`` | ``"planned"``
            | ``"failed"``.
        site_action: ``"configured"`` | ``"planned"`` | ``"skipped"``
            | ``"failed"``. ``"skipped"`` means ``configure_site`` was
            ``False``.
        dry_run: ``True`` if no writes were performed.
        error: Orchestration-level error, empty on success.
    """

    site_name: str
    hub_host: str
    server_uuid: str = ""
    peer_ip: str = ""
    peer_desc: str = ""
    hub_action: str = "pending"
    site_action: str = "skipped"
    dry_run: bool = False
    error: str = ""

    @property
    def success(self) -> bool:
        if self.error:
            return False
        return self.hub_action != "failed" and self.site_action != "failed"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["success"] = self.success
        return d


def onboard_site(
    hub_manager: WireGuardManager,
    *,
    site_name: str,
    peer_pubkey: str,
    site_network: str,
    preferred_peer_ip: str | None = None,
    server_uuid: str | None = None,
    preshared_key: str = "",
    configure_site: bool = False,
    site_client: GatewayClient | None = None,
    site_private_key: str = "",
    site_policy_name: str = "US_WG",
    hub_endpoint: str | None = None,
    hub_endpoint_port: str = "51820",
    apply: bool = False,
    progress: ProgressSink | None = None,
) -> SiteOnboardingResult:
    """Onboard a new site to the hub WireGuard mesh.

    Args:
        hub_manager: :class:`WireGuardManager` wrapping an authenticated
            hub :class:`GatewayClient`.
        site_name: Display name used for the peer description.
        peer_pubkey: Public key of the site gateway's WireGuard
            interface. Never confused with a private key — this is
            safe to log/echo.
        site_network: CIDR of the VPN interface pool used to allocate
            ``peer_ip`` when ``preferred_peer_ip`` is not supplied
            (e.g. ``"10.100.0.0/20"``).
        preferred_peer_ip: Pin the peer to a specific IP if available.
        server_uuid: Target server policy UUID; ``None`` uses the
            default.
        preshared_key: Optional PSK. Never included in progress events
            or result fields.
        configure_site: If ``True``, also create a matching client
            policy on the site gateway. Requires ``site_client`` and
            ``site_private_key``.
        site_client: Authenticated site :class:`GatewayClient`. Only
            consulted when ``configure_site`` is ``True``.
        site_private_key: Site WireGuard private key. **Only used to
            post the policy to the site gateway; never included in any
            returned field or event.**
        site_policy_name: Client policy display name on the site.
        hub_endpoint: Public endpoint IP/DNS for the hub. Defaults to
            the hub client's ``host`` attribute.
        hub_endpoint_port: Hub UDP port (default ``"51820"``).
        apply: If ``False`` (default) probe and report only; no writes.
        progress: Optional :class:`ProgressSink` for streaming events.

    Returns:
        :class:`SiteOnboardingResult`.

    Raises:
        WorkflowPrecheckError: Invalid inputs (missing pubkey,
            configure_site without client/privkey, etc.).
    """
    sink: ProgressSink = progress or NullProgressSink()

    # ── prechecks ────────────────────────────────────────────────
    if not peer_pubkey:
        raise WorkflowPrecheckError("peer_pubkey is required")
    if not site_name:
        raise WorkflowPrecheckError("site_name is required")
    if configure_site:
        if site_client is None:
            raise WorkflowPrecheckError("configure_site=True requires site_client")
        if not site_private_key:
            raise WorkflowPrecheckError("configure_site=True requires site_private_key")

    hub_host = getattr(hub_manager.client, "host", "?")

    sink.emit(
        ProgressEvent(
            "info",
            "workflow.start",
            (
                f"Onboarding '{site_name}' to hub {hub_host} "
                f"({'DRY-RUN' if not apply else 'APPLY'})"
            ),
            context={
                "hub_host": hub_host,
                "site_name": site_name,
                "configure_site": configure_site,
                "apply": apply,
            },
        )
    )

    # ── fetch server policy & allocate IP ────────────────────────
    try:
        server = hub_manager.get_server_policy(server_uuid)
    except RuijieWireGuardError as exc:
        return SiteOnboardingResult(
            site_name=site_name,
            hub_host=hub_host,
            dry_run=not apply,
            error=f"get_server_policy failed: {exc}",
        )

    if preferred_peer_ip and any(p.ipaddr == preferred_peer_ip for p in server.peers):
        peer_ip = preferred_peer_ip  # Existing — idempotent path below.
    else:
        try:
            peer_ip = hub_manager.allocate_next_peer_ip(
                site_network,
                server.uuid,
                preferred=preferred_peer_ip,
            )
        except RuijieWireGuardError as exc:
            return SiteOnboardingResult(
                site_name=site_name,
                hub_host=hub_host,
                server_uuid=server.uuid,
                dry_run=not apply,
                error=f"allocate_next_peer_ip failed: {exc}",
            )

    peer_desc = hub_manager.suggest_policy_name(site_name, "GW")

    # ── hub step ─────────────────────────────────────────────────
    hub_action = "pending"
    existing_peer = server.find_peer(ip=peer_ip)
    if existing_peer:
        hub_action = "already-exists"
        sink.emit(
            ProgressEvent(
                "info",
                "hub.peer_exists",
                f"hub peer {peer_ip} already present as '{existing_peer.desc}'",
                context={"peer_ip": peer_ip, "existing_desc": existing_peer.desc},
            )
        )
    elif not apply:
        hub_action = "planned"
        sink.emit(
            ProgressEvent(
                "info",
                "hub.peer_planned",
                f"[DRY-RUN] would add hub peer '{peer_desc}' ({peer_ip})",
                context={"peer_ip": peer_ip, "peer_desc": peer_desc},
            )
        )
    else:
        try:
            hub_manager.add_site_peer(
                desc=peer_desc,
                interface_ip=peer_ip,
                peer_pubkey=peer_pubkey,
                preshared_key=preshared_key,
                server_uuid=server.uuid,
            )
            hub_action = "added"
            sink.emit(
                ProgressEvent(
                    "success",
                    "hub.peer_added",
                    f"hub peer '{peer_desc}' ({peer_ip}) added",
                    context={"peer_ip": peer_ip, "peer_desc": peer_desc},
                )
            )
        except RuijieWireGuardConflictError as exc:
            hub_action = "already-exists"
            sink.emit(
                ProgressEvent(
                    "warning",
                    "hub.peer_conflict",
                    f"hub peer conflict: {exc}",
                )
            )
        except RuijieWireGuardError as exc:
            sink.emit(ProgressEvent("error", "hub.peer_failed", f"hub add failed: {exc}"))
            return SiteOnboardingResult(
                site_name=site_name,
                hub_host=hub_host,
                server_uuid=server.uuid,
                peer_ip=peer_ip,
                peer_desc=peer_desc,
                hub_action="failed",
                site_action="skipped",
                dry_run=False,
                error=str(exc),
            )

    # ── site step ────────────────────────────────────────────────
    site_action = "skipped"
    if configure_site:
        if not apply:
            site_action = "planned"
            sink.emit(
                ProgressEvent(
                    "info",
                    "site.configure_planned",
                    f"[DRY-RUN] would configure site client policy on "
                    f"{getattr(site_client, 'host', '?')}",
                )
            )
        else:
            try:
                hub_manager.create_site_client_policy(
                    site_client,  # type: ignore[arg-type]
                    policy_name=site_policy_name,
                    hub_endpoint=hub_endpoint or hub_host,
                    hub_endpoint_port=hub_endpoint_port,
                    hub_pubkey=server.local_pubkey,
                    interface_ip=peer_ip,
                    local_privkey=site_private_key,
                    local_pubkey=peer_pubkey,
                    preshared_key=preshared_key,
                )
                site_action = "configured"
                sink.emit(
                    ProgressEvent(
                        "success",
                        "site.configured",
                        f"site client policy configured on {getattr(site_client, 'host', '?')}",
                    )
                )
            except (RuijieAuthError, RuijieWireGuardError) as exc:
                site_action = "failed"
                sink.emit(
                    ProgressEvent(
                        "error",
                        "site.configure_failed",
                        f"site configure failed: {exc}",
                    )
                )
                return SiteOnboardingResult(
                    site_name=site_name,
                    hub_host=hub_host,
                    server_uuid=server.uuid,
                    peer_ip=peer_ip,
                    peer_desc=peer_desc,
                    hub_action=hub_action,
                    site_action="failed",
                    dry_run=False,
                    error=str(exc),
                )

    sink.emit(
        ProgressEvent(
            "success",
            "workflow.done",
            f"'{site_name}' → {peer_ip}: hub={hub_action} site={site_action}",
        )
    )

    return SiteOnboardingResult(
        site_name=site_name,
        hub_host=hub_host,
        server_uuid=server.uuid,
        peer_ip=peer_ip,
        peer_desc=peer_desc,
        hub_action=hub_action,
        site_action=site_action,
        dry_run=not apply,
    )
