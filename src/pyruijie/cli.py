"""pyruijie CLI — WireGuard VPN management for Ruijie/Reyee gateways.

Entry point::

    python -m pyruijie --help
    python -m pyruijie peers list
    python -m pyruijie onboard-site --site-name "Site Delta" ...
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pyruijie.exceptions import (
    RuijieAuthError,
    RuijieWireGuardConflictError,
    RuijieWireGuardError,
    RuijieWireGuardValidationError,
)
from pyruijie.gateway import GatewayClient
from pyruijie.models import WireGuardClientPolicy, WireGuardPeer, WireGuardServerPolicy
from pyruijie.wireguard import DriftReport, WireGuardManager

logger = logging.getLogger(__name__)


# ── Structured result models ──────────────────────────────────────────


@dataclass
class WireGuardSiteLink:
    """Represents one side of a hub↔site WireGuard link."""

    host: str
    role: str  # "hub" or "site"
    peer_ip: str
    pubkey: str
    policy_uuid: str = ""
    policy_name: str = ""


@dataclass
class OnboardingResult:
    """Full result of an onboard-site operation."""

    site_name: str
    success: bool = False
    hub_link: WireGuardSiteLink | None = None
    site_link: WireGuardSiteLink | None = None
    peer_ip: str = ""
    error: str = ""
    dry_run: bool = False
    steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def summary(self) -> str:
        if not self.success:
            return f"FAILED: {self.site_name} — {self.error}"
        prefix = "[DRY-RUN] " if self.dry_run else ""
        return f"{prefix}OK: {self.site_name} → {self.peer_ip}"


@dataclass
class EndpointUpdateResult:
    """Result of updating WireGuard client endpoint on site gateways."""

    ip: str
    name: str
    success: bool
    action: str = ""  # "updated", "already_configured", "needs_update"
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Environment / credential helpers ─────────────────────────────────


def _load_dotenv(env_file: Path | None = None) -> None:
    """Load .env file into os.environ (simple key=value, no override)."""
    if env_file is None:
        candidates = [Path.cwd() / ".env", Path(__file__).resolve().parents[4] / ".env"]
        for p in candidates:
            if p.is_file():
                env_file = p
                break
    if env_file is None or not env_file.is_file():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


def _hub_credentials() -> tuple[str, str, str]:
    """Return (host, username, password) for the hub gateway from env.

    Reads UNIQUE_GW_IP / UNIQUE_GW_USERNAME / UNIQUE_GW_PASSWORD.
    Falls back to legacy R_USCC_GW_* names for backwards compatibility.
    """
    host = os.environ.get("UNIQUE_GW_IP") or os.environ.get("R_USCC_GW_IP", "")
    user = os.environ.get("UNIQUE_GW_USERNAME") or os.environ.get("R_USCC_GW_USERNAME", "admin")
    pw = os.environ.get("UNIQUE_GW_PASSWORD") or os.environ.get("R_USCC_GW_PASSWORD", "")
    if not host:
        _die("UNIQUE_GW_IP not set (hub gateway IP)")
    if not pw:
        _die("UNIQUE_GW_PASSWORD not set")
    return host, user, pw


def _connect_gateway(host: str, username: str, password: str) -> GatewayClient:
    """Create and authenticate a GatewayClient."""
    gw = GatewayClient(host, username, password)
    gw.login()
    return gw


def _die(msg: str, code: int = 1) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(code)


# ── Peer commands ─────────────────────────────────────────────────────


def cmd_peers_list(args: argparse.Namespace) -> None:
    """List all WireGuard peers on the hub server policy."""
    _load_dotenv()
    host, user, pw = _hub_credentials()
    gw = _connect_gateway(host, user, pw)
    wg = WireGuardManager(gw)

    policy = wg.get_server_policy(args.server_uuid)
    peers = policy.peers

    if args.json:
        print(json.dumps([p.to_dict() for p in peers], indent=2))
        return

    print(f"Server: {policy.desc} ({policy.local_addr})")
    print(f"Peers: {len(peers)}\n")
    for p in peers:
        status = ""
        if p.endpoint:
            status = f"  endpoint={p.endpoint}"
        if p.rx_bytes or p.tx_bytes:
            status += f"  rx={p.rx_bytes} tx={p.tx_bytes}"
        print(f"  {p.desc:<45} {p.ipaddr:<18}{status}")


def cmd_peers_add(args: argparse.Namespace) -> None:
    """Add a WireGuard peer to the hub server policy."""
    _load_dotenv()
    host, user, pw = _hub_credentials()

    if args.dry_run:
        print(f"[DRY-RUN] Would add peer: {args.desc} ({args.ip})")
        print(f"  pubkey: {args.pubkey}")
        return

    if not args.yes:
        _confirm(f"Add peer '{args.desc}' ({args.ip}) to hub?")

    gw = _connect_gateway(host, user, pw)
    wg = WireGuardManager(gw)

    peer = wg.add_site_peer(
        desc=args.desc,
        interface_ip=args.ip,
        peer_pubkey=args.pubkey,
        preshared_key=args.psk or "",
        server_uuid=args.server_uuid,
    )
    print(f"OK: Added peer '{peer.desc}' ({peer.ipaddr})")


def cmd_peers_remove(args: argparse.Namespace) -> None:
    """Remove a WireGuard peer from the hub server policy."""
    _load_dotenv()
    host, user, pw = _hub_credentials()

    if args.dry_run:
        print(f"[DRY-RUN] Would remove peer: ip={args.ip}")
        return

    if not args.yes:
        _confirm(f"Remove peer with IP {args.ip} from hub?")

    gw = _connect_gateway(host, user, pw)
    wg = WireGuardManager(gw)
    wg.delete_peer(ip=args.ip, server_uuid=args.server_uuid)
    print(f"OK: Removed peer {args.ip}")


def cmd_peers_rename(args: argparse.Namespace) -> None:
    """Rename WireGuard peers on the hub server policy."""
    _load_dotenv()
    host, user, pw = _hub_credentials()

    # Load name map from JSON file
    name_map = json.loads(Path(args.map_file).read_text())
    if not isinstance(name_map, dict):
        _die("Map file must be a JSON object {old_name: new_name}")

    if args.dry_run:
        print(f"[DRY-RUN] Would rename {len(name_map)} peers:")
        for old, new in name_map.items():
            print(f"  {old:<45} → {new}")
        return

    if not args.yes:
        _confirm(f"Rename {len(name_map)} peers on hub?")

    gw = _connect_gateway(host, user, pw)
    wg = WireGuardManager(gw)
    count = wg.rename_peers(name_map, server_uuid=args.server_uuid)
    print(f"OK: Renamed {count} peers")


# ── Site probe command ────────────────────────────────────────────────


def cmd_probe(args: argparse.Namespace) -> None:
    """Probe a site gateway's WireGuard configuration."""
    _load_dotenv()
    user = os.environ.get("UNIQUE_GW_USERNAME") or os.environ.get("R_USCC_GW_USERNAME", "admin")
    pw = os.environ.get("UNIQUE_GW_PASSWORD") or os.environ.get("R_USCC_GW_PASSWORD", "")
    if not pw:
        _die("UNIQUE_GW_PASSWORD not set")

    gw = _connect_gateway(args.ip, user, pw)
    wg = WireGuardManager(gw)

    print(f"Gateway: {args.ip} (SN: {gw.serial_number})")

    # Client policies
    try:
        clients = wg.list_client_policies()
        print(f"\nClient policies: {len(clients)}")
        for c in clients:
            ep = f"{c.endpoint}:{c.endpoint_port}" if c.endpoint else "(none)"
            print(f"  {c.desc:<30} addr={c.local_addr:<20} endpoint={ep}")
    except Exception as e:
        print(f"\nClient policies: error — {e}")

    # Server policies
    try:
        servers = wg.list_server_policies()
        print(f"\nServer policies: {len(servers)}")
        for s in servers:
            print(f"  {s.desc:<30} addr={s.local_addr:<20} peers={len(s.peers)}")
    except Exception as e:
        print(f"\nServer policies: error — {e}")

    if args.json:
        result = {"host": args.ip, "serial_number": gw.serial_number}
        try:
            result["client_policies"] = [c.to_dict() for c in wg.list_client_policies()]
        except Exception:
            result["client_policies"] = []
        try:
            result["server_policies"] = [s.to_dict() for s in wg.list_server_policies()]
        except Exception:
            result["server_policies"] = []
        print(json.dumps(result, indent=2))


# ── Endpoint update command ───────────────────────────────────────────


def cmd_update_endpoint(args: argparse.Namespace) -> None:
    """Update WireGuard client endpoint on one or more site gateways."""
    _load_dotenv()
    user = os.environ.get("UNIQUE_GW_USERNAME") or os.environ.get("R_USCC_GW_USERNAME", "admin")
    pw = os.environ.get("UNIQUE_GW_PASSWORD") or os.environ.get("R_USCC_GW_PASSWORD", "")
    if not pw:
        _die("UNIQUE_GW_PASSWORD not set")

    targets: list[dict[str, str]] = []
    if args.targets:
        targets = [{"ip": ip, "name": ip} for ip in args.targets]
    elif args.from_file:
        data = json.loads(Path(args.from_file).read_text())
        if isinstance(data, list):
            targets = [{"ip": d.get("ip", d.get("interface_ip", "")), "name": d.get("name", d.get("username", ""))} for d in data]
        else:
            _die("--from-file must contain a JSON array")
    else:
        _die("Specify target IPs or --from-file")

    if not targets:
        _die("No targets found")

    mode = "APPLY" if not args.dry_run else "DRY-RUN"
    print(f"[{mode}] Updating endpoint on {len(targets)} site gateways")
    print(f"  New endpoint: {args.new_endpoint}")
    if args.old_endpoint:
        print(f"  Old endpoint: {args.old_endpoint} (filter)")
    print()

    results: list[EndpointUpdateResult] = []
    for t in targets:
        r = _update_single_endpoint(
            ip=t["ip"],
            name=t["name"],
            new_endpoint=args.new_endpoint,
            old_endpoint=args.old_endpoint,
            username=user,
            password=pw,
            dry_run=args.dry_run,
        )
        results.append(r)
        status = "OK" if r.success else "FAIL"
        detail = r.action or r.error
        print(f"  [{status}] {r.ip:>18}  {r.name:<40} {detail}")

    ok = sum(1 for r in results if r.success)
    fail = sum(1 for r in results if not r.success)
    print(f"\nDone — OK: {ok}, Failed: {fail}")

    if args.output:
        out = Path(args.output)
        out.write_text(json.dumps([r.to_dict() for r in results], indent=2))
        print(f"Results saved to {out}")


def _update_single_endpoint(
    *,
    ip: str,
    name: str,
    new_endpoint: str,
    old_endpoint: str | None,
    username: str,
    password: str,
    dry_run: bool,
) -> EndpointUpdateResult:
    """Update endpoint on a single site gateway."""
    try:
        gw = _connect_gateway(ip, username, password)
    except (RuijieAuthError, Exception) as e:
        return EndpointUpdateResult(ip=ip, name=name, success=False, error=f"Login failed: {e}")

    wg = WireGuardManager(gw)
    try:
        policy = wg.get_client_policy()
    except RuijieWireGuardError as e:
        return EndpointUpdateResult(ip=ip, name=name, success=False, error=str(e))

    if policy.endpoint == new_endpoint:
        return EndpointUpdateResult(ip=ip, name=name, success=True, action="already_configured")

    if old_endpoint and policy.endpoint != old_endpoint:
        return EndpointUpdateResult(
            ip=ip, name=name, success=False,
            error=f"Unexpected endpoint: {policy.endpoint}",
        )

    if dry_run:
        return EndpointUpdateResult(ip=ip, name=name, success=True, action="needs_update")

    try:
        wg.update_client_endpoint(new_endpoint)
        return EndpointUpdateResult(ip=ip, name=name, success=True, action="updated")
    except Exception as e:
        return EndpointUpdateResult(ip=ip, name=name, success=False, error=str(e))


# ── Drift detection command ───────────────────────────────────────────


def cmd_drift(args: argparse.Namespace) -> None:
    """Detect configuration drift between hub and site gateways."""
    _load_dotenv()
    host, user, pw = _hub_credentials()
    hub = _connect_gateway(host, user, pw)
    hub_wg = WireGuardManager(hub)

    policy = hub_wg.get_server_policy(args.server_uuid)
    target_peers = policy.peers

    if args.peer_ip:
        target_peers = [p for p in target_peers if p.ipaddr in args.peer_ip]
        if not target_peers:
            _die(f"No peers found for IPs: {args.peer_ip}")

    reports: list[DriftReport] = []
    for peer in target_peers:
        try:
            site = _connect_gateway(peer.ipaddr, user, pw)
            site_wg = WireGuardManager(site)
            client = site_wg.get_client_policy()
            report = hub_wg.detect_drift(peer, client, expected_endpoint=args.expected_endpoint)
            reports.append(report)
            print(report)
        except Exception as e:
            print(f"{peer.desc} ({peer.ipaddr}): error — {e}")

    drifted = sum(1 for r in reports if r.has_drift)
    print(f"\n{len(reports)} peers checked, {drifted} with drift")


# ── Onboard site command ─────────────────────────────────────────────


def cmd_onboard_site(args: argparse.Namespace) -> None:
    """Onboard a new site: add hub peer + configure site client policy."""
    _load_dotenv()
    host, user, pw = _hub_credentials()

    result = OnboardingResult(site_name=args.site_name, dry_run=args.dry_run)

    # Validate required args
    if not args.site_ip:
        _die("--site-ip required (site gateway VPN/management IP)")
    if not args.pubkey:
        _die("--pubkey required (site gateway WireGuard public key)")

    try:
        # Step 1: Connect to hub
        result.steps.append("Connecting to hub gateway...")
        hub = _connect_gateway(host, user, pw)
        hub_wg = WireGuardManager(hub)

        # Step 2: Determine peer IP
        server = hub_wg.get_server_policy(args.server_uuid)
        if args.peer_ip:
            peer_ip = args.peer_ip
        else:
            network = server.local_addr.replace(
                server.local_addr.split("/")[0].rsplit(".", 1)[-1],
                "0",
            )
            peer_ip = hub_wg.allocate_next_peer_ip(
                network, args.server_uuid
            )

        result.peer_ip = peer_ip
        desc = hub_wg.suggest_policy_name(args.site_name, "GW")

        # Check idempotency — peer already exists?
        existing = server.find_peer(ip=peer_ip)
        if existing:
            print(f"Peer {peer_ip} already exists as '{existing.desc}' — skipping hub add")
            result.steps.append(f"Hub peer already exists: {existing.desc}")
        else:
            result.steps.append(f"Adding hub peer: {desc} → {peer_ip}")

            if args.dry_run:
                print(f"[DRY-RUN] Would add hub peer: {desc} ({peer_ip})")
            else:
                if not args.yes:
                    _confirm(f"Add peer '{desc}' ({peer_ip}) to hub server?")
                hub_wg.add_site_peer(
                    desc=desc,
                    interface_ip=peer_ip,
                    peer_pubkey=args.pubkey,
                    preshared_key=args.psk or "",
                    server_uuid=args.server_uuid,
                )
                print(f"OK: Hub peer added — {desc} ({peer_ip})")

        result.hub_link = WireGuardSiteLink(
            host=host,
            role="hub",
            peer_ip=peer_ip,
            pubkey=args.pubkey,
            policy_uuid=server.uuid,
            policy_name=server.desc,
        )

        # Step 3: Configure site client policy (if --configure-site)
        if args.configure_site:
            result.steps.append("Configuring site client policy...")

            if not args.site_privkey:
                _die("--site-privkey required when --configure-site is set")

            if args.dry_run:
                print(f"[DRY-RUN] Would configure site {args.site_ip} with client policy")
            else:
                if not args.yes:
                    _confirm(f"Configure WireGuard client on site {args.site_ip}?")

                site = _connect_gateway(args.site_ip, user, pw)
                hub_wg.create_site_client_policy(
                    site,
                    policy_name=args.policy_name or "WG_CLIENT",
                    hub_endpoint=args.hub_endpoint or host,
                    hub_endpoint_port=args.hub_port or "51820",
                    hub_pubkey=server.local_pubkey,
                    interface_ip=peer_ip,
                    local_privkey=args.site_privkey,
                    local_pubkey=args.pubkey,
                    preshared_key=args.psk or "",
                )
                print(f"OK: Site client policy configured on {args.site_ip}")

            result.site_link = WireGuardSiteLink(
                host=args.site_ip,
                role="site",
                peer_ip=peer_ip,
                pubkey=server.local_pubkey,
            )

        result.success = True

    except RuijieWireGuardConflictError as e:
        result.error = str(e)
        print(f"Conflict: {e}")
    except RuijieWireGuardError as e:
        result.error = str(e)
        print(f"WireGuard error: {e}")
    except RuijieAuthError as e:
        result.error = str(e)
        print(f"Auth error: {e}")
    except Exception as e:
        result.error = str(e)
        print(f"Error: {e}")

    # Summary
    print(f"\n{result.summary()}")
    for step in result.steps:
        print(f"  • {step}")

    if args.output:
        Path(args.output).write_text(json.dumps(result.to_dict(), indent=2))
        print(f"\nResult saved to {args.output}")


# ── Confirmation helper ───────────────────────────────────────────────


def _confirm(prompt: str) -> None:
    """Ask for user confirmation, exit on 'n'."""
    try:
        answer = input(f"{prompt} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    if answer not in ("y", "yes"):
        print("Aborted.")
        sys.exit(0)


# ── Argument parser ───────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyruijie",
        description="WireGuard VPN management for Ruijie/Reyee gateways",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--env-file", type=str, default=None,
        help="Path to .env file (default: auto-detect)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── peers ──────────────────────────────────────────────────────
    peers = sub.add_parser("peers", help="Manage hub WireGuard peers")
    peers_sub = peers.add_subparsers(dest="peers_action", required=True)

    # peers list
    pl = peers_sub.add_parser("list", help="List all peers")
    pl.add_argument("--json", action="store_true", help="Output as JSON")
    pl.add_argument("--server-uuid", default=None, help="Server policy UUID")
    pl.set_defaults(func=cmd_peers_list)

    # peers add
    pa = peers_sub.add_parser("add", help="Add a peer to the hub")
    pa.add_argument("--desc", required=True, help="Peer description / site name")
    pa.add_argument("--ip", required=True, help="VPN IP for the peer")
    pa.add_argument("--pubkey", required=True, help="Peer public key")
    pa.add_argument("--psk", default=None, help="Pre-shared key")
    pa.add_argument("--server-uuid", default=None)
    pa.add_argument("--dry-run", action="store_true")
    pa.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    pa.set_defaults(func=cmd_peers_add)

    # peers remove
    pr = peers_sub.add_parser("remove", help="Remove a peer from the hub")
    pr.add_argument("--ip", required=True, help="Peer VPN IP to remove")
    pr.add_argument("--server-uuid", default=None)
    pr.add_argument("--dry-run", action="store_true")
    pr.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    pr.set_defaults(func=cmd_peers_remove)

    # peers rename
    prn = peers_sub.add_parser("rename", help="Rename peers from JSON map")
    prn.add_argument("map_file", help="JSON file: {old_name: new_name}")
    prn.add_argument("--server-uuid", default=None)
    prn.add_argument("--dry-run", action="store_true")
    prn.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    prn.set_defaults(func=cmd_peers_rename)

    # ── probe ──────────────────────────────────────────────────────
    probe = sub.add_parser("probe", help="Probe a site gateway's WireGuard config")
    probe.add_argument("ip", help="Site gateway IP")
    probe.add_argument("--json", action="store_true")
    probe.set_defaults(func=cmd_probe)

    # ── update-endpoint ────────────────────────────────────────────
    ue = sub.add_parser("update-endpoint", help="Update WG client endpoint on site gateways")
    ue.add_argument("targets", nargs="*", help="Site gateway VPN IPs")
    ue.add_argument("--from-file", help="JSON file with targets")
    ue.add_argument("--new-endpoint", required=True, help="New endpoint address")
    ue.add_argument("--old-endpoint", default=None, help="Only update if current endpoint matches")
    ue.add_argument("--output", "-o", help="Save results to JSON file")
    ue.add_argument("--dry-run", action="store_true")
    ue.set_defaults(func=cmd_update_endpoint)

    # ── drift ──────────────────────────────────────────────────────
    dr = sub.add_parser("drift", help="Detect config drift between hub and sites")
    dr.add_argument("--peer-ip", nargs="*", help="Specific peer IPs to check")
    dr.add_argument("--server-uuid", default=None)
    dr.add_argument("--expected-endpoint", default=None)
    dr.set_defaults(func=cmd_drift)

    # ── onboard-site ──────────────────────────────────────────────
    ob = sub.add_parser("onboard-site", help="Onboard a new site (hub peer + site config)")
    ob.add_argument("--site-name", required=True, help="Human-readable site name")
    ob.add_argument("--site-ip", required=True, help="Site gateway management/VPN IP")
    ob.add_argument("--pubkey", required=True, help="Site gateway WireGuard public key")
    ob.add_argument("--peer-ip", default=None, help="VPN IP (auto-allocate if omitted)")
    ob.add_argument("--psk", default=None, help="Pre-shared key")
    ob.add_argument("--server-uuid", default=None)
    ob.add_argument("--configure-site", action="store_true",
                    help="Also configure the WireGuard client policy on the site gateway")
    ob.add_argument("--site-privkey", default=None,
                    help="Site gateway WireGuard private key (required with --configure-site)")
    ob.add_argument("--hub-endpoint", default=None, help="Hub endpoint (IP or domain)")
    ob.add_argument("--hub-port", default="51820", help="Hub WireGuard port")
    ob.add_argument("--policy-name", default=None, help="Client policy name (default: WG_CLIENT)")
    ob.add_argument("--output", "-o", help="Save result to JSON file")
    ob.add_argument("--dry-run", action="store_true")
    ob.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    ob.set_defaults(func=cmd_onboard_site)

    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")

    if args.env_file:
        _load_dotenv(Path(args.env_file))
    else:
        _load_dotenv()

    args.func(args)
