"""CLI dispatcher for ``pyruijie workflow <name>`` subcommands.

Mirrors :mod:`pytvt.workflow_cli` to give technicians a consistent
idiom across vendors. Supplies env-driven credential defaults
(``UNIQUE_GW_USERNAME`` / ``UNIQUE_GW_PASSWORD``) to keep CLI
invocations short and avoid passing passwords on the command line.

Existing ``pyruijie`` CLI subcommands (peers, probe, drift,
onboard-site, update-endpoint) remain untouched — this is an additive
namespace suitable for scheduled jobs and UniqueOS automation.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence

from .gateway import GatewayClient
from .wireguard import WireGuardManager
from .workflows import (
    ConsoleProgressSink,
    EndpointTarget,
    PeerAddRequest,
    WorkflowError,
    WorkflowPrecheckError,
    add_hub_peers,
    detect_hub_drift,
    onboard_site,
    update_site_endpoints,
)


def _hub_credentials() -> tuple[str, str, str]:
    """Pull hub host + admin creds from environment."""
    host = os.environ.get("UNIQUE_HUB_HOST") or os.environ.get("R_HUB_HOST", "")
    user = os.environ.get("UNIQUE_GW_USERNAME") or os.environ.get("R_USCC_GW_USERNAME", "admin")
    pw = os.environ.get("UNIQUE_GW_PASSWORD") or os.environ.get("R_USCC_GW_PASSWORD", "")
    return host, user, pw


def _site_credentials() -> tuple[str, str]:
    """Pull shared site-gateway admin creds from environment."""
    user = os.environ.get("UNIQUE_GW_USERNAME") or os.environ.get("R_USCC_GW_USERNAME", "admin")
    pw = os.environ.get("UNIQUE_GW_PASSWORD") or os.environ.get("R_USCC_GW_PASSWORD", "")
    return user, pw


def _connect_gateway(host: str, username: str, password: str) -> GatewayClient:
    gw = GatewayClient(host=host, username=username, password=password)
    gw.login()
    return gw


def _die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def workflow_cli(argv: Sequence[str] | None = None) -> None:
    """Dispatch ``pyruijie workflow <name> ...`` subcommands."""
    parser = argparse.ArgumentParser(
        prog="pyruijie workflow",
        description="Technician-facing multi-step operations against Ruijie gateways.",
    )
    sub = parser.add_subparsers(dest="name", required=True)

    ob = sub.add_parser(
        "onboard-site",
        help="Add a new site peer to the hub (and optionally configure the site).",
    )
    ob.add_argument("--site-name", required=True)
    ob.add_argument("--peer-pubkey", required=True, help="Site gateway's WireGuard public key.")
    ob.add_argument(
        "--site-network", required=True, help="Hub WG interface network CIDR for auto-allocation."
    )
    ob.add_argument("--preferred-peer-ip", default=None)
    ob.add_argument("--server-uuid", default=None)
    ob.add_argument(
        "--psk", default="", help="Preshared key (never printed; passed through only)."
    )
    ob.add_argument("--configure-site", action="store_true")
    ob.add_argument(
        "--site-ip", default=None, help="Site gateway IP, required with --configure-site."
    )
    ob.add_argument(
        "--site-privkey-env",
        default="UNIQUE_SITE_PRIVKEY",
        help="Env var name that holds the site private key "
        "(default: UNIQUE_SITE_PRIVKEY). Never accepted on "
        "the command line.",
    )
    ob.add_argument("--site-policy-name", default="WG_CLIENT")
    ob.add_argument("--hub-endpoint", default=None)
    ob.add_argument("--hub-endpoint-port", default="51820")
    ob.add_argument("--apply", action="store_true")
    ob.add_argument("--json", action="store_true")
    ob.add_argument("--quiet", action="store_true")

    ap = sub.add_parser(
        "add-peers",
        help="Batch-add peers to the hub from a JSON file.",
        description=(
            "Reads a JSON array of objects with fields: desc, interface_ip, "
            "peer_pubkey, preshared_key (optional), allow_ips (optional). "
            "Idempotent: peers already on the hub are skipped."
        ),
    )
    ap.add_argument("--from-file", required=True)
    ap.add_argument("--server-uuid", default=None)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")

    dr = sub.add_parser(
        "drift",
        help="Read-only drift scan across all hub peers.",
    )
    dr.add_argument("--server-uuid", default=None)
    dr.add_argument("--expected-endpoint", default=None)
    dr.add_argument(
        "--peer-ip", action="append", default=None, help="Restrict to specific peer IP(s)."
    )
    dr.add_argument("--json", action="store_true")
    dr.add_argument("--quiet", action="store_true")

    ue = sub.add_parser(
        "update-endpoint",
        help="Batch-update the hub endpoint on site gateways.",
    )
    ue.add_argument("--new-endpoint", required=True)
    ue.add_argument(
        "--expected-old-endpoint",
        default=None,
        help="Skip sites whose current endpoint doesn't match.",
    )
    ue.add_argument("--new-endpoint-port", default=None)
    ue.add_argument("--target", action="append", default=[], help="Site gateway IP (repeatable).")
    ue.add_argument("--from-file", default=None, help="JSON array of {ip, name} objects.")
    ue.add_argument("--apply", action="store_true")
    ue.add_argument("--json", action="store_true")
    ue.add_argument("--quiet", action="store_true")

    args = parser.parse_args(argv)

    if args.name == "onboard-site":
        _run_onboard_site(args)
    elif args.name == "add-peers":
        _run_add_peers(args)
    elif args.name == "drift":
        _run_drift(args)
    elif args.name == "update-endpoint":
        _run_update_endpoint(args)
    else:  # pragma: no cover — argparse enforces choices
        parser.error(f"unknown workflow: {args.name}")


# ── handlers ─────────────────────────────────────────────────────────


def _mk_sink(args: argparse.Namespace) -> ConsoleProgressSink | None:
    if args.json:
        return None
    return ConsoleProgressSink(verbose=not args.quiet)


def _login_hub() -> WireGuardManager:
    host, user, pw = _hub_credentials()
    if not host or not pw:
        _die("UNIQUE_HUB_HOST and UNIQUE_GW_PASSWORD env vars are required")
    try:
        gw = _connect_gateway(host, user, pw)
    except Exception as exc:  # noqa: BLE001
        _die(f"hub login to {host} failed: {exc}")
    return WireGuardManager(gw)


def _run_onboard_site(args: argparse.Namespace) -> None:
    sink = _mk_sink(args)
    site_private_key = ""
    site_client = None
    if args.configure_site:
        if not args.site_ip:
            _die("--configure-site requires --site-ip")
        site_private_key = os.environ.get(args.site_privkey_env, "")
        if not site_private_key:
            _die(f"--configure-site requires ${args.site_privkey_env} to be set")
        user, pw = _site_credentials()
        if not pw:
            _die("UNIQUE_GW_PASSWORD is required for site login")
        try:
            site_client = _connect_gateway(args.site_ip, user, pw)
        except Exception as exc:  # noqa: BLE001
            _die(f"site login to {args.site_ip} failed: {exc}")

    hub_mgr = _login_hub()
    try:
        result = onboard_site(
            hub_mgr,
            site_name=args.site_name,
            peer_pubkey=args.peer_pubkey,
            site_network=args.site_network,
            preferred_peer_ip=args.preferred_peer_ip,
            server_uuid=args.server_uuid,
            preshared_key=args.psk,
            configure_site=args.configure_site,
            site_client=site_client,
            site_private_key=site_private_key,
            site_policy_name=args.site_policy_name,
            hub_endpoint=args.hub_endpoint,
            hub_endpoint_port=args.hub_endpoint_port,
            apply=args.apply,
            progress=sink,
        )
    except WorkflowPrecheckError as exc:
        _die(f"precheck failed: {exc}")
    except WorkflowError as exc:
        _die(f"workflow failed: {exc}", code=1)

    if args.json:
        json.dump(result.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(
            f"{result.site_name}: hub={result.hub_action} "
            f"site={result.site_action} peer_ip={result.peer_ip} "
            f"({'DRY-RUN' if result.dry_run else 'APPLIED'})"
        )
    sys.exit(0 if result.success else 1)


def _run_add_peers(args: argparse.Namespace) -> None:
    sink = _mk_sink(args)
    try:
        with open(args.from_file, encoding="utf-8") as f:
            raw = json.loads(f.read())
    except OSError as exc:
        _die(f"cannot read {args.from_file}: {exc}")
    if not isinstance(raw, list):
        _die("--from-file must contain a JSON array")

    peers: list[PeerAddRequest] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            _die(f"entry #{i} is not an object")
        try:
            peers.append(
                PeerAddRequest(
                    desc=entry["desc"],
                    interface_ip=entry["interface_ip"],
                    peer_pubkey=entry["peer_pubkey"],
                    preshared_key=entry.get("preshared_key", ""),
                    allow_ips=tuple(entry.get("allow_ips", ())),
                )
            )
        except KeyError as exc:
            _die(f"entry #{i} missing required field: {exc}")

    hub_mgr = _login_hub()
    try:
        result = add_hub_peers(
            hub_mgr,
            peers,
            server_uuid=args.server_uuid,
            apply=args.apply,
            progress=sink,
        )
    except WorkflowPrecheckError as exc:
        _die(f"precheck failed: {exc}")

    if args.json:
        json.dump(result.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(
            f"{result.hub_host}: added={result.peers_added} "
            f"skipped={result.peers_skipped} failed={result.peers_failed} "
            f"({'DRY-RUN' if result.dry_run else 'APPLIED'})"
        )
    sys.exit(0 if result.success else 1)


def _run_drift(args: argparse.Namespace) -> None:
    sink = _mk_sink(args)
    user, pw = _site_credentials()
    if not pw:
        _die("UNIQUE_GW_PASSWORD is required")

    def factory(ip: str) -> GatewayClient:
        return _connect_gateway(ip, user, pw)

    hub_mgr = _login_hub()
    result = detect_hub_drift(
        hub_mgr,
        site_client_factory=factory,
        server_uuid=args.server_uuid,
        expected_endpoint=args.expected_endpoint,
        peer_filter=args.peer_ip,
        progress=sink,
    )

    if args.json:
        json.dump(result.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        tag = "OK" if result.ok else "DRIFT"
        print(
            f"{result.hub_host}: {tag} "
            f"drift={result.peers_in_drift} "
            f"unreachable={result.peers_unreachable}/{result.peers_total}"
        )
    sys.exit(0 if result.ok else 1)


def _run_update_endpoint(args: argparse.Namespace) -> None:
    sink = _mk_sink(args)

    targets: list[EndpointTarget] = []
    if args.target:
        targets.extend(EndpointTarget(ip=ip) for ip in args.target)
    if args.from_file:
        try:
            with open(args.from_file, encoding="utf-8") as f:
                raw = json.loads(f.read())
        except OSError as exc:
            _die(f"cannot read {args.from_file}: {exc}")
        if not isinstance(raw, list):
            _die("--from-file must contain a JSON array")
        for entry in raw:
            ip = entry.get("ip") or entry.get("interface_ip")
            if not ip:
                continue
            targets.append(
                EndpointTarget(ip=ip, name=entry.get("name", entry.get("username", "")))
            )
    if not targets:
        _die("supply --target or --from-file")

    user, pw = _site_credentials()
    if not pw:
        _die("UNIQUE_GW_PASSWORD is required")

    def factory(ip: str) -> GatewayClient:
        return _connect_gateway(ip, user, pw)

    try:
        result = update_site_endpoints(
            targets,
            new_endpoint=args.new_endpoint,
            site_client_factory=factory,
            expected_old_endpoint=args.expected_old_endpoint,
            new_endpoint_port=args.new_endpoint_port,
            apply=args.apply,
            progress=sink,
        )
    except WorkflowPrecheckError as exc:
        _die(f"precheck failed: {exc}")

    if args.json:
        json.dump(result.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(
            f"{result.new_endpoint}: updated={result.sites_updated} "
            f"already={result.sites_already_configured} "
            f"unreachable={result.sites_unreachable} "
            f"failed={result.sites_failed} "
            f"({'DRY-RUN' if result.dry_run else 'APPLIED'})"
        )
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":  # pragma: no cover
    workflow_cli()
