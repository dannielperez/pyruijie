"""Ruijie/Reyee EG WAN multi-line load-balance (``mllb``) read/write helpers.

On a dual-/multi-WAN Reyee EG gateway the uplink priority ("which WAN is the
primary vs the backup") lives in the local eWeb config module ``mllb``
(Multi-Line Load Balance), reachable over the LuCI JSON-RPC transport that
:class:`~pyruijie.gateway.GatewayClient` speaks (``POST /cgi-bin/luci/api/cmd``).
The cloud service-API does *not* expose it — only WireGuard + read-only info.

The config shape (``devConfig.get module=mllb`` → ``data``)::

    {"mode": "master", "enable": "1", "policy": "load", "intf_cnt": "2",
     "wan": "1", "wan1": "1", "backup_discon": "1",
     "master_list": [{"ifname": "wan",  "m": "1", "band_up": "100", "band_down": "100"},
                     {"ifname": "wan1", "m": "0", "band_up": "100", "band_down": "100"}]}

``m`` is the master bit (``"1"`` = primary, ``"0"`` = backup).  ``mode="master"``
is Active/Backup; ``backup_discon="1"`` is the GUI "Forced Switch" (send *all*
traffic to the master unless it drops).  The setter (``devConfig.set``) takes the
same object **without** the read-only stamp fields
(``version``/``configTime``/``currentTime``/``configId``).

WARNING — WG egress interaction: on a Forced-Switch site the backup WAN loses its
default route, so a WireGuard client pinned (``intf``) to a WAN that you demote to
backup goes dark.  When swapping the master, move any such WG client to ``intf=all``
(or the new master) in the same change window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyruijie.gateway import GatewayClient

MLLB_MODULE = "mllb"

# Fields the setter accepts; the read-only stamps below are dropped on write.
_STAMP_FIELDS = ("version", "configTime", "currentTime", "configId")
# Per-line fields, in the order the GUI Save emits them.
_LINE_FIELDS = ("band_up", "band_down", "ifname", "m")


@dataclass(frozen=True)
class WanLine:
    """One WAN uplink in the load-balance policy."""

    ifname: str
    is_master: bool
    band_up: str = "100"
    band_down: str = "100"


@dataclass
class WanLoadBalance:
    """Parsed ``mllb`` WAN load-balance policy."""

    mode: str
    policy: str
    backup_discon: bool
    lines: list[WanLine] = field(default_factory=list)
    enable: bool = True
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def master_ifname(self) -> str | None:
        """The ifname currently flagged as master (primary), or None."""
        for ln in self.lines:
            if ln.is_master:
                return ln.ifname
        return None

    @property
    def forced_switch(self) -> bool:
        """True when 'Forced Switch' is on (strict primary/backup)."""
        return self.backup_discon

    @classmethod
    def parse(cls, data: dict[str, Any]) -> WanLoadBalance:
        """Build from a ``devConfig.get module=mllb`` ``data`` object."""
        lines = [
            WanLine(
                ifname=str(e.get("ifname", "")),
                is_master=str(e.get("m", "0")) == "1",
                band_up=str(e.get("band_up", "100")),
                band_down=str(e.get("band_down", "100")),
            )
            for e in data.get("master_list", [])
        ]
        return cls(
            mode=str(data.get("mode", "")),
            policy=str(data.get("policy", "")),
            backup_discon=str(data.get("backup_discon", "0")) == "1",
            enable=str(data.get("enable", "1")) == "1",
            lines=lines,
            raw=dict(data),
        )


def build_master_swap_payload(mllb_data: dict[str, Any], primary_ifname: str) -> dict[str, Any]:
    """Return a ``devConfig.set module=mllb`` ``data`` dict making *primary_ifname* the master.

    Pure function (no I/O): takes the current ``mllb`` config (as returned by
    ``devConfig.get``), sets ``m="1"`` on *primary_ifname* and ``m="0"`` on every
    other line, and strips the read-only stamp fields so the result is safe to POST.

    Raises:
        ValueError: if *primary_ifname* is not one of the configured WAN lines.
    """
    ifnames = [str(e.get("ifname", "")) for e in mllb_data.get("master_list", [])]
    if primary_ifname not in ifnames:
        raise ValueError(f"{primary_ifname!r} not in WAN lines {ifnames}")

    out = {k: v for k, v in mllb_data.items() if k not in _STAMP_FIELDS}
    out["master_list"] = [
        {
            "band_up": str(e.get("band_up", "100")),
            "band_down": str(e.get("band_down", "100")),
            "ifname": str(e.get("ifname", "")),
            "m": "1" if str(e.get("ifname", "")) == primary_ifname else "0",
        }
        for e in mllb_data.get("master_list", [])
    ]
    return out


def get_wan_loadbalance(client: GatewayClient) -> WanLoadBalance:
    """Read the current WAN load-balance policy from the gateway eWeb."""
    resp = client.cmd_checked("devConfig.get", MLLB_MODULE)
    return WanLoadBalance.parse(resp.get("data", {}) or {})


def set_wan_primary(client: GatewayClient, primary_ifname: str) -> WanLoadBalance:
    """Make *primary_ifname* the master (primary) WAN; return the resulting policy.

    Reads the current ``mllb`` config, swaps the master bit to *primary_ifname*
    (no-op if already master), writes it back, and re-reads to confirm.  A write
    ReadTimeout is treated as success by ``cmd_checked`` (the gateway applies WAN
    changes asynchronously and may drop the mgmt path briefly during reconverge).
    """
    current = client.cmd_checked("devConfig.get", MLLB_MODULE).get("data", {}) or {}
    if WanLoadBalance.parse(current).master_ifname == primary_ifname:
        return WanLoadBalance.parse(current)
    payload = build_master_swap_payload(current, primary_ifname)
    client.cmd_checked("devConfig.set", MLLB_MODULE, data=payload)
    return get_wan_loadbalance(client)
