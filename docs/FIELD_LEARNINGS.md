# pyruijie — Field Learnings (validated 2026-06-23, WAN-outage response)

From repointing ~97 site WireGuard tunnels to a DDNS and setting auto egress on
dual-WAN sites during a primary-WAN ISP outage.

## WireGuard hub / site model
- Monitoring-center hub is a **dual-WAN** Ruijie EG (LAN `10.200.0.1`). Sites run a WG **client**
  policy (`US_WG`) to the hub.
- **Site endpoint should be a DDNS, not a static WAN IP.** A static IP (e.g. `67.203.206.66`) dies
  with that WAN; the DDNS (`centrouniquec.ruijieddnsd.com`) follows whichever WAN is live. This was
  the root cause of a mass site outage. Repoint = copy the existing client policy, change only
  `endpoint`, `wireguard_update(sn, payload)` → `{"code":0,"msg":"OK."}`.
- **Client `intf` (egress) = `all` (Auto) vs `wan`/`wan2` (pinned).** Sites with **two working WANs**
  should be `all` so the tunnel rides whichever WAN is up. Value is the string `"all"` (UI label "Auto").
- **Dual-WAN detection:** `get_gateway_ports(sn)` → count ports with `port_type=="WAN"`,
  `line_status=="true"`, and an `ip_address`. ≥2 ⇒ dual-WAN-working.

## Gotchas
- **Cloud `vpn_info` `connectStatus` is STALE/unreliable** — it lagged *backwards* during the
  incident. Don't use it as ground truth for up/down; prefer device `get_devices` online + actual
  reachability, or accept it as soft signal only.
- `get_devices(groupId)` `offlineReason=INFORM` on a tight cluster at the same minute = upstream
  link/WAN drop, not individual device failures. `lastOnline` is ms epoch.
- A device whose gateway is offline in cloud can still accept a queued config change (applies on
  reconnect) — but if it egresses cloud-management through the dead tunnel, it won't.

## Suggested high-level helpers (would directly back UniqueOS actions)
- `repoint_endpoint(site, new_endpoint)` — minimal-diff WG client endpoint change (idempotent).
- `set_egress(site, mode)` — set client `intf` (auto/wan/wan2).
- `detect_dual_wan(sn)` → (#wan_ports, #wan_up, ips).
- `site_connectivity(site)` — composite status not relying solely on stale `connectStatus`.

(Working reference implementations live in unique-audit `data/repoint_wg_to_ddns_cloud.py`
and `data/wg_set_auto_egress.py`.)
