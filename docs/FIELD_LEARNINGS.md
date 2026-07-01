# pyruijie — Field Learnings

Vendor-neutral notes on Ruijie/Reyee cloud + gateway behavior, useful when
building WireGuard automation on top of `pyruijie`. All addresses below are
placeholders (RFC 5737 / RFC 1918); substitute your own.

## WireGuard hub / site model

- A common topology is a central **dual-WAN** Ruijie EG acting as the WireGuard
  **hub**, with remote sites running a WG **client** policy back to it.
- **Prefer a DDNS name over a static WAN IP for the site→hub endpoint.** A static
  IP tied to one WAN dies when that WAN fails; a DDNS name that tracks the live
  WAN survives a WAN failover. Repointing is a minimal diff: copy the existing
  client policy and change only `endpoint`; a successful
  `wireguard_update(sn, payload)` returns `{"code": 0, "msg": "OK."}`.
- **Client `intf` (egress) — `all` (UI label "Auto") vs a pinned `wan` / `wan2`.**
  On a site with two working WANs, `all` lets the tunnel ride whichever WAN is up.
  The API value is the literal string `"all"`.
- **Dual-WAN detection:** `get_gateway_ports(sn)` and count ports where
  `port_type == "WAN"`, `line_status == "true"`, and an `ip_address` is present.
  Two or more ⇒ dual-WAN working.

## Cloud API gotchas

- **`vpn_info` `connectStatus` is stale/unreliable** — it can lag, and even lag
  *backwards*. Don't treat it as ground truth for up/down; prefer device
  `get_devices` online state plus actual reachability, or use it only as a soft
  signal.
- `get_devices(groupId)` reporting `offlineReason == "INFORM"` across a tight
  cluster of devices at the same minute usually means an upstream link/WAN drop,
  not individual device failures. `lastOnline` is a millisecond epoch.
- A device whose gateway is offline in the cloud can still accept a queued config
  change — it applies on reconnect. But if the device egresses cloud management
  through the same tunnel/link that is down, the change won't reach it.

## Suggested high-level helpers

- `repoint_endpoint(site, new_endpoint)` — minimal-diff, idempotent WG client
  endpoint change.
- `set_egress(site, mode)` — set client `intf` (`all` / `wan` / `wan2`).
- `detect_dual_wan(sn)` → `(#wan_ports, #wan_up, ips)`.
- `site_connectivity(site)` — composite status that does not rely solely on the
  stale `connectStatus` field.
