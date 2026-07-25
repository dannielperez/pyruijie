# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `RuijieClient.get_fleet_devices()` fetches the hierarchy once, paginates the
  device endpoint from the account root, and resolves each device to its nearest
  building/project locally, avoiding one API request sequence per project.
- `Device.group_id`, `group_name`, `project_id`, and `project_name` preserve raw
  hierarchy identity and the SDK-resolved owning project on typed results.

- `ddns` module: `RuijieWebSession` (web-SSO login, the flow the cloud UI uses)
  and native Ruijie DDNS (`*.ruijieddnsd.com`) read via the `/webproxy` +
  `/aliyun/device/domain/info` pass-through — the DDNS config is not exposed by
  the appid/secret open API. Methods: `get_ddns(sn)`, `enumerate_ddns(sns)`,
  `list_domain_suffixes()`, and `webproxy(api, method, module)` for other web-only
  endpoints. `set_ddns` is stubbed pending a live capture of the UI Save call.
  Verified live 2026-07-02 (35+ US gateways enumerated). Adds a `cryptography`
  dependency (RSA password encryption for the SSO login).

### Fixed

- Normalize read timeouts to the SDK's public `ConnectionError` at both the
  authentication and authenticated-request boundaries.
- Fleet pagination validates `totalCount`, rejects repeated/inconsistent pages,
  and enforces page-count and aggregate-time bounds before returning a snapshot.
- Fleet snapshot authentication now shares the aggregate deadline and deducts
  token-refresh time from each subsequent request timeout.
- Fleet snapshots resolve the root group ID from Ruijie response-envelope and
  synthetic-wrapper variants while rejecting ambiguous hierarchies.
- Device, client, and switch-port pagination now stops at a configurable
  defensive page limit when an endpoint keeps returning full pages.

## [0.5.1]

### Security

- Removed a hardcoded Ruijie Cloud OpenAPI gateway token that was embedded in
  `authenticate()`. The token is now supplied via the new `api_token`
  constructor argument or the `RUIJIE_API_TOKEN` environment variable.
  **Deployments that relied on the built-in token must now provide their own.**
  The previously committed token should be rotated in the Ruijie Cloud portal.

## [0.5.0]

### Changed

- **BREAKING: CLI credential env vars renamed** from `UNIQUE_GW_IP` /
  `UNIQUE_GW_USERNAME` / `UNIQUE_GW_PASSWORD` / `UNIQUE_HUB_HOST` /
  `UNIQUE_SITE_PRIVKEY` to `RUIJIE_GW_IP` / `RUIJIE_GW_USERNAME` /
  `RUIJIE_GW_PASSWORD` / `RUIJIE_HUB_HOST` / `RUIJIE_SITE_PRIVKEY`. The legacy
  `R_USCC_GW_*` / `R_HUB_HOST` fallbacks have been removed. Update your `.env`
  files and job configs accordingly.
- Default WireGuard client policy name changed from `WG_CLIENT` to `WG_CLIENT`.
- Documentation genericized for public release (removed internal
  deployment-specific references and example infrastructure).

## [0.2.0] — 2026-04-15

### Added

- **`DEFAULT_BASE_URL` export** — callers no longer need to hardcode the
  Ruijie Cloud US endpoint URL.
- **`py.typed` marker** (PEP 561) — enables downstream type-checkers to
  resolve pyruijie type annotations.
- **`RuijieClient.base_url` property** — inspect the configured API endpoint.
- **`RuijieClient.__repr__`** — useful repr showing base URL and auth state.
- **`ClientDevice` WiFi/traffic fields** — `flow_up`, `flow_down`, `band`,
  `rssi`, `channel` now modeled from the API response (Section 3.0).
- **Integration-pattern test suite** (`test_integration_patterns.py`) — tests
  mirroring common consumer usage: `model_dump(by_alias=True)` alias
  stability, exception hierarchy, client init kwargs, discovery provider
  flow, device import flow, and `format_mac` compatibility.
- Comprehensive Args/Returns/Raises docstrings for all public client methods.
- Expanded README with configuration examples, region URLs, raw payload
  access, and complete model/exception reference tables.
- **`GatewayPort` model** — Pydantic model for gateway WAN/LAN ports with
  `subnet`, `is_lan`, `is_wan`, `is_up` computed properties. Maps to
  `/service/api/gateway/intf/info/{sn}`.
- **`SwitchPort` model** — Pydantic model for switch ports with `vlan`,
  `allowed_vlans`, `is_uplink`, `is_up`, `poe_status`. Maps to
  `/service/api/conf/switch/device/{sn}/ports`.
- **`RuijieClient.get_gateway_ports(serial_number)`** — fetch WAN/LAN port
  details for a gateway device (API 2.6.4).
- **`RuijieClient.get_switch_ports(serial_number)`** — paginated retrieval
  of switch port details (API 2.6.7, 0-based pagination).
- **`format_mac()` utility** — normalize Ruijie dot-format MACs
  (`aabb.ccdd.eeff` → `AA:BB:CC:DD:EE:FF`). Also handles dash, bare hex,
  and already-colon-separated formats.
- **`parse_vlan_list()` utility** — parse VLAN range strings
  (`"1-4,100,200"` → `{1, 2, 3, 4, 100, 200}`).
- Internal `_post()` and `_put()` HTTP helpers for write operations.
- `SwitchPort.is_uplink` field validator that coerces string/int truthy values.

### Fixed

- **`get_clients()` pagination** — was 0-indexed (`page_index=0`), now
  correctly starts at `page_index=1` matching the Ruijie Cloud API and
  the original `ruijie-cloud-cli` implementation. This caused discovery
  to return 0 clients.
- **`get_clients()` default `page_size`** — restored to `200` (was `100`)
  matching the original CLI behavior for fewer API round trips.

## [0.1.0] — 2026-04-10

### Added

- Initial release: Ruijie Cloud API client with OAuth2 client_credentials auth.
- `RuijieClient` with `authenticate()`, `get_projects()`, `get_devices()`,
  `get_clients()`.
- Pydantic models: `Project`, `Device`, `ClientDevice`.
- `Project.group_id` coercion — `field_validator` normalizes numeric
  group IDs from the API to strings.
- Exception hierarchy: `RuijieError`, `AuthenticationError`, `APIError`, `ConnectionError`.
- Context manager support.
- URL sanitization in error messages (strips `access_token` from exceptions).
