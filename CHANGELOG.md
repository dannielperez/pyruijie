# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  mirroring exact UniqueOS usage: `model_dump(by_alias=True)` alias
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
  (`585b.6947.b194` → `58:5B:69:47:B1:94`). Also handles dash, bare hex,
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
