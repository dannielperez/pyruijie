# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`ClientDevice` model** — Pydantic model for connected client devices
  (phones, laptops, IoT) discovered via Ruijie Cloud's client listing API.
  Fields: `mac`, `ip`, `hostname`, `os_type`, `connect_type`, `ssid`,
  `ap_name`, `ap_mac`, `switch_name`, `switch_port`, `vlan_id`,
  `online_status`, `up_time`.
- **`RuijieClient.get_clients()`** — paginated retrieval of all connected
  client devices for a given project.
- **`Project.group_id` coercion** — `field_validator` normalizes numeric
  group IDs from the API to strings.

## [0.1.0] — 2026-04-10

### Added

- Initial release: Ruijie Cloud API client with OAuth2 client_credentials auth.
- `RuijieClient` with `authenticate()`, `get_projects()`, `get_devices()`.
- Pydantic models: `Project`, `Device`.
- Exception hierarchy: `RuijieError`, `AuthenticationError`, `APIError`, `ConnectionError`.
- Context manager support.
