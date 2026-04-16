# pyruijie ↔ UniqueOS Integration Audit

_Conducted: 2026-04-16_

## Summary

Full audit of how UniqueOS consumes pyruijie across 5 service modules.
All model fields, method signatures, exception types, and serialization
contracts are compatible. No breaking issues found.

## Integration Points

| UniqueOS File | pyruijie Methods Used | Models/Exceptions |
|---|---|---|
| `devices/services/ruijie_discovery.py` | `authenticate()`, `get_clients()` | `ClientDevice`, `RuijieError` |
| `devices/services/ruijie_import.py` | `get_projects()`, `get_devices()` | `Project`, `Device`, `RuijieError` |
| `devices/services/ruijie.py` (Adapter) | `authenticate()`, `get_projects()`, `get_devices()` | `APIError`, `AuthenticationError`, `ConnectionError`, `RuijieError` |
| `devices/services/discovery/providers/ruijie.py` | `authenticate()`, `get_clients()` | `ClientDevice`, `RuijieError` |
| `organizations/services/connections.py` | `authenticate()` | `RuijieError` |

## Client Init Patterns

All callers use keyword arguments matching the `RuijieClient.__init__` signature:

```python
RuijieClient(app_id=..., app_secret=..., base_url=..., timeout=30)
```

All kwargs are supported. The `base_url` and `timeout` params are optional
with sensible defaults.

## Model Field Access Map

### ClientDevice (via `get_clients`)

| Property | Source Field | Used By |
|---|---|---|
| `.mac` | `mac` | discovery, provider |
| `.ip` | `ip` | discovery, provider |
| `.hostname` | `userName` (property) | discovery, provider |
| `.os_type` | `staOs` / `manufacturer` (property) | discovery, provider |
| `.is_online` | always `True` (property) | discovery, provider |
| `.connect_type` | `connectType` | discovery, provider |
| `.ssid` | `ssid` | discovery, provider |
| `.ap_name` | `deviceName` when AP (property) | discovery, provider |
| `.ap_mac` | `linkedDevice` when AP (property) | discovery, provider |
| `.switch_name` | `deviceName` when Switch (property) | provider |
| `.switch_port` | `None` (property) | provider |
| `.vlan_id` | `None` (property) | provider |
| `.model_dump(by_alias=True)` | all alias keys | discovery, provider |

### Device (via `get_devices`)

| Property | Source Field | Used By |
|---|---|---|
| `.serial_number` | `serialNumber` | import, adapter |
| `.name` | `aliasName` | import, adapter |
| `.product_type` | `productType` | import, adapter |
| `.product_class` | `productClass` | import |
| `.firmware_version` | `softwareVersion` | import, adapter |
| `.mac` | `mac` | import, adapter |
| `.is_online` | `onlineStatus == "ONLINE"` | import, adapter |
| `.online_status` | `onlineStatus` | adapter |
| `.local_ip` | `localIp` | import, adapter |
| `.egress_ip` | `cpeIp` | import |

### Project (via `get_projects`)

| Property | Source Field | Used By |
|---|---|---|
| `.group_id` | `groupId` (coerced to str) | import, adapter |
| `.name` | `name` | import |

## Exception Handling Patterns

- **Broad catch**: `except (RuijieError, OSError, TimeoutError)` — discovery, provider
- **Granular catch**: `AuthenticationError` / `ConnectionError` / `RuijieError` — adapter
- **`APIError` attributes**: `.code`, `.message` — accessed by adapter

All exception types are properly exported and the hierarchy is stable:
`AuthenticationError → RuijieError`, `APIError → RuijieError`, `ConnectionError → RuijieError`.

## Serialization Contract

`ClientDevice.model_dump(by_alias=True)` is stored as `raw_payload` in the
database. **Alias names are a public API contract** — changing them would
break stored data deserialization. This is now covered by
`TestModelDumpByAlias` in `test_integration_patterns.py`.

## Improvements Made

1. **Exported `DEFAULT_BASE_URL`** — callers no longer need to hardcode
   `"https://cloud-us.ruijienetworks.com"`.
2. **Added `py.typed` marker** — PEP 561 compliance for type-checkers.
3. **Created `test_integration_patterns.py`** — 23 tests that mirror exact
   UniqueOS usage patterns as a regression safety net.

## Observations

- `ruijie_discovery.py` has a local `_normalize_mac()` that duplicates
  pyruijie's `format_mac()`. This is a UniqueOS-side cleanup opportunity,
  not a pyruijie issue.
- `discovery/providers/ruijie.py` uses `normalize_mac` from its own base
  provider module — this is correct for its architecture.
- New methods `get_gateway_ports()` and `get_switch_ports()` have no
  app-side consumers yet — they are safe additions with no integration risk.

## Write-Operation Assessment

pyruijie exposes internal `_post()` and `_put()` helpers but no public
write methods. The Ruijie Cloud API supports write operations for:

| Endpoint | Method | Risk | Recommendation |
|---|---|---|---|
| Device alias rename | PUT | Low | Safe to expose |
| SSID configuration | POST/PUT | Medium | Expose with confirmation pattern |
| VLAN assignment | PUT | Medium | Expose with validation |
| Firmware upgrade trigger | POST | High | Do not expose without explicit opt-in |
| Device reboot | POST | High | Do not expose without explicit opt-in |

**Recommendation**: Start with read-only; add write methods individually
as UniqueOS needs them, behind explicit method names that make the
side-effect obvious (e.g., `rename_device()`, not `update()`).

## Test Coverage

| Suite | Tests | Status |
|---|---|---|
| `test_client.py` | 21 | ✅ Pass |
| `test_models.py` | 23 | ✅ Pass |
| `test_utils.py` | 9 | ✅ Pass |
| `test_integration_patterns.py` | 23 | ✅ Pass |
| **Total pyruijie** | **82** | ✅ Pass |
| UniqueOS `devices/tests/` | 714 | ✅ Pass |
