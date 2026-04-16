# pyruijie

[![CI](https://github.com/dannielperez/pyruijie/actions/workflows/ci.yml/badge.svg)](https://github.com/dannielperez/pyruijie/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pyruijie)](https://pypi.org/project/pyruijie/)
[![Python](https://img.shields.io/pypi/pyversions/pyruijie)](https://pypi.org/project/pyruijie/)
[![License](https://img.shields.io/pypi/l/pyruijie)](https://github.com/dannielperez/pyruijie/blob/main/LICENSE)

Python client library for [Ruijie/Reyee Cloud](https://cloud-us.ruijienetworks.com)-managed networking.

Provides typed Pydantic models, automatic pagination, and a clean exception
hierarchy for the Ruijie Cloud REST API.

## Features

- **Typed models** — Pydantic v2 models with field aliases matching the upstream API
- **Automatic pagination** — all list methods handle multi-page responses
- **Exception hierarchy** — granular errors for auth, API, and connectivity failures
- **Context manager** — connection pool lifecycle via `with` statement
- **PEP 561** — `py.typed` marker for downstream type-checkers

## Requirements

- Python 3.11+
- httpx ≥ 0.27
- pydantic ≥ 2.0

## Installation

```bash
pip install pyruijie
```

## Quick Start

```python
from pyruijie import RuijieClient

with RuijieClient(app_id="your-app-id", app_secret="your-secret") as client:
    client.authenticate()

    # List all projects (sites)
    for project in client.get_projects():
        print(f"{project.name} ({project.group_id})")

        # Get managed devices (APs, switches, gateways)
        for device in client.get_devices(project.group_id):
            status = "online" if device.is_online else "offline"
            print(f"  {device.name} [{device.product_type}] - {status}")
```

## Configuration

```python
from pyruijie import RuijieClient, DEFAULT_BASE_URL

# US region (default)
client = RuijieClient(app_id="...", app_secret="...")

# Asia region
client = RuijieClient(
    app_id="...",
    app_secret="...",
    base_url="https://cloud-as.ruijienetworks.com",
)

# Custom timeout (seconds)
client = RuijieClient(app_id="...", app_secret="...", timeout=60)

# Inspect configuration
print(client.base_url)          # "https://cloud-us.ruijienetworks.com"
print(client.is_authenticated)  # False
```

## Connected Clients

```python
# List connected client devices (phones, laptops, cameras, IoT)
clients = client.get_clients(project.group_id)
for c in clients:
    print(f"  {c.mac} {c.ip} {c.hostname} via {c.connect_type}")

    # Wireless client details
    if c.ap_name:
        print(f"    AP: {c.ap_name}, SSID: {c.ssid}, RSSI: {c.rssi}")

    # Wired client details
    if c.switch_name:
        print(f"    Switch: {c.switch_name}")
```

## Gateway Ports

```python
# Get WAN/LAN port details for a gateway device
gateways = [d for d in devices if d.product_type == "EGW"]
for gw in gateways:
    ports = client.get_gateway_ports(gw.serial_number)
    for port in ports:
        up = "UP" if port.is_up else "DOWN"
        print(f"  {port.alias} ({port.port_type}) {port.subnet} {up}")
```

## Switch Ports

```python
# Get port details for a switch (VLANs, PoE, uplink status)
switches = [d for d in devices if d.product_type in ("Switch", "ESW")]
for sw in switches:
    ports = client.get_switch_ports(sw.serial_number)
    for port in ports:
        print(f"  {port.name} VLAN {port.vlan} VLANs {port.allowed_vlans}")
```

## Utilities

```python
from pyruijie import format_mac, parse_vlan_list

# Normalize Ruijie dot-format MACs to colon-separated uppercase
format_mac("585b.6947.b194")      # → "58:5B:69:47:B1:94"
format_mac("aa-bb-cc-dd-ee-ff")   # → "AA:BB:CC:DD:EE:FF"

# Parse VLAN range strings
parse_vlan_list("1-4,100,200")    # → {1, 2, 3, 4, 100, 200}
```

## Raw Payload Access

All models support Pydantic serialization for storage and debugging:

```python
# Serialize with original API field names (aliases)
raw = client_device.model_dump(by_alias=True)
# {"mac": "AA:BB:...", "userName": "phone-01", "staOs": "Android", ...}

# Serialize with Python field names
raw = device.model_dump()
# {"serial_number": "SN001", "product_type": "AP", ...}
```

## API Reference

| Method | Returns | Description |
|---|---|---|
| `authenticate()` | `str` | Authenticate and return access token |
| `get_projects()` | `list[Project]` | All building-level groups (sites) |
| `get_devices(project_id)` | `list[Device]` | All managed infrastructure devices |
| `get_clients(project_id)` | `list[ClientDevice]` | Online client devices (phones, cameras, etc.) |
| `get_gateway_ports(serial_number)` | `list[GatewayPort]` | WAN/LAN port details for a gateway |
| `get_switch_ports(serial_number)` | `list[SwitchPort]` | Port details for a switch |

### Models

| Model | Key Fields | Computed Properties |
|---|---|---|
| `Project` | `name`, `group_id` | — |
| `Device` | `serial_number`, `product_type`, `product_class`, `name`, `local_ip`, `mac`, `firmware_version` | `is_online` |
| `ClientDevice` | `mac`, `ip`, `connect_type`, `ssid`, `band`, `rssi`, `channel` | `hostname`, `os_type`, `ap_name`, `ap_mac`, `switch_name`, `is_online` |
| `GatewayPort` | `alias`, `port_type`, `ip_address`, `ip_mask`, `speed` | `subnet`, `is_lan`, `is_wan`, `is_up` |
| `SwitchPort` | `name`, `port_type`, `vlan`, `vlan_list`, `is_uplink`, `poe_status` | `allowed_vlans`, `is_up` |

### Constants

| Name | Value | Description |
|---|---|---|
| `DEFAULT_BASE_URL` | `"https://cloud-us.ruijienetworks.com"` | US region endpoint |

## Error Handling

```python
from pyruijie import (
    RuijieClient,
    RuijieError,
    AuthenticationError,
    APIError,
    ConnectionError,
)

try:
    with RuijieClient(app_id="...", app_secret="...") as client:
        client.authenticate()
        devices = client.get_devices("project-id")
except AuthenticationError:
    print("Invalid credentials")
except ConnectionError:
    print("Cannot reach Ruijie Cloud API")
except APIError as e:
    print(f"API error {e.code}: {e.message}")
except RuijieError:
    print("Unexpected pyruijie error")
```

All exceptions inherit from `RuijieError`:

| Exception | When | Attributes |
|---|---|---|
| `AuthenticationError` | Invalid credentials or auth failure | — |
| `APIError` | Non-zero error code from the API | `.code`, `.message` |
| `ConnectionError` | Network unreachable or timeout | — |

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

This project is licensed under the [Apache License 2.0](LICENSE).
