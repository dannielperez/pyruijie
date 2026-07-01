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
format_mac("aabb.ccdd.eeff")      # → "AA:BB:CC:DD:EE:FF"
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

## Gateway Management (LuCI JSON-RPC)

pyruijie also provides a `GatewayClient` for direct management of Ruijie EG
gateways via the local LuCI JSON-RPC API. Tested on EG1510XS and EG310GH-P-E.

```python
from pyruijie import GatewayClient, WireGuardManager

gw = GatewayClient("10.100.1.1", "admin", "password")
gw.login()

wg = WireGuardManager(gw)

# List server policies and peers
for server in wg.list_server_policies():
    print(f"{server.desc} ({server.local_addr}) — {len(server.peers)} peers")
    for peer in server.peers:
        print(f"  {peer.desc}: {peer.ipaddr}")

# Add a new site peer to the hub
wg.add_site_peer(
    desc="New Site GW",
    interface_ip="10.100.0.200",
    peer_pubkey="base64-pubkey==",
)

# Detect drift between hub and site
site_gw = GatewayClient("10.100.0.105", "admin", "password")
site_gw.login()
site_wg = WireGuardManager(site_gw)
client_policy = site_wg.get_client_policy()
peer = wg.get_peer(ip="10.100.0.105")
report = wg.detect_drift(peer, client_policy)
print(report)
```

## CLI Usage

pyruijie includes a CLI for common WireGuard operations. Set hub credentials
in a `.env` file:

```
RUIJIE_GW_IP=10.100.1.1
RUIJIE_GW_USERNAME=admin
RUIJIE_GW_PASSWORD=yourpassword
```

### Peer Management

```bash
# List all peers on the hub
python -m pyruijie peers list
python -m pyruijie peers list --json

# Add a peer (with confirmation prompt)
python -m pyruijie peers add --desc "New Site" --ip 10.100.0.200 --pubkey "key=="

# Add with dry-run (no changes)
python -m pyruijie peers add --desc "New Site" --ip 10.100.0.200 --pubkey "key==" --dry-run

# Remove a peer
python -m pyruijie peers remove --ip 10.100.0.200

# Rename peers from a JSON map file
python -m pyruijie peers rename rename_map.json
```

### Site Onboarding

```bash
# Onboard a new site — adds hub peer (with auto IP allocation)
python -m pyruijie onboard-site \
    --site-name "Example Site" \
    --site-ip 10.100.0.50 \
    --pubkey "site-gateway-pubkey==" \
    --dry-run

# Full onboard — hub peer + configure site client policy
python -m pyruijie onboard-site \
    --site-name "Example Site" \
    --site-ip 10.100.0.50 \
    --pubkey "site-gateway-pubkey==" \
    --configure-site \
    --site-privkey "site-gateway-privkey==" \
    --hub-endpoint hub.example.com \
    -y -o result.json
```

### Probe & Drift Detection

```bash
# Probe a site gateway's WireGuard config
python -m pyruijie probe 10.100.0.105

# Detect configuration drift between hub and sites
python -m pyruijie drift
python -m pyruijie drift --peer-ip 10.100.0.105 10.100.0.103
```

### Endpoint Updates

```bash
# Update WG client endpoint on site gateways
python -m pyruijie update-endpoint 10.100.0.105 10.100.0.103 \
    --new-endpoint hub.example.com \
    --old-endpoint 203.0.113.10 \
    --dry-run

# From a targets file
python -m pyruijie update-endpoint --from-file targets.json \
    --new-endpoint hub.example.com
```

## License

This project is licensed under the [Apache License 2.0](LICENSE).
