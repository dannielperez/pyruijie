# pyruijie

Python client library for Ruijie/Reyee Cloud-managed networking.

## Installation

```bash
pip install pyruijie
```

## Quick Start

```python
from pyruijie import RuijieClient

client = RuijieClient(app_id="your-app-id", app_secret="your-secret")
client.authenticate()

# List all projects (sites)
projects = client.get_projects()
for project in projects:
    print(f"{project.name} ({project.group_id})")

# Get devices for a project
devices = client.get_devices(projects[0].group_id)
for device in devices:
    status = "online" if device.is_online else "offline"
    print(f"  {device.name} [{device.product_type}] - {status}")
```

## Context Manager

```python
with RuijieClient(app_id="...", app_secret="...") as client:
    projects = client.get_projects()
```

## Error Handling

```python
from pyruijie import RuijieClient, AuthenticationError, APIError

try:
    client = RuijieClient(app_id="...", app_secret="...")
    client.authenticate()
except AuthenticationError:
    print("Bad credentials")
except APIError as e:
    print(f"API error {e.code}: {e.message}")
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

This project is licensed under the [Apache License 2.0](LICENSE).
