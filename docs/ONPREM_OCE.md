# Targeting a self-hosted Ruijie controller (RG-OCE / MACC-private)

Ruijie's self-hosted controller edition — **RG-OCE** ("On-Cloud Edition", internally
**MACC-private**) — exposes the **same `/service/api/` OpenAPI** as the hosted Ruijie
Cloud. That means `pyruijie` can talk to a private, on-premises controller with no code
changes beyond configuration: point `base_url` at your controller and, if needed,
adjust the OAuth gateway token.

> **Compatibility note.** The API surface is the same family as the hosted cloud, but
> a given on-prem deployment may enable a different set of endpoints, use a different
> gateway token, or run behind a self-signed certificate. Treat compatibility as
> **deployment-specific and verify it against your instance** — start by confirming
> `authenticate()` succeeds, then `get_projects()`.

## Configuration

```python
from pyruijie import RuijieClient

client = RuijieClient(
    app_id="<open-api-app-id>",
    app_secret="<open-api-app-secret>",
    base_url="https://your-controller.example.net",  # your RG-OCE / MACC host
    auth_token=None,   # see "Gateway token" below
)
client.authenticate()
for project in client.get_projects():
    ...
```

### `base_url`

Set it to your controller's base URL (scheme + host, no trailing slash — it is
stripped for you). This replaces the default hosted-cloud endpoint
(`https://cloud-us.ruijienetworks.com`).

### Gateway token (`auth_token`)

The hosted Ruijie Cloud requires a fixed `token` query parameter on the OAuth call.
`pyruijie` sends it by default (exported as `DEFAULT_AUTH_TOKEN`). A self-hosted
controller may:

- accept the same token — leave `auth_token` at its default;
- require a **deployment-specific token** — pass `auth_token="<your-token>"`;
- require **no token** — pass `auth_token=None` to omit the parameter entirely.

If authentication fails against an on-prem controller, the gateway token is the first
thing to check.

### TLS

On-prem controllers commonly ship with a **self-signed certificate**. Prefer installing
a trusted certificate (or your organization's CA) on the controller rather than
disabling verification in your client. `pyruijie` uses `httpx` defaults; configure trust
at the environment/OS level as you would for any HTTPS client.

## Scope

This targets the controller's **REST OpenAPI** (`/service/api/...`) only — the same
surface the existing client methods use. On-prem controllers also expose device
**southbound** protocols (e.g. MQTT/CoAP/CWMP/SNMP) for device-to-controller
communication; those are out of scope for this REST client.

## Endpoint coverage

`pyruijie` implements a focused subset of the OpenAPI (projects/groups, device
inventory, clients, gateway ports, switch ports). The same methods work against a
self-hosted controller. If your deployment exposes additional endpoints you need,
open an issue or PR — contributions that add read-only endpoints are welcome.
