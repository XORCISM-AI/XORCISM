# Microsoft Entra ID

`entra-id` · **import** connector · category **Cloud Security**

Microsoft 365 / Entra ID (Azure AD) identity & device sync via the Microsoft Graph API. Collects and synchronizes users (human identities), service principals & managed identities (non-human identities / NHI) and registered devices (assets) into XORCISM (IDENTITY + ASSET). App-only auth (OAuth2 client credentials) — secrets from the worker environment: ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET. Requires the application permissions User.Read.All, Application.Read.All and Device.Read.All. Microsoft Graph: https://learn.microsoft.com/graph/overview.

**Upstream:** https://learn.microsoft.com/graph/overview

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `tenant` | string | no | — | Entra tenant id (GUID) or primary domain. Overrides ENTRA_TENANT_ID. |
| `include` | string | no | — | Comma-separated object types to sync: users, servicePrincipals, devices (default: all three). |
| `max_items` | number | no | — | Maximum objects to pull per type (default 1000). |
| `file` | file | no | — | Offline mode: a saved Microsoft Graph JSON export to parse instead of calling the API. Accepts {users:[],servicePrincipals:[],devices:[]} or raw Graph {value:[...]} arrays. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Microsoft Entra ID*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:entra-id`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/entra-id/sample.json --connector entra-id
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
