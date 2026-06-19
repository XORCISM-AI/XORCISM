# Microsoft Sentinel — incidents import

`sentinel` · **import** connector · category **siem**

Importe les incidents Microsoft Sentinel via l'API Azure Management (OAuth2 client_credentials). Les incidents deviennent des findings rattachés à un actif « workspace ». Configuration par variables d'environnement du worker : SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID, SENTINEL_CLIENT_SECRET, SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `since_hours` | int | no | `24` | Incidents modifiés dans les N dernières heures (range 1–720) |
| `limit` | int | no | `200` | Nombre maximal d'incidents à importer (range 1–1000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Microsoft Sentinel — incidents import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:sentinel`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
