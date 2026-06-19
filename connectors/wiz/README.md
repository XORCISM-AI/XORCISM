# Wiz — cloud issues import

`wiz` · **import** connector · category **cnapp**

Importe les Issues Wiz via l'API GraphQL (OAuth2 client_credentials). Entité concernée → ASSET, issue → finding lié. Configuration par variables d'environnement du worker : WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_URL (endpoint GraphQL, ex. https://api.<region>.app.wiz.io/graphql), WIZ_AUTH_URL (déf. https://auth.app.wiz.io/oauth/token).

**Upstream:** https://api.<region

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `limit` | int | no | `200` | Nombre maximal d'issues à importer (range 1–2000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Wiz — cloud issues import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:wiz`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
