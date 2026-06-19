# Aikido Security — issues import

`aikido` · **import** connector · category **appsec**

Importe les issues Aikido Security (SCA / SAST / DAST / IaC / secrets / cloud) via l'API publique v1 (OAuth2 client_credentials). Dépôt ou ressource → ASSET ; issue (CVE ou règle) → finding lié. Configuration par variables d'environnement du worker (jamais saisies dans l'UI) : AIKIDO_CLIENT_ID, AIKIDO_CLIENT_SECRET, AIKIDO_API_URL (déf. https://app.aikido.dev).

**Upstream:** https://app.aikido.dev

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `status` | enum | no | `open` | Filtrer par statut d'issue (one of: `open`, `all`) |
| `limit` | int | no | `500` | Nombre maximal d'issues à importer (range 1–5000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Aikido Security — issues import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:aikido`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
