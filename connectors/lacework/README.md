# Lacework — host vulnerabilities import

`lacework` · **import** connector · category **cnapp**

Importe les vulnérabilités hôtes Lacework via l'API v2 (jeton keyId/secret). Hôte → ASSET, vulnérabilités (CVE) → findings liés. Configuration par variables d'environnement du worker : LACEWORK_ACCOUNT (ex. mycompany ou mycompany.lacework.net), LACEWORK_KEY_ID, LACEWORK_SECRET.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `since_hours` | int | no | `24` | Fenêtre temporelle (heures) à interroger (range 1–720) |
| `limit` | int | no | `500` | Nombre maximal de résultats à importer (range 1–5000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Lacework — host vulnerabilities import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:lacework`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
