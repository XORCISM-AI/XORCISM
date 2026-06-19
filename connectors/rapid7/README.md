# Rapid7 InsightVM — import assets/vulns

`rapid7` · **import** connector · category **vuln-management**

Récupère assets et vulnérabilités via l'API InsightVM v3 (console Nexpose) et les importe en VULNERABILITY (CVE). Config : R7_API_URL, R7_API_USER, R7_API_PASSWORD, R7_INSECURE (optionnel).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max_assets` | int | no | `200` | Nombre max d'assets à importer (range 1–5000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Rapid7 InsightVM — import assets/vulns*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:rapid7`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
