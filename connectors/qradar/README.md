# IBM QRadar — offenses import

`qradar` · **import** connector · category **siem**

Importe les offenses IBM QRadar via l'API REST (/api/siem/offenses). offense_source → ASSET, offense → finding lié. Configuration par variables d'environnement du worker : QRADAR_URL (ex. https://qradar.lab), QRADAR_TOKEN (en-tête SEC), QRADAR_VERIFY_TLS (déf. true).

**Upstream:** https://qradar.lab

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `since_hours` | int | no | `24` | Offenses mises à jour dans les N dernières heures (range 1–720) |
| `limit` | int | no | `200` | Nombre maximal d'offenses à importer (range 1–5000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *IBM QRadar — offenses import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:qradar`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
