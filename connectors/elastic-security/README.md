# Elastic Security — detection alerts import

`elastic-security` · **import** connector · category **siem**

Importe les alertes de détection Elastic Security via l'API de recherche Elasticsearch. host.name/host.ip → ASSET, alertes → findings liés. Configuration par variables d'environnement du worker : ELASTIC_URL (ex. https://es:9200), ELASTIC_API_KEY, ELASTIC_INDEX (déf. .alerts-security.alerts-default), ELASTIC_VERIFY_TLS (déf. true).

**Upstream:** https://es:9200

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `since_hours` | int | no | `24` | Fenêtre temporelle (heures) à interroger (range 1–720) |
| `limit` | int | no | `200` | Nombre maximal d'alertes à importer (range 1–5000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Elastic Security — detection alerts import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:elastic-security`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
