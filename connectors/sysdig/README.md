# Sysdig — runtime vulnerabilities import

`sysdig` · **import** connector · category **cnapp**

Importe les résultats de vulnérabilités runtime Sysdig Secure via l'API REST. Workload/host → ASSET, vulnérabilités (CVE) → findings liés. Configuration par variables d'environnement du worker : SYSDIG_URL (ex. https://app.us4.sysdig.com), SYSDIG_API_TOKEN (Bearer), SYSDIG_PATH (déf. /secure/vulnerability/v1/runtime-results), SYSDIG_VERIFY_TLS (déf. true).

**Upstream:** https://app.us4.sysdig.com

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `limit` | int | no | `200` | Nombre maximal de résultats à importer (range 1–2000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Sysdig — runtime vulnerabilities import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:sysdig`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
