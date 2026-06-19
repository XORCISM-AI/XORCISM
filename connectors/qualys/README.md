# Qualys VMDR — import détections

`qualys` · **import** connector · category **vuln-management**

Récupère les détections d'hôtes via l'API Qualys VMDR et les importe en VULNERABILITY (QID/CVE) liées aux assets. Config : QUALYS_API_URL, QUALYS_USER, QUALYS_PASSWORD.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `ips` | string | no | — | Filtre IPs (ex. 10.0.0.0/24 ou 10.0.0.1-10.0.0.50). Vide = tout. |
| `min_severity` | enum | no | `2` | Severité Qualys minimale (one of: `1`, `2`, `3`, `4`, `5`) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Qualys VMDR — import détections*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:qualys`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
