# Burp Suite Professional — REST API

`burpsuite` · **import** connector · category **web** · ⚠️ **intrusive** (engagement scope enforced)

Lance/relit un scan Burp Suite Pro via l'API REST et importe les issues en VULNERABILITY. Config par variables d'environnement : BURP_API_URL, BURP_API_KEY.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | url | no | — | URL à scanner (démarre un nouveau scan, dans le périmètre) |
| `scan_id` | int | no | — | ID d'un scan Burp existant à relire (au lieu de target) (range 0–) |
| `max_wait` | int | no | `1800` | Attente max du scan (secondes) (range 0–7200) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Burp Suite Professional — REST API*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:burpsuite`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
