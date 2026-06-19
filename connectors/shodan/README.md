# Shodan

`shodan` · **import** connector · category **OSINT**

Imports internet-exposure data from Shodan (https://www.shodan.io). Each host becomes an ASSET (IP, OS), each banner an exposed SERVICE (host:port + product/version), and detected CPEs are linked to the asset. Offline mode: parse a `shodan host <ip>` / `shodan download`+`shodan parse` JSON (a single host object, a JSON-lines banner stream, or `{matches:[...]}`). Live mode: if `query` is set and SHODAN_API_KEY is in the worker env, calls the Shodan search API (needs `pip install requests`). Read-only OSINT (non-intrusive). No DB access in run.py (worker-safe).

**Upstream:** https://www.shodan.io

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Shodan JSON (host object, JSON-lines banners, or {matches:[...]}) to import. |
| `query` | string | no | — | Live mode: Shodan search query (needs SHODAN_API_KEY in the worker env). |
| `limit` | int | no | `100` | Live mode: maximum number of results to import. (range 1–1000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Shodan*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:shodan`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/shodan/sample.json --connector shodan
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
