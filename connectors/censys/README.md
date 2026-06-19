# Censys

`censys` · **import** connector · category **OSINT**

Imports internet/attack-surface data from Censys (https://search.censys.io). Each host becomes an ASSET (IP, OS), each exposed service a SERVICE (host:port), and detected software CPEs are linked to the asset. Offline mode: parse a Censys hosts export / API JSON (a list of hosts, or a v2 hosts-search `{result:{hits:[...]}}` response). Live mode: if `query` is set and CENSYS_API_ID / CENSYS_API_SECRET are in the worker env, calls the v2 hosts search API (needs `pip install requests`). Read-only OSINT (non-intrusive). No DB access in run.py (worker-safe).

**Upstream:** https://search.censys.io

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Censys hosts JSON (export or v2 hosts-search response) to import. |
| `query` | string | no | — | Live mode: Censys hosts search query (e.g. `services.service_name: HTTP and location.country: FR`). Needs CENSYS_API_ID/SECRET in the worker env. |
| `limit` | int | no | `200` | Live mode: maximum number of hosts to import. (range 1–1000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Censys*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:censys`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/censys/sample.json --connector censys
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
