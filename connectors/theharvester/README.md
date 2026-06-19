# theHarvester

`theharvester` · **import** connector · category **OSINT**

Imports OSINT recon results from theHarvester (https://github.com/laramies/theHarvester). Discovered hosts and IP addresses become ASSETs (hostname + IP). Offline mode: parse a theHarvester JSON output file (`theHarvester -f <name>` → <name>.json). Live mode: if `domain` is set and the `theHarvester` binary is on the worker PATH, runs `theHarvester -d <domain> -b <sources> -f`. Read-only OSINT (non-intrusive). No DB access in run.py (worker-safe).

**Upstream:** https://github.com/laramies/theHarvester

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a theHarvester JSON output file to import. |
| `domain` | string | no | — | Live mode: domain to harvest with the local `theHarvester` binary. |
| `sources` | string | no | `all` | Live mode: theHarvester sources passed to -b (default: all). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *theHarvester*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:theharvester`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/theharvester/sample.json --connector theharvester
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
