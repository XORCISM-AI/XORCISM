# Naabu

`naabu` · **import** connector · category **Network Scanning** · ⚠️ **intrusive** (engagement scope enforced)

Imports open-port results from ProjectDiscovery naabu (https://github.com/projectdiscovery/naabu). Each scanned host becomes an ASSET (host + IP) and each open port a SERVICE (host:port). Offline mode: parse a naabu JSON-lines output (`naabu -json`) or a plain `host:port` list. Live mode: if `target` is set and the `naabu` binary is on the worker PATH, runs `naabu -json` against it. Intrusive (active port scan) — run live only within an authorised engagement scope. No DB access in run.py (worker-safe).

**Upstream:** https://github.com/projectdiscovery/naabu

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a naabu `-json` output file (or a plain host:port list) to import. |
| `target` | string | no | — | Live mode: a host/CIDR (or path to a hosts file) to scan with the local `naabu` binary. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Naabu*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:naabu`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/naabu/sample.json --connector naabu
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
