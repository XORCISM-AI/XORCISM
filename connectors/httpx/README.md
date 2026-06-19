# httpx

`httpx` · **import** connector · category **Recon** · ⚠️ **intrusive** (engagement scope enforced)

Imports HTTP probe results from ProjectDiscovery httpx (https://github.com/projectdiscovery/httpx). Each probed host becomes an ASSET (hostname + resolved IP), each live URL a SERVICE, and detected technologies are recorded as CPE-like components. Offline mode: parse an httpx JSON-lines output (`httpx -json`). Live mode: if `target` is set and the `httpx` binary is on the worker PATH, runs `httpx -json -silent` against it. Run live only within an authorised engagement scope. No DB access in run.py (worker-safe).

**Upstream:** https://github.com/projectdiscovery/httpx

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to an httpx JSON-lines output file (`httpx -json`) to import. |
| `target` | string | no | — | Live mode: a host/URL (or path to a hosts file) to probe with the local `httpx` binary. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *httpx*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:httpx`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/httpx/sample.json --connector httpx
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
