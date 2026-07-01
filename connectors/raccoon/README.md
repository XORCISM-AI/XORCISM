# Raccoon

`raccoon` · **import** connector · category **Recon** · ⚠️ **intrusive** (engagement scope enforced)

Imports reconnaissance results from Raccoon, the offensive reconnaissance & information-gathering framework (https://github.com/evyatarmeged/Raccoon): DNS/subdomain enumeration, host (nmap) port scan, DNS records, TLS data, web-application fingerprint and URL/dir fuzzing. Each discovered host/subdomain becomes an ASSET (hostname + resolved IP) and each open port a service on the target — recon output is attack surface, so it maps to ASSET/services (not the threat-intel exchange). Offline mode: point `dir` at a Raccoon results folder (raccoon_scan_results/<target>/) or `file` at a single subdomains list. Live mode: if `target` is set and the `raccoon` binary is on the worker PATH, runs Raccoon and parses its output. No DB access in run.py (worker-safe). Run live only within an authorised engagement scope; Raccoon actively scans ports and fuzzes URLs.

**Upstream:** https://github.com/evyatarmeged/Raccoon

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `dir` | string | no | — | Path on the worker to a Raccoon results directory (e.g. raccoon_scan_results/example.com/). Parses subdomains, DNS records, host/port scan, TLS, web scan and URL fuzz files found under it. |
| `file` | file | no | — | Offline mode: a single Raccoon subdomains file (one hostname per line) to import. |
| `target` | target | no | — | Live mode: host or domain to scan with the local `raccoon` binary (raccoon --outdir <tmp> <target>). Only within an authorised scope. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Raccoon*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:raccoon`.
- **Self-test** — parse **and import** the bundled `sample.txt` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/raccoon/sample.txt --connector raccoon
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
