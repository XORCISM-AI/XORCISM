# Chainguard

`chainguard` · **import** connector · category **Container Security**

Imports container-image vulnerability results from Chainguard (https://www.chainguard.dev) — minimal, low-CVE Wolfi-based images and the chainctl platform. The scanned image becomes an ASSET, each package a component, and each vulnerability a VULNERABILITY / ASSETVULNERABILITY (ref = CVE/GHSA, severity). Offline mode: import a Grype JSON report (`grype <image> -o json`, the scanner Chainguard tooling uses), an `{images:[{name,vulnerabilities:[...]}]}` export, or a flat findings list. Live mode: if `image` is set and the `chainctl` or `grype` binary is on the worker, scans it. Optional env CHAINGUARD_TOKEN for chainctl auth. No DB access in run.py (worker-safe).

**Upstream:** https://www.chainguard.dev

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Chainguard/Grype JSON vulnerability report to import. |
| `image` | string | no | — | Live mode: an image ref to scan with the local grype/chainctl binary (also used as the ASSET name). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Chainguard*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:chainguard`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/chainguard/sample.json --connector chainguard
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
