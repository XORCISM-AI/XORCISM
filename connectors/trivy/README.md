# Trivy

`trivy` · **import** connector · category **Container Security**

Imports vulnerability scan results from Aqua Trivy (https://github.com/aquasecurity/trivy). The scanned artifact (container image, filesystem or repo) becomes an ASSET, each package a component (CPE), and each finding a vulnerability (VULNERABILITY / ASSETVULNERABILITY) mapped by CVE with severity. Offline mode: parse a Trivy JSON report (`trivy ... -f json`). Live mode: if `source` is set and the `trivy` binary is on the worker PATH, runs `trivy image|fs --format json <source>`. Non-intrusive local scan. No DB access in run.py (worker-safe).

**Upstream:** https://github.com/aquasecurity/trivy

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Trivy JSON report (`trivy ... -f json -o report.json`) to import. |
| `source` | string | no | — | Live mode: an image ref or path to scan with the local `trivy` binary. |
| `project` | string | no | — | Asset name to attach the findings to (default: the report's ArtifactName). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Trivy*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:trivy`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/trivy/sample.json --connector trivy
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
