# OpenSCAP — SCAP/OVAL/XCCDF compliance & vulnerability

`openscap` · **import** connector · category **Compliance**

Imports an OpenSCAP (https://www.open-scap.org) report into the XORCISM model. Run `oscap` yourself and pass the output file: OVAL results (`oscap oval eval --results res.xml <oval.xml>`), XCCDF results (`oscap xccdf eval --results res.xml <ds.xml>`) or an ARF report (`--results-arf arf.xml`, which bundles both). The scanned host becomes an ASSET; OVAL vulnerability-class `true` definitions become VULN findings (the referenced CVE), OVAL inventory-class `true` become CPE (installed software), and failed XCCDF rules become VULN findings (compliance gaps). Read-only import (no DB access in run.py, worker-safe). This is the file-based counterpart of the XOR agent's live OVAL scan (/api/agent/oval).

**Upstream:** https://www.open-scap.org

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to an oscap report: OVAL results, XCCDF results, or an ARF (.xml) report. |
| `target` | string | no | — | Asset name/host for the report (default: the report's host name, else the file name). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *OpenSCAP — SCAP/OVAL/XCCDF compliance & vulnerability*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:openscap`.
- **Self-test** — parse **and import** the bundled `sample.xml` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/openscap/sample.xml --connector openscap
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
