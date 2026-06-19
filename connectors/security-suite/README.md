# Security Suite

`security-suite` · **import** connector · category **Pentest** · ⚠️ **intrusive** (engagement scope enforced)

Imports recon & scan results from Security Suite (https://github.com/TheSecuredAnalyst/security-suite), an all-in-one Python offensive toolkit (OSINT recon, web/API scanners, vuln scanning). Discovered subdomains/hosts and IPs become ASSETs; detected technologies become services/CPEs; scanner findings (XSS, SQLi, SSL/TLS, etc.) become VULNERABILITIES. Offline mode: parse a Security Suite JSON export (`secsuite ... --json -o <file>`). Live mode: if a `target` is set and the `secsuite` binary is on the worker PATH, runs a scan and parses its JSON. Active scanning (intrusive). No DB access in run.py (worker-safe).

**Upstream:** https://github.com/TheSecuredAnalyst/security-suite

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Security Suite JSON export to import (offline mode). |
| `target` | target | no | — | Live mode: domain, host, IP or URL to scan with the local `secsuite` binary (must be in the engagement scope). |
| `command` | string | no | `scan` | Live mode: secsuite subcommand to run against the target (default: scan). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Security Suite*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:security-suite`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
