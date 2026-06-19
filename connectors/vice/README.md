# VICE — web-app security auditor (SAST + DAST)

`vice` · **import** connector · category **Web Scanner** · ⚠️ **intrusive** (engagement scope enforced)

Security audit with VICE (vice-security, https://github.com/Webba-Creative-Technologies/vice) — a black-box & white-box auditor for web applications. White-box: audits a project directory (source code, .env exposure, npm audit, Supabase RLS, SQLi/XSS). Black-box: crawls a URL, extracts secrets from JS bundles, tests login for brute-force / SQLi, scans ports. VICE emits SARIF, so this connector maps its findings into the XORCISM model via the shared SARIF parser: the audited project / scanned host becomes an ASSET and each finding becomes a VULN (ref = CVE if referenced, else VICE-<rule>@<file:line>; severity from the SARIF security-severity / level). Read-only import (worker-safe, no DB access in run.py). Offline mode: pass a saved VICE SARIF report via the 'file' parameter. Live mode runs VICE (Node ≥18 + `npm install` in the clone, or `npm install -g vice-security`); locate it via VICE_PATH (default C:\tools\vice\bin\vice.js) or `vice` on PATH; VICE_ACCEPT_TERMS=1 is set automatically.

**Upstream:** https://github.com/Webba-Creative-Technologies/vice

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `source` | string | no | — | White-box: path on the worker to a project directory to audit (e.g. /srv/app). Maps to `vice audit <source>`. |
| `url` | url | no | — | Black-box: a URL in scope to scan (e.g. https://app.example.com). Maps to `vice scan --url <url>`. Intrusive — engagement scope is enforced. |
| `file` | file | no | — | Offline: path on the worker to a saved VICE SARIF report to import instead of running a scan. |
| `min_score` | int | no | `0` | White-box audit: VICE --min-score threshold (0 imports all findings). (range 0–100) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *VICE — web-app security auditor (SAST + DAST)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:vice`.
- **Self-test** — parse **and import** the bundled `sample.sarif` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/vice/sample.sarif --connector vice
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
