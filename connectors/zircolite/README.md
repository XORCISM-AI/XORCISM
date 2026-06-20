# Zircolite

`zircolite` · **import** connector · category **DFIR**

Imports detections from Zircolite (https://github.com/wagga40/Zircolite), a standalone SIGMA-based detection tool for logs (Windows EVTX/XML/JSONL, Auditd, Sysmon for Linux, CSV, JSON array). Each log source's Computer/host becomes an ASSET and every fired Sigma rule becomes a finding (VULNERABILITY / ASSETVULNERABILITY) with the rule level as severity and the ATT&CK technique(s) embedded in the finding name. Offline mode: import a Zircolite JSON report (`zircolite.py ... -o detected_events.json`). Live mode: if `events` and `ruleset` are set and Zircolite is on the worker (env ZIRCOLITE_PATH, default C:\tools\Zircolite\zircolite.py, else `zircolite` on PATH; optional env ZIRCOLITE_RULESET), runs `zircolite --events <events> --ruleset <ruleset> -o <out>` and parses the result. Non-intrusive local log triage. No secrets. No DB access in run.py (worker-safe).

**Upstream:** https://github.com/wagga40/Zircolite

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Zircolite JSON report (`zircolite.py ... -o detected_events.json`) to import. |
| `events` | string | no | — | Live mode: path to the logs to scan (EVTX/XML/JSONL/Auditd/Sysmon/CSV/JSON file or folder). |
| `ruleset` | string | no | — | Live mode: path to the Sigma ruleset (JSON or YAML) Zircolite should use (or set env ZIRCOLITE_RULESET). |
| `host` | string | no | — | Default asset name for detections whose log events carry no Computer/host field. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Zircolite*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:zircolite`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/zircolite/sample.json --connector zircolite
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
