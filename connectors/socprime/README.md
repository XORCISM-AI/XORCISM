# SOC Prime — Detection content (Sigma)

`socprime` · **import** connector · category **threat-intel**

Imports detection content (Sigma rules) from SOC Prime's Threat Detection Marketplace / Platform (https://socprime.com) — the world's largest library of curated, behavior-based detections. Each Sigma rule is imported into XTHREAT.SIGMARULE (idempotent by rule reference), where it boosts the Threat-Informed Defense 'detect' pillar and Purple-Team coverage; AND it is recorded as an XTHREAT.INTELEXCHANGE item so the detection shows in the intel feed and its MITRE ATT&CK techniques (from the rule's `tags: attack.tXXXX`) are cross-linked into INTELEXCHANGEATTACK for ATT&CK coverage. Read-only, non-intrusive, Python stdlib only (PyYAML used if installed, else a built-in Sigma field extractor). Live mode needs the worker env var SOCPRIME_API_KEY (and optional SOCPRIME_API_URL). Offline import is supported via the 'file'/'path' parameter — a single Sigma .yml file, a directory of .yml rules, or a JSON list/export of rules.

**Upstream:** https://socprime.com

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `path` | file | no | — | Offline mode: a Sigma rule file (.yml), a directory of Sigma rules, or a JSON list/export of rules to import. Worker-local. |
| `file` | file | no | — | Alias of 'path' (a saved SOC Prime / Sigma export JSON). |
| `max_items` | int | no | `200` | Maximum number of detection rules to import. (range 1–5000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *SOC Prime — Detection content (Sigma)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:socprime`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/socprime/sample.json --connector socprime
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
