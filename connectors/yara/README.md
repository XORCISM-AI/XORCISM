# YARA

`yara` · **import** connector · category **Malware Analysis**

Pattern-matching engine to identify and classify malware. Tool: https://github.com/VirusTotal/yara. This connector scans a path with YARA and maps each match to a finding on the host asset; if a rules file is supplied, the rules are also imported into XTHREAT.YARARULE (the YARA rule store browsable in the explorer and served to XOR agents).

**Upstream:** https://github.com/VirusTotal/yara

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | no | — | Live mode: a file or directory path to scan with YARA (engagement scope enforced). Requires the yara binary on the worker PATH and a 'rules' file. |
| `rules` | file | no | — | YARA rules file (.yar/.yara) — used to scan (live mode) AND imported into the YARARULE store. |
| `file` | file | no | — | Offline mode: a saved YARA scan output to parse instead of running the tool (default `rule /path` lines). |
| `host` | string | no | — | Asset name to attach the match findings to (defaults to the worker hostname). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *YARA*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:yara`.
- **Self-test** — parse **and import** the bundled `sample.txt` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/yara/sample.txt --connector yara
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
