# Lyra — CTI / OSINT digital-risk monitor

`lyra` · **import** connector · category **OSINT**

Defensive OSINT / digital-risk-protection monitoring with Lyra (CTI Monitor by K3lgy, https://github.com/K3lgy/lyra). Lyra scans ~10 open-web / OSINT sources (Have I Been Pwned, DeHashed, VirusTotal, URLScan.io, Shodan, GitHub, paste sites, Google dorks, Ransomware.live, crt.sh) for public mentions, leaked credentials and exposed infrastructure of an organisation, scores each finding (CRITIQUE/ÉLEVÉ/MOYEN/FAIBLE) and exports a JSON report. This connector maps that report to the XORCISM model: discovered hosts / subdomains / IPs become ASSETs, Shodan-exposed services become SERVICEs, and each finding becomes a redacted exposure (VULN) on the relevant asset (or the monitored organisation as a fallback). For defensive use on YOUR OWN organisation only. Read-only (non-intrusive): no DB access in run.py (worker-safe). API keys are read from the worker ENVIRONMENT, never the UI: LYRA_HIBP, LYRA_VIRUSTOTAL, LYRA_SHODAN, LYRA_URLSCAN, LYRA_DEHASHED, LYRA_DEHASHED_EMAIL. Lyra's location: LYRA_PATH (default C:\tools\lyra\lyra.py) or `lyra.py` on PATH; live mode needs Python 3.8+ and `pip install requests` on the worker. Offline mode: pass a saved lyra_report.json via the 'file' parameter (no network, no keys).

**Upstream:** https://github.com/K3lgy/lyra

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `name` | string | no | — | Organisation / company name under monitoring (labels findings; fallback asset). Required for live mode. |
| `domains` | string | no | — | Comma-separated domains you own (e.g. acme.com,acme.fr). Drives HIBP / crt.sh / Shodan / VirusTotal. |
| `emails` | string | no | — | Comma-separated organisation email addresses to check for breach exposure. |
| `brands` | string | no | — | Comma-separated brand / product names to search for public mentions. |
| `keywords` | string | no | — | Extra search keywords (registration numbers, internal code names…). |
| `file` | file | no | — | Offline mode: path on the worker to a saved Lyra JSON report (lyra_report.json) to import instead of running a live scan. |
| `limit` | int | no | `1000` | Maximum number of findings to import. (range 1–20000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Lyra — CTI / OSINT digital-risk monitor*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:lyra`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/lyra/sample.json --connector lyra
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
