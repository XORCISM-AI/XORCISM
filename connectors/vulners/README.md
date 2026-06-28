# Vulners connector

Imports vulnerability intelligence from [Vulners](https://vulners.com/) (a database of 3M+ enriched CVEs,
exploits and advisories) into XORCISM as VULNERABILITY findings.

## Modes
- **search** — a Vulners Lucene query or product → `/api/v3/search/lucene`
  (`--query "affectedSoftware.name:openssl"`, `--query "type:exploit log4j"`)
- **id** — a CVE / bulletin id → `/api/v3/search/id` (`--cve CVE-2021-44228`)
- **audit** — a Linux host's OS + installed packages → `/api/v3/audit/audit` (Vulners' agentless package
  audit; pass `--os ubuntu --osversion 22.04 --packages "$(dpkg-query -W -f='${Package} ${Version} ${Architecture}\n')"`)

## Mapping
- each bulletin / referenced CVE → **VULN** (ref = CVE, severity from CVSS, exploit bulletins flagged)
- the audit target host (or query) → **ASSET**

## Auth
Requires a Vulners API key: pass `--apiKey …` or set `VULNERS_API_KEY` in the worker environment.

## Offline
Pass `--file saved-response.json` to normalise a previously-saved Vulners JSON response without any network
call (useful for air-gapped pipelines and testing). The in-app **/vuln-assessment** page does the same kind
of audit against XORCISM's own enriched store with no API key.

`run.py` uses only the stdlib (urllib) and does no DB access (worker-safe).
