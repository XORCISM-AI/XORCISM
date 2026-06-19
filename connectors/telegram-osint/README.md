# Telegram OSINT (Dark Web Informer)

`telegram-osint` · **import** connector · category **OSINT**

Imports Telegram OSINT investigations from telegram_osint (Dark Web Informer edition, https://github.com/DarkWebInformer/telegram_osint). The tool profiles Telegram users, channels and groups (Telethon) and exports a structured JSON file (./exports/*.json) for the user / chat / members / search modes. This connector ingests that JSON export and maps it into the XORCISM model: the investigated subject (user / channel / group) becomes an ASSET (tg:<handle|title>); shared / linked real domains become host ASSETs; and notable items become findings (VULN) — a scam/fake/restricted flag, a keyword-search hit (snippet truncated), and investigative pivots (other @handles, t.me links, external/social links). Privacy-aware: phone numbers and personal names are NOT imported as findings — only handles, links, domains, risk flags and truncated keyword snippets. Read-only import (no DB access in run.py, worker-safe). Live collection needs Telegram API credentials + Telethon + interactive auth on YOUR account, so this connector is import-only: run telegram_osint.py yourself (`--export json`) and pass the exported JSON via the 'file' parameter.

**Upstream:** https://github.com/DarkWebInformer/telegram_osint

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to a telegram_osint JSON export (exports/<name>_<mode>_<ts>.json) — user / chat / members / search. |
| `limit` | int | no | `500` | Maximum number of findings to import (keyword hits / pivots / shared domains). (range 1–20000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Telegram OSINT (Dark Web Informer)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:telegram-osint`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/telegram-osint/sample.json --connector telegram-osint
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
