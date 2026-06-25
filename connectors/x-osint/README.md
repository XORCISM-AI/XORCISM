# X-OSINT connector

Imports the output of [**X-OSINT**](https://github.com/TermuxHackz/X-osint) — an open-source
OSINT framework for Termux/Linux that gathers intelligence on a **phone number, email, username
or domain** (VIN OSINT, reverse phone/email, subdomain enumeration, email-from-name) — into
XORCISM's threat-intel exchange (`XTHREAT.INTELEXCHANGE`, via `runner.import_threat_intel`).

X-OSINT is an interactive CLI with no stable API, so this connector ingests the **output of a
run** rather than driving it live (the same pattern as the `cti-expert` connector). The native
[`/cti-expert`](../../xorcism_ts/server/ctiexpert.ts) cockpit maps OSINT techniques
(VIN / email-from-name) to the `x-osint` connector.

## Input

`run()` accepts, in `file` (or the bundled `sample.json`):

* an **X-OSINT case JSON**

  ```json
  {
    "target": "example.com",
    "kind": "domain",
    "results": [
      { "module": "subdomains", "type": "domain", "value": "mail.example.com", "source": "crt.sh" },
      { "module": "emails", "type": "email", "value": "admin@example.com", "source": "theHarvester" }
    ],
    "phones": [{ "value": "+1 202 555 0142" }]
  }
  ```

  (convenience buckets `subdomains` / `hosts` / `emails` / `phones` / `urls` / `accounts` /
  `ips` / `usernames` are also accepted alongside or instead of `results`), **or**

* the **raw console text** of a run — emails, subdomains/hosts, IPv4s, URLs, phone numbers and
  `@usernames` are extracted with regex (UI banners are ignored). Pass `target` so the import is
  labelled.

## Output

```json
{ "source": "X-OSINT", "intel": [ { "name", "reference", "external_id", "description", "tags" } ] }
```

Each discovered observable becomes one `INTELEXCHANGE` item (`x-osint:<value>` as the idempotent
reference; the X-OSINT module carried in `tags` as `module:<name>`).

## Modes

* **Offline** — `file=<saved export>` (JSON or text), or no config → bundled `sample.json`.

Worker-safe: stdlib only, ASCII-only output, no database access.

## Quick test

```bash
python connectors/x-osint/run.py
```
