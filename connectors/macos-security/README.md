# NIST macOS Security (mSCP) connector

Imports the results of a [**NIST macOS Security Compliance Project**](https://pages.nist.gov/macos_security/)
(mSCP, [usnistgov/macos_security](https://github.com/usnistgov/macos_security)) baseline compliance
scan into XORCISM's GRC layer (`XCOMPLIANCE`, via `runner.import_compliance`).

mSCP generates hardening **baselines** for Apple platforms (macOS / iOS / iPadOS / visionOS); each
baseline ships a **compliance script** that audits a Mac and writes results, with every rule mapped
to **NIST SP 800-53**. This connector ingests that output — **it does not run the scan** — and
records a **Compliance AUDIT** with one **AUDITFINDING per failed rule** (severity + 800-53
references), surfaced at [`/compliance-management`](../../xorcism_ts/server/compliance.ts) and
`/compliance`.

## Input (`file`, else bundled `sample.json`)

1. **Results JSON** (richest — carries titles, severity, 800-53 refs):

   ```json
   { "baseline": "800-53r5_high", "os": "macOS 14", "host": "mac01",
     "results": [
       { "rule_id": "os_firewall_enable", "title": "Enable the Application Firewall",
         "result": "fail", "severity": "high",
         "references": { "800-53r5": ["SC-7", "AC-4"] }, "discussion": "…" }
     ] }
   ```

2. **The mSCP audit plist** `org.<baseline>.audit.plist` (XML or binary) — `{rule_id: {finding: bool}}`
   where `finding == true` means the rule **failed**. Parsed with stdlib `plistlib`. (Sparse: no
   titles/severity/refs — pass a results JSON for those.)

3. **The compliance-script console summary** (text) — `rule_id … passed|failed|exempt` lines.

`result` values: `pass` / `fail` / `exempt` (also tolerates `finding: true|false`).

## Output → `XCOMPLIANCE`

```json
{ "source": "NIST macOS Security (mSCP)",
  "compliance": { "benchmark": "macOS Security (mSCP)", "baseline": "…", "os": "…", "host": "…",
                  "results": [ { "rule_id", "title", "result", "severity", "references", "discussion" } ] } }
```

`import_compliance` creates/updates one `AUDIT` per `baseline` + `host` (idempotent by name) and one
`AUDITFINDING` per **failed** rule (idempotent by `Source = "mscp:<rule_id>"`). The audit
description carries the compliant/total tally; passing rules are counted but not stored as findings.

## Modes

* **Offline** — `file=<audit plist | results JSON | summary text>`, or no config → bundled `sample.json`.

Worker-safe: stdlib only (`json`, `plistlib`, `re`), ASCII-only output, no database access.

## Quick test

```bash
python connectors/macos-security/run.py
```
