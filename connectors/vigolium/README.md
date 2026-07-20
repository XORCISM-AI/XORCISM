# Vigolium connector

Imports findings from [Vigolium](https://github.com/vigolium/vigolium) (AGPL-3.0) into XORCISM.

Vigolium is a high-fidelity web vulnerability scanner "fusing agentic AI with native speed" — a Go
engine with **317 scanner modules** (SQLi, XSS, SSTI, command injection, IDOR/BOLA, path traversal,
SSRF, XXE, misconfiguration, race conditions…) covering the OWASP Top 10, an **agentic mode**
(autopilot / swarm with pluggable LLM providers), OAST/interactsh out-of-band testing for blind
bugs, multi-session authenticated scanning, and source-code audit drivers.

## What it maps to

| Vigolium | XORCISM | Path |
|---|---|---|
| Finding target host | `ASSET` | runner `assets` → `import_findings` |
| Each finding (name, severity, CWE/CVSS, URL) | `XVULNERABILITY.VULNERABILITY` (+ `ASSETVULNERABILITY`) | runner `vulns` → `import_findings` |

Findings then feed the exposure-fusion score, Tenable VPR, SSVC, the Unified Exposure queue, the
attack-path graph and the Enterprise Risk Score — and Vigolium is wired into the pentest
attack-chain (`chain.ts`): when nmap finds a web service, the chain escalates to a Vigolium scan.

Severity maps critical/high/medium/low/info → Critical/High/Medium/Low/Info. A CVE anywhere in the
finding becomes the vuln reference; otherwise a stable `VIGOLIUM-<id>` ref is synthesised. CWE and
remediation are preserved in the description; CVSS, when present, is carried through.

## Modes

1. **File.** `file` = a Vigolium export. Produce one with `vigolium scan -t https://target --format jsonl -o out.jsonl`. The parser accepts JSONL (one finding per line), a JSON array, or `{"findings":[...]}` / `{"results":[...]}`.
2. **Live.** `target` = a URL, with `VIGOLIUM_SERVER` (default `http://localhost:9002`) + optional `VIGOLIUM_API_KEY` pointing at a running `vigolium server`. Falls back to a clear "export to file" message if the server is unreachable.
3. **Demo.** No input → the bundled `sample.jsonl` (6 findings: XSS, SQLi, IDOR/BOLA, blind SSRF, missing headers, banner).

Secrets come from the worker environment, never UI params.

```bash
python connectors/vigolium/run.py                                     # demo
python connectors/runner.py --selftest out.jsonl --connector vigolium # a real export
```

> **Authorised testing only.** Vigolium is an active scanner (this connector is marked `intrusive`).
> Only run it against targets you are authorised to assess.
