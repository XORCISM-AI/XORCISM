# HexStrike AI

`hexstrike-ai` · **import** connector · category **Exploitation**

Imports findings from HexStrike AI (https://github.com/0x4m4/hexstrike-ai), an MCP server (Python, MIT) that lets AI agents (Claude, GPT, Copilot…) autonomously run 150+ offensive security tools across recon, web, network, auth/password, binary RE, cloud/container and CTF/forensics for automated pentesting, vulnerability discovery and bug-bounty. Import-only: export a run's findings/vulnerability cards to JSON and this connector maps each to an XORCISM finding — the affected target/host/URL becomes an ASSET and each issue a VULNERABILITY / ASSETVULNERABILITY (ref = CVE when referenced, else HEXSTRIKE-<hash>; severity from the finding's risk level). Defensive parser: accepts a findings array or a {findings|vulnerabilities|results|cards|issues:[...]} object. No secrets and no DB access in run.py (worker-safe). NOTE: run HexStrike AI itself only against systems you are authorized to test.

**Upstream:** https://github.com/0x4m4/hexstrike-ai

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to a HexStrike AI findings export (JSON) to import. |
| `target` | string | no | — | Default asset name for findings whose record carries no target/host/URL. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *HexStrike AI*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:hexstrike-ai`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/hexstrike-ai/sample.json --connector hexstrike-ai
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
