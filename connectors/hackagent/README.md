# HackAgent

`hackagent` · **import** connector · category **AI Security**

Imports AI-agent attack-evaluation results from HackAgent (https://github.com/AISecurityLab/hackagent), a security-testing toolkit (Python, Apache-2.0) that probes AI agents for prompt injection, jailbreaking, goal hijacking and tool misuse using AdvPrefix, AutoDAN-Turbo, PAIR, TAP, FlipAttack, BoN, h4rm3l, CipherChat, PAP and Baseline techniques. Import-only: export results to JSON and this connector maps each AI agent under test to an ASSET and every SUCCESSFUL attack to a VULNERABILITY / ASSETVULNERABILITY (ref = HACKAGENT-<category>-<hash>; severity by attack category — jailbreak/prompt-injection/goal-hijack/tool-misuse = high, others = medium). Defensive parser: accepts a results array or a {results|runs|attacks|evaluations:[...]} object; only successful/failed-defence attacks become findings. No secrets and no DB access in run.py (worker-safe).

**Upstream:** https://github.com/AISecurityLab/hackagent

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to a HackAgent results export (JSON) to import. |
| `agent` | string | no | — | Default asset name for the AI agent under test when a result carries no agent/target name. |
| `all` | bool | no | `False` | Import every attempt as a finding, not only the successful attacks (default: successful only). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *HackAgent*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:hackagent`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/hackagent/sample.json --connector hackagent
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
