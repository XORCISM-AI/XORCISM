# Semgrep — SAST (SARIF)

`semgrep` · **tool-runner** connector · category **appsec**

Runs Semgrep static analysis on a local source path and imports the results via OASIS SARIF (shared SARIF parser). The scanned project becomes an ASSET; each Semgrep finding becomes a finding (VULNERABILITY / ASSETVULNERABILITY) with severity from the rule's security-severity / level. Non-intrusive local code scan; no secrets. Install on the worker: pip install semgrep (or use the semgrep binary on PATH).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `source` | string | yes | — | Path on the worker to scan (a file or directory). |
| `config` | string | no | `auto` | Semgrep ruleset: 'auto', a registry id (e.g. p/ci), or a rules path (default: auto). |
| `project` | string | no | — | Application/asset name to attach the findings to (default: derived from the source / SARIF). |

## How it works

This is a **tool-runner** connector. It executes the `semgrep` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
semgrep scan --quiet --sarif --output {{outfile}} --config {{config}} {{source}}
```

Output: **file** (`.sarif`), parsed by `parse_semgrep.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *Semgrep — SAST (SARIF)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:semgrep`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
