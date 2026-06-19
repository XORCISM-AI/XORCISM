# Jaeles — web vulnerability scan (signatures)

`jaeles` · **tool-runner** connector · category **vuln** · ⚠️ **intrusive** (engagement scope enforced)

Automated web-application vulnerability scanning with Jaeles signatures. Each matched signature becomes a finding (VULNERABILITY / ASSETVULNERABILITY) on the target asset; CVE ids referenced by a signature are used as the reference. Intrusive — run only against authorized targets (the engagement scope is enforced by the runner). Install on the worker: go install github.com/jaeles-project/jaeles@latest, then `jaeles config init` to fetch signatures.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | url | yes | — | Target URL within the authorized engagement scope (e.g. https://example.com). |
| `level` | int | no | `1` | Signature level filter (1 = safest … 5 = most intrusive). (range 1–5) |
| `concurrency` | int | no | `20` | Concurrent threads. (range 1–100) |

## How it works

This is a **tool-runner** connector. It executes the `jaeles` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
jaeles scan -u {{target}} --level {{level}} -c {{concurrency}}
```

Output: **stdout**, parsed by `parse_jaeles.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *Jaeles — web vulnerability scan (signatures)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:jaeles`.
- **Self-test** — parse **and import** the bundled `sample.txt` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/jaeles/sample.txt --connector jaeles
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
