# Nuclei — Template-based vulnerability scan

`nuclei` · **tool-runner** connector · category **vuln** · ⚠️ **intrusive** (engagement scope enforced)

Scan de vulnérabilités piloté par templates (ProjectDiscovery). Importe les findings dans VULNERABILITY / ASSETVULNERABILITY.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | yes | — | URL ou hôte cible (dans le périmètre autorisé) |
| `severity` | enum | no | `medium,high,critical` | niveaux de sévérité à inclure (one of: `info,low,medium,high,critical`, `medium,high,critical`, `high,critical`, `critical`) |
| `rate_limit` | int | no | `150` | requêtes/seconde (range 1–1000) |
| `timeout` | int | no | `10` | timeout par requête (s) (range 1–60) |

## How it works

This is a **tool-runner** connector. It executes the `nuclei` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
nuclei -target {{target}} -severity {{severity}} -rate-limit {{rate_limit}} -timeout {{timeout}} -jsonl -silent -output {{outfile}}
```

Output: **file** (`.jsonl`), parsed by `parse_nuclei.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *Nuclei — Template-based vulnerability scan*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:nuclei`.
- **Self-test** — parse **and import** the bundled `sample.jsonl` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/nuclei/sample.jsonl --connector nuclei
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
