# Nikto — Web server scanner

`nikto` · **tool-runner** connector · category **web** · ⚠️ **intrusive** (engagement scope enforced)

Scanner de serveur web : fichiers/répertoires dangereux, versions obsolètes, mauvaises configurations. Importe les constats dans VULNERABILITY / ASSETVULNERABILITY.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | yes | — | URL ou hôte cible (dans le périmètre autorisé) |
| `maxtime` | int | no | `600` | durée maximale du scan (secondes) (range 60–3600) |

## How it works

This is a **tool-runner** connector. It executes the `nikto` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
nikto -h {{target}} -Format json -output {{outfile}} -ask no -maxtime {{maxtime}}
```

Output: **file** (`.json`), parsed by `parse_nikto.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *Nikto — Web server scanner*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:nikto`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/nikto/sample.json --connector nikto
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
