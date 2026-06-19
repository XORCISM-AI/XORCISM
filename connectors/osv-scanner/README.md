# OSV-Scanner — dependency vulnerability scan

`osv-scanner` · **tool-runner** connector · category **sbom**

Analyse des lockfiles, SBOM et répertoires de code pour les vulnérabilités connues via OSV.dev (Google). Importe les composants et les vulnérabilités dans XORCISM (VULNERABILITY / ASSETVULNERABILITY). Non intrusif : lecture locale + requêtes à OSV.dev.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `source` | string | yes | — | Chemin à analyser sur le worker : répertoire de projet, lockfile (package-lock.json, requirements.txt, go.mod…) ou SBOM |
| `project` | string | no | — | Nom de l'application/asset de rattachement (optionnel ; défaut « OSV-Scanner scan ») |

## How it works

This is a **tool-runner** connector. It executes the `osv-scanner` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
osv-scanner --format json --output {{outfile}} --recursive {{source}}
```

Output: **file** (`.json`), parsed by `parse_osv.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *OSV-Scanner — dependency vulnerability scan*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:osv-scanner`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/osv-scanner/sample.json --connector osv-scanner
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
