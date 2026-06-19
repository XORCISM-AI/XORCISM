# WPScan — WordPress security scanner

`wpscan` · **tool-runner** connector · category **web** · ⚠️ **intrusive** (engagement scope enforced)

Scanner de sécurité WordPress : version du cœur, plugins/thèmes vulnérables, utilisateurs. Importe les vulnérabilités (CVE quand disponible) dans VULNERABILITY / ASSETVULNERABILITY. Astuce : un jeton WPScan (~/.wpscan ou --api-token côté worker) enrichit la base de vulnérabilités.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | url | yes | — | URL du site WordPress (dans le périmètre autorisé) |
| `enumerate` | enum | no | `vp,vt,u` | vp=plugins vulnérables, vt=thèmes vulnérables, ap/at=tous, u=utilisateurs (one of: `vp,vt,u`, `vp,vt`, `ap,at,u`, `vp`, `u`) |

## How it works

This is a **tool-runner** connector. It executes the `wpscan` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
wpscan --url {{target}} --format json --output {{outfile}} --no-banner --random-user-agent --enumerate {{enumerate}}
```

Output: **file** (`.json`), parsed by `parse_wpscan.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *WPScan — WordPress security scanner*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:wpscan`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/wpscan/sample.json --connector wpscan
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
