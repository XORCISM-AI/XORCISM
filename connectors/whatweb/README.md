# WhatWeb — Web technology fingerprint

`whatweb` · **tool-runner** connector · category **web** · ⚠️ **intrusive** (engagement scope enforced)

Identification des technologies web (serveur, frameworks, CMS…). Importe les technos en CPE liés à l'asset.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | yes | — | URL ou hôte (dans le périmètre) |
| `aggression` | enum | no | `1` | 1=passif, 3=agressif (one of: `1`, `3`) |

## How it works

This is a **tool-runner** connector. It executes the `whatweb` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
whatweb -a {{aggression}} --log-json={{outfile}} {{target}}
```

Output: **file** (`.json`), parsed by `parse_whatweb.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *WhatWeb — Web technology fingerprint*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:whatweb`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/whatweb/sample.json --connector whatweb
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
