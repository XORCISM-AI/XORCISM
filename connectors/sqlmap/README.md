# sqlmap — SQL injection

`sqlmap` · **tool-runner** connector · category **web** · ⚠️ **intrusive** (engagement scope enforced)

Détection d'injections SQL. Chaque point d'injection est importé en VULNERABILITY liée à l'asset cible.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | url | yes | — | URL à tester (ex. http://app.lab/item?id=1) |
| `level` | enum | no | `1` | Profondeur des tests (one of: `1`, `2`, `3`, `4`, `5`) |
| `risk` | enum | no | `1` | Niveau de risque des payloads (one of: `1`, `2`, `3`) |

## How it works

This is a **tool-runner** connector. It executes the `sqlmap` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
sqlmap -u {{target}} --batch --level {{level}} --risk {{risk}} --flush-session --disable-coloring
```

Output: **stdout**, parsed by `parse_sqlmap.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *sqlmap — SQL injection*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:sqlmap`.
- **Self-test** — parse **and import** the bundled `sample.txt` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/sqlmap/sample.txt --connector sqlmap
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
