# Nmap — Network & service scan

`nmap` · **tool-runner** connector · category **recon** · ⚠️ **intrusive** (engagement scope enforced)

Découverte d'hôtes, ports, services, versions, OS et CPE. Importe les résultats dans ASSET / services / CPE.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | yes | — | hôte, plage ou CIDR (doit être dans le périmètre autorisé) |
| `ports` | string | no | `1-1000` | ex. 22,80,443 ou 1-1024 |
| `scan` | enum | no | `-sV` | type de scan (one of: `-sS`, `-sT`, `-sV`, `-A`) |
| `timing` | enum | no | `-T3` | one of: `-T2`, `-T3`, `-T4` |
| `os_detect` | bool | no | `False` | détection d'OS (-O, nécessite des privilèges) |

## How it works

This is a **tool-runner** connector. It executes the `nmap` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
nmap {{scan}} {{timing}} -p {{ports}} -oX {{outfile}} {{target}}
```

Output: **file** (`.xml`), parsed by `parse_nmap.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *Nmap — Network & service scan*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:nmap`.
- **Self-test** — parse **and import** the bundled `sample.xml` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/nmap/sample.xml --connector nmap
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
