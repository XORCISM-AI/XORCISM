# Sn1per — automated recon & attack surface

`sn1per` · **tool-runner** connector · category **recon** · ⚠️ **intrusive** (engagement scope enforced)

Automated reconnaissance / attack-surface scan with Sn1per. The target becomes an ASSET, discovered open ports/services become CPEs linked to it, and any CVEs found become findings. Intrusive — run only against authorized targets (the engagement scope is enforced by the runner); pick the least-intrusive mode that fits your authorization. Install Sn1per on the worker (https://github.com/1N3/Sn1per) and ensure it runs non-interactively.

**Upstream:** https://github.com/1N3/Sn1per

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | yes | — | Target host / domain / IP within the authorized engagement scope. |
| `mode` | enum | no | `stealth` | Sn1per scan mode (stealth = least intrusive). (one of: `stealth`, `discover`, `web`, `port`) |

## How it works

This is a **tool-runner** connector. It executes the `sniper` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
sniper -t {{target}} -m {{mode}}
```

Output: **stdout**, parsed by `parse_sn1per.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *Sn1per — automated recon & attack surface*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:sn1per`.
- **Self-test** — parse **and import** the bundled `sample.txt` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/sn1per/sample.txt --connector sn1per
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
