# Amass

`amass` · **import** connector · category **Recon** · ⚠️ **intrusive** (engagement scope enforced)

Imports attack-surface / subdomain enumeration results from OWASP Amass (https://github.com/owasp-amass/amass). Each discovered name becomes an ASSET (hostname + resolved IP). Offline mode: parse an `amass enum -json` output file (JSON lines or array). Live mode: if `domain` is set and the `amass` binary is on the worker PATH, runs `amass enum -d <domain> -json`. No DB access in run.py (worker-safe). Run live only within an authorised engagement scope.

**Upstream:** https://github.com/owasp-amass/amass

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to an `amass enum -json` output file (JSON lines or a JSON array) to import. |
| `domain` | string | no | — | Live mode: domain to enumerate with the local `amass` binary (amass enum -d <domain> -json). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Amass*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:amass`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/amass/sample.json --connector amass
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
