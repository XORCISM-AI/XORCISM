# BloodHound

`bloodhound` · **import** connector · category **Active Directory**

Imports Active Directory computer objects collected for BloodHound (https://github.com/SpecterOps/BloodHound) into XORCISM as ASSETs. Parse a SharpHound / BloodHound `computers.json` (or any export with `data[].Properties.name`): each computer becomes an ASSET (FQDN hostname + operating system). Offline import of already-collected data — non-intrusive, no DB access in run.py (worker-safe).

**Upstream:** https://github.com/SpecterOps/BloodHound

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to a SharpHound/BloodHound computers JSON file (computers.json) to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *BloodHound*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:bloodhound`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/bloodhound/sample.json --connector bloodhound
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
