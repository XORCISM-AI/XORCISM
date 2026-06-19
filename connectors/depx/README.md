# depx — malicious package / supply-chain audit

`depx` · **tool-runner** connector · category **sbom**

Audits local lockfiles and SBOMs for KNOWN MALICIOUS packages (supply-chain compromise) with ProjectDiscovery depx, cross-referencing the OpenSSF Malicious Packages dataset and a live intelligence feed (hijacked publishes, credential stealers, install-script backdoors, typosquats). Imports the audited project as an ASSET and each malicious-package advisory as a finding (VULNERABILITY / ASSETVULNERABILITY); affected packages are recorded as components/CPEs. Non-intrusive: local read of dependency files + advisory lookups. Requires no secrets/env vars. Install the binary on the worker: curl -sfL https://raw.githubusercontent.com/projectdiscovery/depx/main/scripts/install.sh | sh

**Upstream:** https://raw.githubusercontent.com/projectdiscovery/depx/main/scripts/install.sh

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `source` | string | yes | — | Path on the worker to audit: a project directory, a lockfile (package-lock.json, yarn.lock, requirements.txt, go.sum, Gemfile.lock…) or an SBOM (CycloneDX/SPDX). |
| `project` | string | no | — | Application/asset name to attach the findings to (optional; default « depx audit »). |

## How it works

This is a **tool-runner** connector. It executes the `depx` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
depx audit {{source}} --json --output {{outfile}}
```

Output: **file** (`.json`), parsed by `parse_depx.py` into the normalized `{assets, services, cpes, vulns}` result.

## Running it

- **From XORCISM** — open **Connectors**, choose *depx — malicious package / supply-chain audit*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:depx`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/depx/sample.json --connector depx
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
