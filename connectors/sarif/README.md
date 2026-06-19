# SARIF — import static-analysis results

`sarif` · **import** connector · category **appsec**

Imports an OASIS SARIF 2.1.0 document (Static Analysis Results Interchange Format) produced by any compatible tool — CodeQL, Semgrep, Bandit, ESLint, Trivy, Grype, Checkov, gitleaks, nuclei -sarif, and more. The analyzed project/repository becomes an ASSET; each SARIF result becomes a finding (VULNERABILITY / ASSETVULNERABILITY) with severity from the SARIF level or the security-severity property, and the tool, rule, message and file:line in the description. A CVE referenced by a rule/result is used as the finding reference (otherwise a stable SARIF-<rule> ref is derived). Read-only file import, no secrets. Point 'file' at a .sarif/.json on the worker.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to a SARIF (.sarif/.json) document to import. |
| `project` | string | no | — | Application/asset name to attach the findings to (default: derived from the SARIF repository URI / tool name). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *SARIF — import static-analysis results*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:sarif`.
- **Self-test** — parse **and import** the bundled `sample.sarif` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/sarif/sample.sarif --connector sarif
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
