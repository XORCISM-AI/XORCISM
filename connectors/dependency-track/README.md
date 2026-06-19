# OWASP Dependency-Track — SBOM (CycloneDX)

`dependency-track` · **import** connector · category **sbom**

Gestion des SBOM : lit un SBOM CycloneDX (composants → CPE/PURL liés à l'application, vulnérabilités → VULNERABILITY). Mode API optionnel : pousse le SBOM vers Dependency-Track et récupère les findings (DTRACK_URL + DTRACK_API_KEY).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Chemin du SBOM CycloneDX (.json) sur le worker |
| `project` | string | no | — | Nom du projet/application (défaut : metadata.component.name du SBOM) |
| `version` | string | no | `1.0` | Version du projet (mode API) |
| `api` | bool | no | `False` | Pousser vers Dependency-Track et récupérer les findings (DTRACK_URL/DTRACK_API_KEY) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *OWASP Dependency-Track — SBOM (CycloneDX)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:dependency-track`.
- **Self-test** — parse **and import** the bundled `sample.cdx.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/dependency-track/sample.cdx.json --connector dependency-track
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
