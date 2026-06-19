# MITRE Caldera — adversary emulation (agents & opérations)

`caldera` · **import** connector · category **adversary-emulation**

Se connecte à un serveur MITRE Caldera (API v2) : importe les agents déployés en ASSET et les abilities exécutées lors des opérations en findings (technique ATT&CK liée à l'hôte). Lecture seule. Config UNIQUEMENT par variables d'environnement : CALDERA_URL + CALDERA_API_KEY.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `operation` | string | no | — | Filtre par nom ou ID d'opération (vide = toutes les opérations) |
| `agents_only` | bool | no | `False` | N'importer que l'inventaire des agents (ignore les résultats d'opérations) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *MITRE Caldera — adversary emulation (agents & opérations)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:caldera`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
