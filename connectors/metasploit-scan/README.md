# Metasploit (RPC) — network scan

`metasploit-scan` · **import** connector · category **recon** · ⚠️ **intrusive** (engagement scope enforced)

Scan réseau via Metasploit RPC (msfrpcd) : exécute « db_nmap -sV » sur la cible puis importe hôtes/services/vulnérabilités (CVE) dans XORCISM. Configuration par variables d'environnement du worker : MSF_RPC_PASS (requis), MSF_RPC_HOST (déf. 127.0.0.1), MSF_RPC_PORT (déf. 55553), MSF_RPC_USER (déf. msf), MSF_RPC_SSL (déf. true). Requiert msfrpcd lancé et la lib Python pymetasploit3.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | yes | — | IP / hôte / CIDR (dans le périmètre autorisé) |
| `ports` | string | no | — | Ports nmap (ex. 1-1000 ou 22,80,443). Vide = défaut nmap. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Metasploit (RPC) — network scan*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:metasploit-scan`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
