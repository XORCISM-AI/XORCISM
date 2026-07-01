# Zphisher

`zphisher` · **import** connector · category **Security Awareness**

Imports the results of an AUTHORISED phishing-simulation exercise run with Zphisher (https://github.com/htr-tech/zphisher) into XORCISM Security Awareness. Point `dir` at a Zphisher session/`auth` folder (or `file` at a single output file): the connector reads the visitor IP log (page opened / clicked) and the captured-credential log (credentials submitted) and normalizes them into a PHISHINGSIMULATION campaign with per-recipient PHISHINGRESULT outcomes — feeding the Phish-Prone % and human-risk scoring. Recipients are matched to PERSON by e-mail where possible. run.py does NOT run Zphisher or capture anything itself and performs no DB writes (the runner writes); it only parses output you already collected during an authorised engagement. Use only for internal awareness testing with consent.

**Upstream:** https://github.com/htr-tech/zphisher

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `dir` | string | no | — | Path on the worker to a Zphisher session / auth folder to parse (its visitor IP log + captured-credential log). |
| `file` | file | no | — | A single Zphisher output file (e.g. ip.txt or usernames.dat) to parse instead of a folder. |
| `campaign_name` | string | no | — | Name for the phishing-simulation campaign this import records (default: 'Zphisher simulation'). |
| `template` | string | no | — | The Zphisher template/theme used (e.g. Facebook, Instagram, Microsoft) — recorded on the campaign. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Zphisher*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:zphisher`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
