# ANSSI AD Control Paths

`anssi-ad-control-paths` · **import** connector · category **Identity Security**

Imports the output of ANSSI's AD Control Paths (github.com/ANSSI-FR/AD-control-paths) — analysis of Active Directory access-control relationships that reveal hidden privilege-escalation / takeover paths to high-value objects (Domain Admins, the domain root, etc.). Pass a relationship CSV exported by the tooling (a `*.csv` of source -> target via a control right). Each AD object becomes an ASSET (tagged ad/identity) and each control relationship becomes a VULN finding (an identity attack path) on the target object. Read-only (no DB access in run.py).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to an AD-control-paths relationship CSV (columns auto-detected: source/target/right). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *ANSSI AD Control Paths*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:anssi-ad-control-paths`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
