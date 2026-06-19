# WPProbe

`wpprobe` · **import** connector · category **Web** · ⚠️ **intrusive** (engagement scope enforced)

Imports WordPress plugin/theme & vulnerability findings from WPProbe (https://github.com/Chocapikk/wpprobe). The scanned site becomes an ASSET (host); each detected plugin/theme + version becomes a component/CPE on it; each correlated CVE becomes a VULNERABILITY (CVE ref + severity). Offline mode: parse a WPProbe JSON export (`wpprobe scan -u <url> -o out.json`). Live mode: if `target` is set and the `wpprobe` binary is on the worker PATH, runs a scan and parses its JSON. Active web scanning (intrusive). No DB access in run.py (worker-safe).

**Upstream:** https://github.com/Chocapikk/wpprobe

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a WPProbe JSON export to import (offline mode). |
| `target` | target | no | — | Live mode: WordPress site URL to scan with the local `wpprobe` binary (must be in the engagement scope). |
| `mode` | string | no | `stealthy` | Live mode: scan mode passed to wpprobe (stealthy \| bruteforce \| hybrid). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *WPProbe*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:wpprobe`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
