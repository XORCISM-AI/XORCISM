# RedRoom

`redroom` · **import** connector · category **OSINT**

RedRoom (github.com/Owlinkai/redroom, by Owlink.ai) — an open-source real-time news OSINT platform: a command-and-control-style intelligence dashboard for geopolitical analysis (live feed with sentiment + threat classification, 3D threat globe, RSS crawler, satellite/SIGINT tracking, AI narrative detection for information operations). This connector imports RedRoom's classified intelligence feed and maps each item to an XORCISM threat-intel record (XTHREAT.INTELEXCHANGE): headline -> IntelName, summary + classification -> description, source link -> reference, with sentiment / threat-level / region / narrative as tags and any referenced CVE extracted. Worker-safe: parses an exported feed file, or reads a configured read-only RedRoom API; no DB access.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | A RedRoom feed export in JSON (an array, or an object with items/feed/data/articles/results[]). If omitted, the REDROOM_URL / REDROOM_API_KEY env (worker) is read. |
| `limit` | number | no | — | Maximum number of feed items to import (default 500). |
| `min_threat` | string | no | — | Only import items at or above this threat level (low\|medium\|high\|critical). Default: low (all). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *RedRoom*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:redroom`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
