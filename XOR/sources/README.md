# XOR — Endpoint agent (enhanced EDR) for XORCISM

**Cross-OS** agent (Windows / macOS / Linux) in **pure Python (stdlib only)**:
copy `xor_agent.py` onto the endpoint, enroll it, and you're done.

## Capabilities
| Function | Detail |
|---|---|
| **Enrollment → ASSET** | the endpoint registers with XORCISM and becomes an ASSET (hostname). |
| **Software inventory → CPE** | Windows (registry), Linux (`dpkg`/`rpm`), macOS (`system_profiler`) → CPEs linked to the asset (`CPEFORASSET`). |
| **Vulnerabilities → ASSETVULNERABILITY** | CPE→CVE correlation server-side (NVD database) → asset↔CVE links. |
| **Configuration / compliance** | OpenSCAP (`oscap`) if present, otherwise built-in checks (firewall, disk encryption, SSH…). **OVAL**-extensible. |
| **Antivirus** | ClamAV (`clamscan`/`clamdscan`) if installed → detections reported. |
| **Threat hunting** | fetches **IOCs** (threat intel) from the server and hunts them locally (processes, network connections, files, hashes). |
| **On-demand scan** | runs the **"Launch a scan"** scans triggered from the ASSET window in XORCISM (at the next check-in). |

## Threat intelligence (IOCs)
The IOCs served to agents come from XORCISM CTI and are loaded into
`XAGENT.XIOC` by [`connectors/import_iocs.py`](../connectors/import_iocs.py):
- **STIX 2.1** (files imported / received on the **TAXII** server, `stix/` folder),
- **AlienVault OTX** and other **CTI connectors/feeds** (`--otx-key` / `OTX_API_KEY`),
- (extensible) objects from the **XTHREAT** database.

```bash
python connectors/import_iocs.py --stix-dir stix            # from STIX/TAXII
python connectors/import_iocs.py --otx-key $OTX_API_KEY     # from AlienVault OTX
```

## Quick start (endpoint)
```bash
# 1) Enrollment (the server may require a key: XOR_ENROLL_KEY)
python xor_agent.py --server https://xorcism.example:9292 --enroll [--enroll-key KEY] [--insecure]

# 2) Scans
python xor_agent.py --scan full          # inventory + vuln + compliance + AV + hunt
python xor_agent.py --inventory          # inventory only
python xor_agent.py --once               # one check-in (runs scans requested from the ASSET)

# 3) Daemon (periodic check-in)
python xor_agent.py --run --interval 300
```
The token is stored in `xor_agent.conf` (next to the script).

## XORCISM server side
- Agent API (token): `/api/agent/{enroll,checkin,inventory,vulnerabilities,events,match,intel}`.
- Inventory/vuln reports go through the existing **import pipeline**
  (`runner.py` → `import_findings`): run the local runner to ingest
  (`python connectors/runner.py`).
- UI: **ASSET → "XOR agent — launch a scan"** window; agents/events via
  `/api/agents`, `/api/agent-events`.

## Service deployment
- **Linux**: see `install/xor-agent.service` (systemd).
- **macOS**: see `install/com.xorcism.xor.plist` (launchd).
- **Windows**: Task Scheduler (at startup) or NSSM for a service.
- **Standalone binary**: `pyinstaller --onefile xor_agent.py` produces a
  per-OS executable (no Python dependency required on the target).

## Scope & roadmap
This agent provides **host-based detection** (telemetry + IOCs) and full
integration with XORCISM. For a "real-time" kernel-level EDR (ETW/eBPF hooks,
process blocking, network isolation), plan for a native core (Go/Rust) — the
server API and the event model above are designed to host it.
