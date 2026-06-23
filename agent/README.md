# XOR — Endpoint agent (enhanced EDR) for XORCISM

**Cross-OS** agent (Windows / macOS / Linux) in **pure Python (stdlib only)**:
copy `xor_agent.py` to the endpoint, enroll it, done.

## Capabilities
| Function | Detail |
|---|---|
| **Enrollment → ASSET** | the endpoint registers with XORCISM and becomes an ASSET (hostname). |
| **Software inventory → CPE** | Windows (registry), Linux (`dpkg`/`rpm`), macOS (`system_profiler`) → CPEs linked to the asset (`CPEFORASSET`). |
| **Vulnerabilities → ASSETVULNERABILITY** | server-side CPE→CVE correlation (NVD database) → asset↔CVE links. |
| **Configuration / compliance (OVAL/SCAP)** | OpenSCAP (`oscap`) when present (Linux **and Windows** — 1.3.x build); **on Windows without oscap, a built-in native OVAL evaluator** (registry, files, OS family, environment variables, WMI) — hardening, compliance and vulnerabilities. Otherwise, built-in checks (firewall, BitLocker, SSH…). |
| **Antivirus** | ClamAV (`clamscan`/`clamdscan`) when installed → detections reported. |
| **Threat hunting** | pulls the **IOCs** (threat intel) from the server and hunts them locally (processes, network connections, files, hashes). |
| **BAS emulation + detection attribution** | executes a Threat-Informed Defense **validation plan** (`--scan emulate --scenario N`): runs the scenario's Atomic Red Team injects, then **correlates each executed inject with the host's detection telemetry** (Defender threats / Defender, Sysmon, PowerShell-ScriptBlock & Security-4688 event logs) in the post-inject window → outcome **Detected** / **Logged** / **Executed** (ran undetected — a visibility gap) / **Prevented** / **Skipped**, with the source in `DetectedBy` → `EMULATIONRUN`/`EMULATIONRESULT`. **Opt-in & two-tier**: `XOR_ALLOW_EMULATION=1` auto-runs only read-only recon (writes / persistence / downloads / credential-dumping / exec-chains reported `Skipped`); **`XOR_ALLOW_ATOMIC_EXEC=1`** (stronger; set per host by the operator) runs the **full atomic-test command** for authorized BAS/AEV — real ATT&CK procedures — while manual injects stay `Skipped`. The admin still controls which scenario/techniques are assigned. |
| **Advanced forensics (live DFIR triage)** | `--scan forensics` collects a **read-only live-response snapshot** of the host — running processes (path / command line / parent), network connections (with PID & state), persistence (registry autoruns / scheduled tasks / services / cron / systemd), logon sessions & users, recently-modified files in key dirs, network artifacts (ARP / DNS cache / routes), loaded drivers / kernel modules and an event-log summary (failed logons, system errors). Cross-OS, stdlib-only, bounded; collection **never modifies the host**. Conservative heuristics raise triage **flags** (a process or autorun running from a temp dir, a failed-logon spike) → `XAGENT.FORENSICTRIAGE` + a `forensic_triage` event. |
| **Rustinel EDR bridge (kernel-level ETW/eBPF detection)** | `--scan rustinel` **tails** the alert log of [**Rustinel**](https://github.com/Karib0u/rustinel) — an open-source cross-platform EDR sensor that collects native telemetry via **ETW** (Windows), **eBPF** (Linux) and **Endpoint Security** (macOS) and matches it against **Sigma** rules, **YARA** signatures and **atomic IOCs**, writing **ECS-compatible NDJSON** alerts. The agent reads Rustinel's `logs/alerts.json.<date>` and ships each new alert to XORCISM as a `rustinel_alert` **event** (severity from the Sigma level; rule id / engine / process / host / MITRE technique in the detail). This is the **kernel-level "native ETW/eBPF core"** from the roadmap below — delivered by *integrating* Rustinel rather than reimplementing it. **Read-only** (the agent only reads alert files; it never controls the sensor) and a **per-file byte cursor** (persisted in the conf) forwards only *new* alerts across log rotations. Graceful no-op when Rustinel isn't installed. |
| **YARA scanning (malware classification)** | `--scan yara` runs the local **YARA** engine against a path using rules from XORCISM's **YARARULE store** (served at `/api/agent/yara-rules`) or a local rules file (`XOR_YARA_RULES`), and reports each match as a `yara_match` **event**. Targets default to temp + Downloads (override with `XOR_YARA_TARGET`). Read-only, bounded; a graceful no-op when the `yara` binary or rules are absent. |
| **Memory acquisition (RAM dump for forensics)** | `--scan memdump` captures a full **RAM image** for forensics using a privileged tool (**winpmem** on Windows, **avml** on Linux, or `XOR_MEMDUMP_BIN`). The image stays on the endpoint (preserved in place for **chain of custody**); only the **acquisition manifest** — tool, output path, size, **SHA-256**, total RAM — is shipped → `XAGENT.MEMORYDUMP` + a `memory_dump` event. Streamed chunked hashing (never loads GBs into memory). Output dir via `--memdump-dir` / `XOR_MEMDUMP_DIR`; degrades gracefully to a `no-tool` report (with install guidance) when no tool/admin. Read-only DFIR. |
| **AI log hunting (local-AI threat hunt)** | `--scan loghunt` collects recent host logs — **Sysmon / PowerShell / Security / System / Defender** event channels on Windows (`Get-WinEvent`); **journald** + `/var/log/auth.log` on Linux — and ships them to the server, where a heuristic pass + the **local AI (Ollama)** hunt them for threats (encoded PowerShell, LOLBins, LSASS dumping, log clearing…), map them to **MITRE ATT&CK** → `XAGENT.LOGHUNT` + a `log_hunt` event, and **spawn a TaHiTI hunt** when suspicious. Sources via `--log-sources sysmon,powershell,security`, cap via `--max-events`. No host data leaves the box — the AI is the *local* Ollama. |
| **Honeypot (deception sensor)** | `--scan honeypot` runs a bounded **honeypot** on decoy TCP ports (SSH/RDP/SMB/DB/web/…), logging every connection attempt (source IP/port, target port, banner) for a capped window → `XAGENT.HONEYPOTHIT` + a `honeypot_hit` event, and **attacker source IPs become IOCs**. Pure deception — it never executes anything the client sends. Ports/duration via `--honeypot-ports` / `--honeypot-duration`. |
| **AI-agent guardrails (`aiguard`)** | `--scan aiguard` **discovers** the LLM apps / AI agent frameworks running on the host (LangChain, CrewAI, AutoGen, LlamaIndex, Semantic Kernel, Ollama/local models, **MCP servers**, AI SDKs) and reports **guardrail signals** (which guardrail libs are installed, whether tools/agency are used, API keys exposed in the env, MCP configs, container sandboxing). The server scores each against the **AI Guardrail Baseline** (12 controls mapped to OWASP AI Exchange / SAIF / ISO 42001 / OWASP LLM Top 10 / MITRE ATLAS / NIST AI RMF) → `XAGENT.AIAGENT` / `AIGUARDRAILRESULT`, and — with optional AI traces (`XOR_AI_TRACE_GLOB`) — monitors them with the local AI for guardrail **violations** (prompt injection, jailbreak, exfiltration, excessive agency) → `AIGUARDRAILVIOLATION` + a spawned hunt. Read-only, best-effort discovery; surfaced at **/ai-guardrails**. |
| **On-demand scan** | runs the **"Launch a scan"** scans triggered from the XORCISM ASSET window (at the next check-in). |

## Threat intelligence (IOC)
The IOCs served to agents come from XORCISM's CTI and are loaded into
`XAGENT.XIOC` by [`connectors/import_iocs.py`](../connectors/import_iocs.py):
- **STIX 2.1** (files imported / received on the **TAXII** server, `stix/` folder),
- **AlienVault OTX** and other **CTI connectors/feeds** (`--otx-key` / `OTX_API_KEY`),
- (extensible) objects from the **XTHREAT** database.

```bash
python connectors/import_iocs.py --stix-dir stix            # from STIX/TAXII
python connectors/import_iocs.py --otx-key $OTX_API_KEY     # from AlienVault OTX
```

## Configuration scan (OVAL / SCAP)
The `oval` scan evaluates **OVAL/SCAP** content and reports classified verdicts
(*compliance* / *vulnerability* / *inventory* / *patch*) → `XOVAL.OVALRESULTS`
(+ `ASSETVULNERABILITY`/`CPEFORASSET`), surfaced on the **Configuration Management** page.

Three engines, selected automatically:
1. **OpenSCAP `oscap`** when present — Linux **and Windows alike** (the OpenSCAP 1.3.x
   installer ships `oscap.exe` with the Windows probes: registry, files…).
2. **Native OVAL evaluator** (built-in, no dependency) on **Windows without oscap**:
   parses the OVAL definitions and evaluates them against the system (registry via
   `winreg`, files, OS family, environment variables, WMI), with the OVAL result algebra.
   Force this engine even when oscap is present: `XOR_OVAL_NATIVE=1` (useful when oscap's
   Windows probe coverage is incomplete). *XCCDF datastreams are not yet evaluated
   natively — they require oscap.*
3. **Built-in checks**, portable, as a last resort (firewall, BitLocker/FileVault, SSH).

The **OVAL content** comes (in order) from `XOR_OVAL_CONTENT` (local file) →
the XORCISM server (`/api/agent/oval-content`, fed by
`importers/fetch_oval_content.py`) → `XOR_OVAL_URL` → distro feed (Linux).

An OVAL scan evaluates every class in the content by default; restrict it to a single
class with `--oval-class` (or, from the **Configuration Management** page, the *OVAL class*
selector — which queues the scan with that class on the chosen host):

```bash
python xor_agent.py --scan oval                              # all classes in the content
python xor_agent.py --scan oval --oval-class compliance      # hardening only
python xor_agent.py --scan oval --oval-class vulnerability   # CVE checks only
XOR_OVAL_NATIVE=1 python xor_agent.py --scan oval            # Windows: force the native evaluator
XOR_OVAL_CONTENT=C:\path\win-cis.oval.xml python xor_agent.py --scan oval
```

## Rustinel EDR bridge (kernel-level detection)

The agent's own detection is **poll-based** (it samples `tasklist`/`ps`, `netstat`, the registry…
at scan time). [**Rustinel**](https://github.com/Karib0u/rustinel) is a continuous **kernel-level**
sensor (ETW / eBPF / Endpoint Security) that matches live telemetry against **Sigma**, **YARA** and
**IOC** engines and writes ECS NDJSON alerts. Running both gives XORCISM the best of each: deploy
Rustinel as the always-on sensor, and let the XOR agent forward its detections.

```bash
python xor_agent.py --scan rustinel        # forward new Rustinel alerts as events (also part of --scan full)
XOR_RUSTINEL_GLOB="/var/log/rustinel/alerts.json*" python xor_agent.py --scan rustinel
```

- **Discovery** — by default the agent looks in the usual Rustinel install locations
  (`C:\Program Files\Rustinel\logs\…`, `/var/log/rustinel/…`, `/opt/rustinel/logs/…`, …). Override
  with **`XOR_RUSTINEL_GLOB`** (one or more glob patterns, `os.pathsep`-separated).
- **Mapping** — each ECS alert → a `rustinel_alert` event: severity from the Sigma `rule.level`
  (`critical`/`high`/`medium`/`low`/`info`), with `rule.id`, the matching engine (sigma/yara/ioc),
  `process`, `host` and the MITRE `threat.technique.id` carried in the detail.
- **Exactly-once tailing** — a per-file byte **cursor** is stored in `xor_agent.conf`
  (`rustinel_offsets`), so each run forwards only alerts written since the last run, and a rotated/
  truncated file restarts cleanly. The forward is **read-only** — the agent never controls Rustinel.
- **Graceful** — if no alert file is found, the scan is a no-op (it just reports that Rustinel
  isn't installed). `--scan full` includes this step, so a routine full scan also drains new alerts.

## YARA scanning (malware classification)

XORCISM is the source of YARA rules: the **YARARULE store** (`XTHREAT.YARARULE`) is populated
by [`import_yara.py`](../xorcism_python/importers/import_yara.py) or the **yara connector**, and
served to agents at `GET /api/agent/yara-rules`. `--scan yara` pulls those rules, runs the local
`yara` binary against the host, and reports matches as `yara_match` events:

```bash
python xor_agent.py --scan yara                                  # rules from XORCISM, scan default paths
XOR_YARA_RULES=/opt/rules/malware.yar python xor_agent.py --scan yara   # use a local rules file
XOR_YARA_TARGET="/srv:/home" python xor_agent.py --scan yara            # custom scan targets
```

- **Rules** — `XOR_YARA_RULES` (a local `.yar`/`.yara` file) wins; otherwise the agent fetches the
  YARARULE store from XORCISM and writes it to a temp file. No rules ⇒ nothing to scan.
- **Targets** — `XOR_YARA_TARGET` (`os.pathsep`-separated) or the defaults (temp + Downloads).
- **Requirement** — the `yara` binary on `PATH`. Not installed ⇒ graceful no-op. Read-only; the
  scan never modifies files. **Part of `--scan full`** (no-op when `yara`/rules are absent); the
  default targets keep it light — point `XOR_YARA_TARGET` at a broader path for a deep sweep.

## AI-agent guardrails (`--scan aiguard`)
The operational layer for guarding the **LLM apps / autonomous AI agents** running on a host
(surfaced at **/ai-guardrails**). The agent **discovers** AI agents and reports guardrail signals;
the server scores them against the **AI Guardrail Baseline** and (with traces) hunts for guardrail
violations with the **local AI**.

- **Discovery** — installed AI frameworks (`importlib.metadata`): LangChain, LangGraph, LlamaIndex,
  CrewAI, AutoGen, Semantic Kernel, OpenAI/Anthropic SDKs, LiteLLM, Haystack, DSPy; the **Ollama**
  local model; **MCP server** configs (Cursor / Claude Desktop / Windsurf); and exposed LLM **API
  keys** in the environment (counted, never sent). Per detected framework it reports `framework`,
  `model`, `guardrailLibs` (NeMo Guardrails / LLM Guard / Guardrails AI / Llama Guard / Rebuff /
  Lakera), whether it uses **tools** / is **autonomous** / has **memory**, secrets exposed, MCP
  count, logging and container sandboxing.
- **Assessment** — the server scores each agent against the **12-control AI Guardrail Baseline**
  (runtime guardrail engine, input/output filtering, tool allow-listing, human-in-the-loop,
  sandboxing, secrets hygiene, audit logging, …), cross-mapped to **OWASP AI Exchange · Google SAIF
  · ISO/IEC 42001 · OWASP LLM Top 10 · MITRE ATLAS · NIST AI RMF** → `XAGENT.AIAGENT` /
  `AIGUARDRAILRESULT`.
- **Monitoring** — set `XOR_AI_TRACE_GLOB` to your agent's prompt/tool-call logs and the local AI
  flags **prompt injection / jailbreak / data exfiltration / excessive agency** → `AIGUARDRAILVIOLATION`
  + a spawned **TaHiTI** hunt. Raw prompts are analysed by the *local* Ollama and never leave the host.
- **Enforcement** is delegated to an inline guardrail **gateway** (NeMo / LLM Guard / Llama Guard /
  Lakera); its block telemetry is imported by the `llm-guard` connector and shows up in the same
  cockpit. The endpoint agent verifies *posture*; the gateway does the *gating*.

```bash
python xor_agent.py --scan aiguard                                   # discover + assess AI agents
XOR_AI_TRACE_GLOB="/var/log/myagent/*.log" python xor_agent.py --scan aiguard   # + runtime monitoring
```

## DFIR — memory dump, AI log hunt & honeypot
```bash
python xor_agent.py --scan memdump                                  # RAM acquisition (winpmem/avml) → manifest+SHA-256
python xor_agent.py --scan memdump --memdump-dir /forensics         # custom output dir (image stays on host)
python xor_agent.py --scan loghunt                                  # collect host logs → local-AI threat hunt → ATT&CK
python xor_agent.py --scan loghunt --log-sources sysmon,powershell  # pick the log sources
python xor_agent.py --scan honeypot --honeypot-duration 600         # deception sensor on decoy ports (attacker IPs → IOCs)
```
- **memdump** needs a memory-acquisition tool on the endpoint (**winpmem** on Windows, **avml** on
  Linux) and admin/root; without one it reports `no-tool` with install guidance. The image is
  preserved **in place** for chain of custody — only the manifest (size + SHA-256) is shipped.
- **loghunt** is richest with **Sysmon** + **PowerShell ScriptBlock** logging enabled; otherwise it
  falls back to the channels it can read. The AI narrative needs Ollama reachable from the *server*;
  the deterministic ATT&CK heuristics run regardless.

## Quick start (endpoint)
```bash
# 1) Enrollment (the server may require a key: XOR_ENROLL_KEY)
python xor_agent.py --server https://xorcism.example:9292 --enroll [--enroll-key KEY] [--insecure]

# 2) Scans
python xor_agent.py --scan full          # inventory + vuln + compliance + AV + hunt + Rustinel + YARA
python xor_agent.py --inventory          # inventory only
python xor_agent.py --once               # one check-in (runs the scans requested from the ASSET)

# 3) Daemon (periodic check-in)
python xor_agent.py --run --interval 300
```
The token is stored in `xor_agent.conf` (next to the script).

## XORCISM server side
- Agent API (token): `/api/agent/{enroll,checkin,inventory,vulnerabilities,events,match,intel}`.
- Inventory/vuln reports go through the existing **import pipeline**
  (`runner.py` → `import_findings`): run the local runner to ingest
  (`python connectors/runner.py`).
- UI: **ASSET window → "XOR agent — launch a scan"**; agents/events via
  `/api/agents`, `/api/agent-events`.

## Deploying as a service
Keep the agent checking in across reboots. See [`SETUP.md`](SETUP.md) §9 for full steps.
- **Linux**: `install/xor-agent.service` (systemd).
- **macOS**: `install/com.xorcism.xor.plist` (launchd).
- **Windows (no dependency)**: `install/install_xor_agent.bat <server-url> [enroll-key]` —
  self-elevates, enrolls, and registers a boot-start SYSTEM **scheduled task** ("XORCISM XOR
  Agent") with no time limit and auto-restart. Subcommands: `status`, `uninstall`.
- **Windows (real `services.msc` service)**: `install/install_xor_agent_service.bat` (via
  [NSSM](https://nssm.cc/download)) or the [WinSW](https://github.com/winsw/winsw) config
  `install/xor-agent-service.xml`. Use **one** Windows option, not several.
- **Standalone binary**: `pyinstaller --onefile xor_agent.py` produces a per-OS
  executable (no Python dependency required on the target).

## Scope & roadmap
This agent provides **host-based detection** (telemetry + IOC) and full integration
with XORCISM. For kernel-level "real-time" detection (ETW/eBPF hooks), the **Rustinel EDR
bridge** above now covers it — the agent forwards Rustinel's ETW/eBPF/ESF Sigma/YARA/IOC
alerts as XORCISM events, so you get a native kernel sensor without a custom core. Still on
the roadmap for a self-contained native agent: **active response** (process blocking,
network isolation, anti-tamper) — the server API and event model are designed to host it.
