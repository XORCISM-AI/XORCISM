# XOR Agent — Setup & Deployment Guide

The **XOR agent** (`xor_agent.py`) is a cross-OS (Windows / macOS / Linux) endpoint agent for
XORCISM, written in **pure Python (standard library only)** — no `pip install` required. Copy one
file to the endpoint, enroll it, and it becomes a managed ASSET that performs inventory,
vulnerability correlation, OVAL/SCAP configuration scanning, antivirus checks, IOC threat-hunting,
(opt-in) BAS emulation with detection attribution, and forwarding of kernel-level
[Rustinel](https://github.com/Karib0u/rustinel) EDR alerts (ETW/eBPF/ESF + Sigma/YARA/IOC).

This guide is the step-by-step setup reference. For the capability overview, see
[`README.md`](README.md).

---

## 1. Requirements

| | |
|---|---|
| **Python** | 3.8+ on the endpoint (`python3 --version`). Windows: the python.org installer or the Microsoft Store build. |
| **Privileges** | Run as a normal user for inventory/hunt. Some OVAL/registry/firewall checks and antivirus need **admin/root** for full coverage. Start least-privilege and elevate only if a check reports "access denied". |
| **Network** | Outbound HTTPS to the XORCISM server (default port `9292`). The agent **polls** the server (check-in) — no inbound port is opened on the endpoint. |
| **Optional tools** | `oscap` (OpenSCAP) for full SCAP/OVAL; `clamscan`/`clamdscan` (ClamAV) for antivirus. Both are auto-detected; the agent degrades gracefully without them. |

> The agent is a single file. There are no dependencies to install. Air-gapped hosts work too
> (offline OVAL content via `XOR_OVAL_CONTENT`/`XOR_OVAL_URL`).

---

## 2. Quick start

```bash
# 1) copy the agent to the endpoint
scp agent/xor_agent.py user@endpoint:/opt/xor/

# 2) enroll it (registers the host as an ASSET, stores a token in the conf file)
python3 xor_agent.py --enroll --server https://xorcism.example:9292 --enroll-key "$XOR_ENROLL_KEY"

# 3) one immediate full check-in (inventory + vuln + OVAL + AV + hunt)
python3 xor_agent.py --scan full

# 4) run as a daemon, checking in every 5 minutes
python3 xor_agent.py --run --interval 300
```

In a lab with a self-signed certificate, add `--insecure` (skips TLS verification — **lab only**).

---

## 3. Enrollment

Enrollment exchanges a one-time **enrollment key** for a persistent **agent token**, and registers
the endpoint as a XORCISM ASSET (by hostname).

```bash
python3 xor_agent.py --enroll \
    --server https://xorcism.example:9292 \
    --enroll-key "<XOR_ENROLL_KEY value configured on the server>"
```

- The server's enrollment key is the env var **`XOR_ENROLL_KEY`** set on the XORCISM server. If the
  server has **no** key set, enrollment is open (dev only — set a key in production).
- On success the agent writes `server`, `token` (and `insecure`) into its **config file** so later
  runs need no flags. Default config path: `xor_agent.conf` next to the script (override with
  `--conf /path/to/xor_agent.conf`).
- The token is a bearer credential — protect the config file (`chmod 600`, restrict ACLs).

`xor_agent.conf` (created by `--enroll`, or copy `xor_agent.conf.example`):

```json
{ "server": "https://xorcism.example:9292", "token": "xor_agent_...", "insecure": false }
```

---

## 4. Configuration — environment variables

All are **optional**. Set them in the service unit / scheduled-task environment.

| Variable | Purpose | Default |
|---|---|---|
| `XOR_ENROLL_KEY` | Enrollment key (alternative to `--enroll-key`). | — |
| `XOR_ALLOW_EMULATION` | **Opt-in** switch for BAS emulation execution (`1` to allow). See §7. | unset (disabled) |
| `XOR_OVAL_FROM_SERVER` | Fetch OVAL content from the XORCISM server at scan time. | `1` (on) |
| `XOR_OVAL_CONTENT` | Path to a local OVAL/SCAP XML file to evaluate (air-gapped). | — |
| `XOR_OVAL_URL` | URL to download OVAL content from. | — |
| `XOR_OVAL_NATIVE` | Force the **built-in** native OVAL evaluator even if `oscap` is present (`1`). | unset |
| `XOR_XCCDF_PROFILE` | XCCDF profile id for `oscap xccdf eval` (e.g. a CIS profile). | auto |
| `XOR_RUSTINEL_GLOB` | Glob pattern(s) for [Rustinel](https://github.com/Karib0u/rustinel)'s ECS NDJSON alert log, `os.pathsep`-separated. See §8c. | auto (common install paths) |
| `XOR_YARA_RULES` | Path to a local YARA rules file (`.yar`/`.yara`); else the agent fetches XORCISM's YARARULE store. See §8d. | server-served |
| `XOR_YARA_TARGET` | Path(s) to scan with YARA, `os.pathsep`-separated. See §8d. | temp + Downloads |

---

## 5. Running modes

| Command | What it does |
|---|---|
| `--enroll` | Register the endpoint and store the token. |
| `--scan full` | One immediate full scan (inventory + vuln + OVAL + AV + hunt). |
| `--scan <kind>` | One scan of a single kind: `inventory`, `vuln`, `oval`, `av`, `hunt`, `emulate`, `forensics`, `rustinel`, `yara`. |
| `--once` | A single check-in (claims and runs any server-queued jobs), then exit. |
| `--run --interval N` | **Daemon**: check in every `N` seconds (default 300) and run queued jobs. |
| `--inventory` | Shortcut for an inventory-only run. |

### OVAL scan class

`--scan oval` accepts `--oval-class {compliance,vulnerability,inventory,patch,all}` to evaluate only
one OVAL definition class (e.g. only hardening/compliance):

```bash
python3 xor_agent.py --scan oval --oval-class compliance
```

Results land in `XOVAL.OVALRESULTS` (plus `ASSETVULNERABILITY`/`CPEFORASSET`) and surface on the
**Configuration Management** page (`/configuration-management`).

---

## 6. OVAL / SCAP engines

The `oval` scan auto-selects an engine:

1. **OpenSCAP `oscap`** when installed — Linux **and Windows** (the OpenSCAP 1.3.x Windows installer
   ships `oscap.exe` with registry/file probes).
2. **Native OVAL evaluator** (built-in, no dependency) on **Windows without oscap** — parses the OVAL
   definitions and evaluates them against the system (registry via `winreg`, files, OS family,
   environment variables, WMI) using the OVAL result algebra. Force it anywhere with
   `XOR_OVAL_NATIVE=1`.
3. **Built-in heuristic checks** (firewall, BitLocker, SSH config…) as a last resort.

Content source order: `XOR_OVAL_CONTENT` → the XORCISM server (`XOR_OVAL_FROM_SERVER=1`) →
`XOR_OVAL_URL`.

---

## 7. BAS emulation & detection attribution (opt-in, safety-gated)

`--scan emulate --scenario <EMULATIONSCENARIO id>` runs a Threat-Informed Defense **validation plan**:
it executes the scenario's Atomic Red Team injects, then correlates each executed inject with the
host's detection telemetry (Defender threats; Defender / Sysmon / PowerShell-ScriptBlock /
Security-4688 event logs on Windows; journald on Linux) and records the outcome (**Detected** /
**Logged** / **Executed** / **Prevented** / **Skipped**) into `EMULATIONRUN`/`EMULATIONRESULT`.

**Safety is paramount — execution is disabled by default:**

- It runs **only** when the operator sets **`XOR_ALLOW_EMULATION=1`**.
- Even then, **only read-only reconnaissance commands are auto-run** (an allowlist:
  `whoami`, `systeminfo`, `ipconfig`, `net config`, `uname`, …).
- Writes, persistence, downloads, credential-dumping, exec-chains and reverse shells are
  **reported `Skipped`** for manual execution — the agent never auto-runs destructive injects.

```bash
XOR_ALLOW_EMULATION=1 python3 xor_agent.py --scan emulate --scenario 12
```

If `XOR_ALLOW_EMULATION` is unset, every inject is recorded `Skipped` (so you can still review the
plan without running anything).

---

## 8. Threat hunting (IOCs)

`--scan hunt` pulls the IOC set the server serves to agents and hunts it locally (processes, network
connections, files, hashes). Populate the server-side IOC store with
[`connectors/import_iocs.py`](../connectors/import_iocs.py) (STIX/TAXII, AlienVault OTX, …).

## 8b. Advanced forensics — live DFIR triage (read-only)

`--scan forensics` collects a **read-only live-response snapshot** of the host and posts it to
`POST /api/agent/forensics` → `XAGENT.FORENSICTRIAGE` (+ a `forensic_triage` event). It captures:

- **Processes** — pid / ppid / name / path / command line.
- **Network connections** — protocol / local / remote / state, with the owning PID.
- **Persistence / autoruns** — Windows registry Run/RunOnce (HKLM + HKCU + Wow6432Node), scheduled
  tasks and running services; Linux crontab + enabled systemd units.
- **Logon sessions & users** — active sessions and recent logins.
- **Recently-modified files** — in Temp / Downloads / Desktop / Startup (Windows) or /tmp, /var/tmp,
  ~/Downloads (Linux), within the last 7 days.
- **Network artifacts** — ARP cache, DNS cache (Windows), routing table.
- **Loaded drivers / kernel modules** and an **event-log summary** (failed logons in 24h, system
  errors).

```bash
python3 xor_agent.py --scan forensics
```

**Safety**: collection is **strictly read-only** — it inspects host state via standard tools
(`tasklist`/`ps`, `netstat`/`ss`, `winreg`, `schtasks`, `arp`, `driverquery`/`lsmod`, …) and **never
modifies the host**. Conservative heuristics raise triage **flags** (a process or autorun running
from a temp directory, a failed-logon spike); flags bump the event severity so a reviewer can pivot
to the full bundle. View collected triages in the explorer (`XAGENT.FORENSICTRIAGE`) or via
`GET /api/forensic-triage` (list) / `?id=N` (full bundle).

## 8c. Rustinel EDR bridge — kernel-level detection (read-only)

The agent's built-in detection is poll-based. [**Rustinel**](https://github.com/Karib0u/rustinel)
is a continuous **kernel-level** sensor (ETW on Windows, eBPF on Linux, Endpoint Security on macOS)
that matches live telemetry against **Sigma**, **YARA** and **IOC** engines and writes
ECS-compatible NDJSON alerts to `logs/alerts.json.<date>`. `--scan rustinel` **tails** that alert
log and forwards each new alert to XORCISM as a `rustinel_alert` event:

```bash
python3 xor_agent.py --scan rustinel
# custom location:
XOR_RUSTINEL_GLOB="/var/log/rustinel/alerts.json*" python3 xor_agent.py --scan rustinel
```

- **Deployment pattern**: install and run Rustinel as the always-on endpoint sensor; run the XOR
  agent (daemon or `--scan full`) to ship its detections into XORCISM. `--scan full` includes this
  step automatically.
- **Discovery**: by default the agent searches the usual Rustinel paths (`C:\Program Files\Rustinel\
  logs\…`, `/var/log/rustinel/…`, `/opt/rustinel/logs/…`, …). Override with `XOR_RUSTINEL_GLOB`
  (one or more glob patterns, `os.pathsep`-separated).
- **Mapping**: severity comes from the Sigma `rule.level`; the event detail carries `rule.id`, the
  matching engine (sigma / yara / ioc), `process`, `host` and the MITRE `threat.technique.id`.
- **Exactly-once**: a per-file byte cursor is persisted in `xor_agent.conf` (`rustinel_offsets`), so
  each run forwards only new alerts and a rotated/truncated file restarts cleanly.

**Safety**: the bridge is **strictly read-only** — it only reads Rustinel's alert files and never
configures, controls or stops the sensor. If no alert file is found, the scan is a graceful no-op.

## 8d. YARA scanning (malware classification, read-only)

XORCISM manages the YARA rules and the agent applies them on the host. Populate the
**YARARULE store** (`XTHREAT.YARARULE`) with [`import_yara.py`](../xorcism_python/importers/import_yara.py)
(a `.yar` file or a directory of rules) or the **yara connector**; the store is browsable in the
explorer and served to agents at `GET /api/agent/yara-rules`. Then:

```bash
python3 xor_agent.py --scan yara                                # rules from XORCISM, default targets
XOR_YARA_RULES=/opt/rules/index.yar python3 xor_agent.py --scan yara
XOR_YARA_TARGET="/srv:/home" python3 xor_agent.py --scan yara
```

- **Requirement**: the `yara` binary on `PATH` (install via the OS package manager). Absent ⇒
  graceful no-op.
- **Rules**: `XOR_YARA_RULES` (local file) wins; otherwise the agent fetches the YARARULE store.
- **Targets**: `XOR_YARA_TARGET` (`os.pathsep`-separated), else temp + Downloads.
- **Output**: each match → a `yara_match` event (rule + file). Read-only; never modifies files.
- Included in `--scan full` (graceful no-op when `yara`/rules are absent). The default targets
  (temp + Downloads) keep it light; widen `XOR_YARA_TARGET` for a deep sweep, or run `--scan yara`
  standalone (per-endpoint, or centrally via the ASSET window / `agent-scan`).

> Tip — bulk-load community rules into the store:
> `python xorcism_python/importers/import_yara.py /path/to/signature-base/yara`

---

## 9. Run as a service (always-on check-in)

### Linux — systemd

Edit and install [`install/xor-agent.service`](install/xor-agent.service):

```ini
[Service]
ExecStart=/usr/bin/python3 /opt/xor/xor_agent.py --run --interval 300
Environment=XOR_OVAL_FROM_SERVER=1
# Environment=XOR_ALLOW_EMULATION=1   # only if this host is an authorised BAS target
WorkingDirectory=/opt/xor
User=xor
Restart=always
```

```bash
sudo cp install/xor-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now xor-agent
journalctl -u xor-agent -f
```

### macOS — launchd

Install [`install/com.xorcism.xor.plist`](install/com.xorcism.xor.plist) into
`~/Library/LaunchAgents/` (per-user) or `/Library/LaunchDaemons/` (system), then:

```bash
launchctl load -w ~/Library/LaunchAgents/com.xorcism.xor.plist
```

### Windows — one-shot installer (recommended)

For the packaged `xor_agent.exe`, [`install/install_xor_agent.bat`](install/install_xor_agent.bat)
enrolls the agent **and** registers it to keep running. It self-elevates, then creates a SYSTEM
scheduled task ("XORCISM XOR Agent") that **starts at boot**, has **no time limit** (so it isn't
killed after the default 72 h) and **auto-restarts** if it stops:

```bat
:: enroll + install + start (run from the folder with xor_agent.exe, or agent\install)
install_xor_agent.bat https://xorcism.lab:9292 [enroll-key]

install_xor_agent.bat status        :: show task + process state
install_xor_agent.bat uninstall     :: stop + remove (keeps xor_agent.conf)
```

The installer auto-finds `xor_agent.exe` (next to the .bat, or in `..\dist` / `.\dist`) and writes
`xor_agent.conf` beside it. Requires Windows 8 / Server 2012+.

### Windows — Task Scheduler (manual / from source)

For a source checkout, register the daemon at startup yourself (adjust the python path; use
`pythonw` to run without a console window):

```powershell
schtasks /Create /TN "XOR Agent" /SC ONSTART /RU SYSTEM ^
  /TR "pythonw C:\xor\xor_agent.py --run --interval 300"
```

For BAS emulation on Windows, set the env var on the task: `setx /M XOR_ALLOW_EMULATION 1` (only on
an authorised target).

### Windows — real service in `services.msc` (NSSM or WinSW)

If you want the agent to appear under **Services** (SCM-managed) rather than as a scheduled task, host
the console daemon with a service wrapper. Use **one** of these *or* the scheduled-task installer
above — not several at once.

**NSSM (scripted):** [`install/install_xor_agent_service.bat`](install/install_xor_agent_service.bat)
enrolls the agent and registers it as the **"XORCISM XOR Agent"** service via
[NSSM](https://nssm.cc/download) — auto-start at boot, LocalSystem, restart-on-exit, rolling log next
to the exe. Drop `nssm.exe` next to the .bat (or in `..\tools`, `.\nssm`, or on `PATH`), then:

```bat
install_xor_agent_service.bat https://xorcism.lab:9292 [enroll-key]
install_xor_agent_service.bat status       :: sc query + process state
install_xor_agent_service.bat uninstall    :: stop + remove (keeps xor_agent.conf)
```

**WinSW (config):** [`install/xor-agent-service.xml`](install/xor-agent-service.xml) is a ready
[WinSW](https://github.com/winsw/winsw) definition. Enroll first, rename `WinSW.exe` to
`xor-agent-service.exe`, put it and the XML beside `xor_agent.exe`, then `xor-agent-service.exe
install` and `... start`.

---

## 10. Recurring scans without a daemon — server-side scheduling

You don't have to schedule scans on the endpoint. From **Configuration Management**
(`/configuration-management`) → **Launch an OVAL scan**, pick a host, an OVAL class and a
**Recurrence** (Hourly / Daily / Weekly / Monthly). XORCISM's in-process scheduler (`XSCHEDULE`)
then queues an agent OVAL job on that cadence; the agent runs it at its next check-in and posts the
results — no endpoint cron needed. The only requirement is that the agent is **enrolled and
checking in** (`--run` or a periodic `--once`).

This is the recommended pattern for fleets: run the agent as a lightweight daemon (`--run`), and
drive *what* it scans and *how often* centrally from the server.

---

## 11. Security & hardening

- **Protect the token**: `xor_agent.conf` holds a bearer token — `chmod 600`, restrict ACLs, never
  commit it.
- **TLS**: use a real certificate in production; reserve `--insecure` for labs.
- **Least privilege**: run as a dedicated low-privilege account; elevate only the specific checks
  that need it.
- **Emulation**: leave `XOR_ALLOW_EMULATION` **unset** except on hosts explicitly authorised as BAS
  targets, and only for the duration of an exercise.
- **Network**: the agent only makes outbound calls to the configured server; no listener is opened.

---

## 12. Troubleshooting

| Symptom | Check |
|---|---|
| `agent non enrôlé` | Run `--enroll` first; confirm the token is in `xor_agent.conf`. |
| Enrollment 403 | The server has an `XOR_ENROLL_KEY` set — pass the matching `--enroll-key`. |
| TLS errors in a lab | Add `--insecure` (lab only) or install the server's CA on the endpoint. |
| OVAL returns nothing on Windows | Without `oscap`, the native evaluator runs; force it with `XOR_OVAL_NATIVE=1`. Some checks need admin. |
| Emulation injects all `Skipped` | Expected unless `XOR_ALLOW_EMULATION=1`; and only recon injects auto-run by design. |
| No queued jobs run | Ensure the agent is checking in (`--run`/`--once`) and the server can reach it via check-in. |

---

*XOR agent — part of XORCISM. Single-file, stdlib-only, cross-OS. See [`README.md`](README.md) for
the capability matrix.*
