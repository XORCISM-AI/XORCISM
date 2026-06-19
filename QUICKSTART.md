# XORCISM — Quick Start

Get XORCISM (the TypeScript/Node.js + SQLite cyber-exposure, threat & compliance platform) running locally. The web app lives in `xorcism_ts/`; optional data importers live in `xorcism_python/`.

## Prerequisites

- **Node.js 20–22** (`>=20 <23`, required by `better-sqlite3`). A portable **Node 20** is bundled at `tools/nodejs/` if you don't want to install one — use `tools\nodejs\node.exe` / add it to `PATH`.
- **Git**
- *(optional, only for the data importers)* **Python 3.8+**

> Windows is the primary target (bundled `node.exe`, `.bat`/`.ps1` helpers, `C:\` paths). The `npm` commands work on any OS.

---

## 1. Clone

```bash
git clone https://github.com/XORCISM-AI/XORCISM.git
cd XORCISM
```

## 2. Install

```bash
cd xorcism_ts
npm install          # builds the native better-sqlite3 module (needs Node 20–22)
```

## 3. Build

```bash
npm run build        # = build:server (tsc → dist/server) + build:client (esbuild → dist/client/js)
```

## 4. Run

```bash
npm start            # node dist/server/index.js  → http://localhost:9292
```

On first start the SQLite databases are **created automatically** in `DB_DIR` (default `C:\Users\<you>\XORCISM_databases`), and a one-time admin account is printed to the console:

```
  ============================================================
  COMPTE ADMIN INITIAL CRÉÉ
    Email        : admin@xorcism.local
    Mot de passe : <random — shown only once>
    (change it on first login)
  ============================================================
```

Open **http://localhost:9292/login**, sign in with those credentials, and set a new password.

---

## One-command helpers (Windows)

Either of these installs deps (if needed), builds, and starts — using the bundled portable Node 20:

```powershell
# from xorcism_ts/  — build + start (add --dev for watch mode)
.\start.ps1
```

```bat
:: from the repo root — stops any old instance on the port, then starts
run-server.bat
```

Run the server directly with the bundled Node (no global Node needed):

```bat
tools\nodejs\node.exe xorcism_ts\dist\server\index.js
```

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `9292` | HTTP port |
| `DB_DIR` | `C:/Users/<you>/XORCISM_databases` | Where the `.db` files are created (server) |
| `XORCISM_ALLOW_REGISTER` | `1` | Set `0` to disable self-registration |
| `XORCISM_BASE_URL` | — | External base URL (links in emails) |

```bash
# example (bash)
PORT=9292 DB_DIR="C:\Users\you\XORCISM_databases" npm start
```
```powershell
# example (PowerShell)
$env:PORT=9292; $env:DB_DIR="C:\Users\you\XORCISM_databases"; npm start
```

---

## Optional — load reference data (Python importers)

Populate vulnerabilities, ATT&CK, KEV/EPSS, etc. Point Python at the **same** database folder via `XORCISM_DB_DIR`.

```bash
cd xorcism_python
pip install -r requirements.txt
set XORCISM_DB_DIR=C:\Users\you\XORCISM_databases      # PowerShell: $env:XORCISM_DB_DIR="..."

python importers/import_nvd_cve.py --recent-only        # NVD CVEs (+ CISA KEV + SSVC)
python importers/import_epss.py                         # EPSS exploit-prediction scores
python importers/ssvc.py --all                          # (re)compute CISA SSVC decisions
# …other importers: import_attack.py, import_capec.py, import_cisa_kev.py, import_d3fend.py …
```

## Optional — connector worker (Python)

Runs scan/import connector jobs queued from the **Connectors** page:

```bash
set XORCISM_DB_DIR=C:\Users\you\XORCISM_databases
python connectors/runner.py
```

---

## Troubleshooting

- **`better-sqlite3` ABI / `NODE_MODULE_VERSION` error** → you're on the wrong Node. Use Node 20–22 (or the bundled `tools\nodejs\node.exe`) and re-run `npm install`.
- **Port already in use** → change `PORT`, or use `run-server.bat` (it frees the port first).
- **Forgot the admin password** → it's only shown once at first run; reset via the `/forgot` flow, or delete `DB_DIR\XID.db` to re-seed a fresh admin (this wipes user accounts only).
- **Importer can't see imported data in the app** → make sure `XORCISM_DB_DIR` (Python) points at the same folder as `DB_DIR` (server).

## Pages

`/` explorer · `/dashboard` · `/identities` (IAM) · `/bia` · `/attack` (ATT&CK) · `/d3fend` · `/connectors` · `/exposure` · `/threat-feeds` · `/admin`. Full REST API: see [`API.md`](API.md).
