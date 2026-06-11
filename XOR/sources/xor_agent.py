#!/usr/bin/env python3
"""
XOR — Agent endpoint (EDR amélioré) pour XORCISM. Windows / macOS / Linux.

Sans dépendance (stdlib uniquement) → déployable partout où Python 3.8+ existe.

Capacités :
  • Enrôlement auprès de XORCISM → l'endpoint devient un ASSET.
  • Inventaire logiciel (Windows registre, Linux dpkg/rpm, macOS system_profiler)
    → CPE liés à l'asset (CPEFORASSET).
  • Scan de vulnérabilités (corrélation CPE→CVE via le serveur) → ASSETVULNERABILITY.
  • Scan de configuration / conformité (OpenSCAP `oscap` si présent, sinon checks intégrés).
  • Antivirus (ClamAV `clamscan`/`clamdscan` si présent).
  • Threat hunting : récupère les IOC (threat intel : XTHREAT, connecteurs CTI, feeds,
    STIX/TAXII) et les chasse localement (process, connexions, fichiers, hashes).
  • Boucle de check-in : exécute les scans « lancés » depuis la fenêtre ASSET de XORCISM.

Usage :
  python xor_agent.py --enroll --server https://xorcism.lab:9292 [--enroll-key KEY]
  python xor_agent.py --scan full        # un scan complet immédiat
  python xor_agent.py --run              # démon (check-in périodique)
  python xor_agent.py --inventory        # inventaire seul
Configuration persistée dans xor_agent.conf (à côté du script, ou --conf).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONF = os.path.join(HERE, "xor_agent.conf")
AGENT_VERSION = "1.0.0"


# ── Configuration ──────────────────────────────────────────────────────────────
def load_conf(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_conf(path, conf):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2)


# ── HTTP (stdlib) ───────────────────────────────────────────────────────────────
def _http(method, url, token=None, body=None, headers=None, insecure=False, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw[:200]}
    except Exception as e:  # noqa: BLE001
        return 0, {"error": str(e)}


# ── Informations système ─────────────────────────────────────────────────────────
def primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def sysinfo():
    name = socket.gethostname().split(".")[0]
    try:
        fqdn = socket.getfqdn()
    except Exception:
        fqdn = name
    return {
        "name": name, "fqdn": fqdn, "ip": primary_ip(),
        "os": platform.system(), "platform": platform.platform(),
        "version": platform.version(), "agent_version": AGENT_VERSION,
    }


# ── Inventaire logiciel → CPE ────────────────────────────────────────────────────
def _cpe(vendor, product, version):
    def n(s):
        return (s or "*").strip().lower().replace(" ", "_").replace(":", "") or "*"
    return f"cpe:2.3:a:{n(vendor)}:{n(product)}:{n(version)}:*:*:*:*:*:*:*"


def inventory_windows():
    import winreg  # type: ignore
    out, seen = [], set()
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
    ]
    for hive, subkey, flag in roots:
        try:
            k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(k)[0]):
            try:
                sk = winreg.OpenKey(k, winreg.EnumKey(k, i))
                name = winreg.QueryValueEx(sk, "DisplayName")[0]
            except OSError:
                continue
            try:
                ver = winreg.QueryValueEx(sk, "DisplayVersion")[0]
            except OSError:
                ver = ""
            try:
                pub = winreg.QueryValueEx(sk, "Publisher")[0]
            except OSError:
                pub = ""
            key = (name, ver)
            if name and key not in seen:
                seen.add(key)
                out.append({"name": name, "version": ver, "vendor": pub})
    return out


def inventory_linux():
    out = []
    if subprocess.run(["which", "dpkg-query"], capture_output=True).returncode == 0:
        r = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if p and p[0]:
                out.append({"name": p[0], "version": p[1] if len(p) > 1 else "", "vendor": ""})
    elif subprocess.run(["which", "rpm"], capture_output=True).returncode == 0:
        r = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if p and p[0]:
                out.append({"name": p[0], "version": p[1] if len(p) > 1 else "", "vendor": p[2] if len(p) > 2 else ""})
    return out


def inventory_macos():
    out = []
    try:
        r = subprocess.run(["system_profiler", "-json", "SPApplicationsDataType"], capture_output=True, text=True, timeout=120)
        data = json.loads(r.stdout or "{}")
        for app in data.get("SPApplicationsDataType", []):
            out.append({"name": app.get("_name", ""), "version": app.get("version", ""), "vendor": app.get("obtained_from", "")})
    except Exception:
        for d in ("/Applications", os.path.expanduser("~/Applications")):
            if os.path.isdir(d):
                for n in os.listdir(d):
                    if n.endswith(".app"):
                        out.append({"name": n[:-4], "version": "", "vendor": ""})
    return out


def inventory():
    sysname = platform.system()
    try:
        items = (inventory_windows() if sysname == "Windows"
                 else inventory_macos() if sysname == "Darwin"
                 else inventory_linux())
    except Exception as e:  # noqa: BLE001
        print(f"[inventory] erreur : {e}", file=sys.stderr)
        items = []
    for it in items:
        it["cpe"] = _cpe(it.get("vendor"), it.get("name"), it.get("version"))
    return items


# ── Résultat normalisé (schéma import_findings de XORCISM) ───────────────────────
def inventory_result(si, items):
    host = si["name"]
    services = [{"asset": host, "cpe": it["cpe"], "name": it["name"]} for it in items]
    cpes = sorted({it["cpe"] for it in items})
    return {
        "assets": [{"hostname": host, "ip": si["ip"], "key": host, "os": si["os"]}],
        "services": services, "cpes": cpes, "vulns": [],
    }


# ── Antivirus (ClamAV) ───────────────────────────────────────────────────────────
def av_scan(paths=None):
    exe = None
    for cand in ("clamdscan", "clamscan"):
        if subprocess.run(["where" if platform.system() == "Windows" else "which", cand],
                          capture_output=True).returncode == 0:
            exe = cand
            break
    if not exe:
        return {"available": False, "detections": []}
    target = paths or [os.path.expanduser("~")]
    detections = []
    try:
        r = subprocess.run([exe, "--infected", "--no-summary", "-r"] + target,
                           capture_output=True, text=True, timeout=1800)
        for line in r.stdout.splitlines():
            if line.strip().endswith("FOUND"):
                fp, _, sig = line.rpartition(":")
                detections.append({"file": fp.strip(), "signature": sig.replace("FOUND", "").strip()})
    except Exception as e:  # noqa: BLE001
        return {"available": True, "error": str(e), "detections": []}
    return {"available": True, "detections": detections}


# ── Configuration / conformité (OpenSCAP ou checks intégrés) ─────────────────────
def oval_scan():
    if subprocess.run(["which" if platform.system() != "Windows" else "where", "oscap"],
                      capture_output=True).returncode == 0:
        return {"engine": "openscap", "note": "oscap présent — fournir un contenu OVAL/XCCDF pour évaluation complète", "checks": _builtin_compliance()}
    return {"engine": "builtin", "checks": _builtin_compliance()}


def _builtin_compliance():
    """Quelques contrôles de configuration portables (extensibles via OVAL)."""
    checks = []
    sysname = platform.system()

    def add(cid, title, result, detail=""):
        checks.append({"id": cid, "title": title, "result": result, "detail": detail})

    if sysname == "Windows":
        try:
            r = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True)
            on = r.stdout.count("ON")
            add("WIN-FW-1", "Windows Firewall enabled (all profiles)", "pass" if on >= 3 else "fail", f"{on}/3 profiles ON")
        except Exception:
            add("WIN-FW-1", "Windows Firewall enabled", "unknown")
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-Command",
                                "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"],
                               capture_output=True, text=True, timeout=30)
            add("WIN-ENC-1", "System drive encrypted (BitLocker)", "pass" if "1" in r.stdout else "fail", r.stdout.strip())
        except Exception:
            add("WIN-ENC-1", "System drive encrypted (BitLocker)", "unknown")
    elif sysname == "Darwin":
        try:
            r = subprocess.run(["fdesetup", "status"], capture_output=True, text=True)
            add("MAC-ENC-1", "FileVault enabled", "pass" if "On" in r.stdout else "fail", r.stdout.strip())
        except Exception:
            add("MAC-ENC-1", "FileVault enabled", "unknown")
        try:
            r = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], capture_output=True, text=True)
            add("MAC-FW-1", "Application firewall enabled", "pass" if "enabled" in r.stdout.lower() else "fail", r.stdout.strip())
        except Exception:
            add("MAC-FW-1", "Application firewall enabled", "unknown")
    else:  # Linux
        add("LNX-SSH-1", "SSH root login disabled",
            "pass" if _grep("/etc/ssh/sshd_config", "PermitRootLogin no") else "fail",
            "/etc/ssh/sshd_config")
        ufw = subprocess.run(["which", "ufw"], capture_output=True).returncode == 0
        if ufw:
            r = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            add("LNX-FW-1", "Host firewall (ufw) active", "pass" if "active" in r.stdout.lower() else "fail", "")
    return checks


def _grep(path, needle):
    try:
        with open(path, "r", errors="ignore") as f:
            return needle.lower() in f.read().lower()
    except Exception:
        return False


# ── Threat hunting (IOC) ─────────────────────────────────────────────────────────
def _processes():
    procs = []
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if parts:
                    procs.append(parts[0].strip('"'))
        else:
            r = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True)
            procs = [l.strip() for l in r.stdout.splitlines()[1:] if l.strip()]
    except Exception:
        pass
    return procs


def _remote_ips():
    ips = set()
    try:
        r = subprocess.run(["netstat", "-n"], capture_output=True, text=True, timeout=20)
        import re
        for m in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+", r.stdout):
            ips.add(m)
    except Exception:
        pass
    return ips


def hunt(iocs):
    hits = []
    by_type = {}
    for i in iocs:
        by_type.setdefault(i["ioc_type"], {})[str(i["value"]).lower()] = i.get("threat")

    procs = [p.lower() for p in _processes()]
    for fn, threat in by_type.get("filename", {}).items():
        for p in procs:
            if p == fn or p.endswith("\\" + fn) or p.endswith("/" + fn):
                hits.append({"type": "filename", "value": fn, "where": "process", "threat": threat})
                break

    ips = _remote_ips()
    for ip, threat in by_type.get("ip", {}).items():
        if ip in ips:
            hits.append({"type": "ip", "value": ip, "where": "network connection", "threat": threat})

    # Hashes : on hashe les exécutables des process (borné), si des IOC hash existent.
    hash_iocs = {**by_type.get("sha256", {}), **by_type.get("md5", {}), **by_type.get("sha1", {})}
    if hash_iocs:
        import hashlib
        checked = 0
        for path in _running_exe_paths():
            if checked > 200:
                break
            checked += 1
            try:
                with open(path, "rb") as f:
                    data = f.read()
                for algo, name in (("sha256", "sha256"), ("md5", "md5"), ("sha1", "sha1")):
                    if name in (k for k in ("sha256", "md5", "sha1") if by_type.get(k)):
                        h = getattr(hashlib, algo)(data).hexdigest()
                        if h in hash_iocs:
                            hits.append({"type": algo, "value": h, "where": path, "threat": hash_iocs[h]})
            except Exception:
                continue
    return hits


def _running_exe_paths():
    paths = set()
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["powershell", "-NoProfile", "-Command",
                                "Get-Process | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue"],
                               capture_output=True, text=True, timeout=30)
            paths = {l.strip() for l in r.stdout.splitlines() if l.strip()}
        else:
            r = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True)
            for c in r.stdout.splitlines()[1:]:
                c = c.strip()
                if os.path.isabs(c) and os.path.exists(c):
                    paths.add(c)
    except Exception:
        pass
    return paths


# ── Orchestration agent ──────────────────────────────────────────────────────────
class XorAgent:
    def __init__(self, conf, conf_path):
        self.conf = conf
        self.conf_path = conf_path
        self.server = conf.get("server", "").rstrip("/")
        self.token = conf.get("token")
        self.insecure = bool(conf.get("insecure"))
        self.si = sysinfo()

    def _post(self, path, body):
        return _http("POST", self.server + path, self.token, body, insecure=self.insecure)

    def _get(self, path):
        return _http("GET", self.server + path, self.token, insecure=self.insecure)

    def enroll(self, enroll_key=None):
        body = dict(self.si)
        st, d = _http("POST", self.server + "/api/agent/enroll", body=body,
                      headers={"X-Enroll-Key": enroll_key} if enroll_key else None, insecure=self.insecure)
        if st == 200 and d.get("token"):
            self.token = d["token"]
            self.conf.update({"server": self.server, "token": self.token, "name": self.si["name"], "insecure": self.insecure})
            save_conf(self.conf_path, self.conf)
            print(f"[enroll] OK — asset « {d.get('asset')} », token enregistré dans {self.conf_path}")
            return True
        print(f"[enroll] échec ({st}) : {d.get('error')}")
        return False

    def do_inventory(self):
        items = inventory()
        res = inventory_result(self.si, items)
        st, d = self._post("/api/agent/inventory", {"result": res})
        print(f"[inventory] {len(items)} logiciels → CPE liés à l'asset ({st})")
        return len(items)

    def do_vuln(self):
        items = inventory()
        # Corrélation CPE→CVE côté serveur (heuristique), bornée.
        products = [{"name": it["name"], "version": it.get("version", "")} for it in items][:40]
        st, d = self._post("/api/agent/match", {"products": products, "host": self.si["name"]})
        vulns = d.get("vulns", []) if st == 200 else []
        self._post("/api/agent/vulnerabilities", {"vulns": vulns})
        print(f"[vuln] {len(vulns)} CVE corrélées → ASSETVULNERABILITY ({st})")
        return len(vulns)

    def do_oval(self):
        res = oval_scan()
        fails = [c for c in res.get("checks", []) if c.get("result") == "fail"]
        self._post("/api/agent/events", {"events": [{
            "type": "compliance", "severity": "medium" if fails else "info",
            "title": f"Config scan ({res['engine']}): {len(fails)} fail / {len(res.get('checks', []))}",
            "detail": res,
        }]})
        print(f"[oval] {len(res.get('checks', []))} contrôles, {len(fails)} en échec")
        return len(fails)

    def do_av(self):
        res = av_scan()
        if not res.get("available"):
            print("[av] ClamAV non installé (clamscan/clamdscan absent)")
            return 0
        dets = res.get("detections", [])
        if dets:
            self._post("/api/agent/events", {"events": [{
                "type": "av_detection", "severity": "high",
                "title": f"ClamAV: {len(dets)} détection(s)", "detail": dets,
            }]})
        print(f"[av] {len(dets)} détection(s)")
        return len(dets)

    def do_hunt(self):
        st, d = self._get("/api/agent/intel")
        iocs = d.get("iocs", []) if st == 200 else []
        hits = hunt(iocs)
        if hits:
            self._post("/api/agent/events", {"events": [{
                "type": "hunt_hit", "severity": "high",
                "title": f"Threat hunt: {len(hits)} IOC trouvé(s)", "detail": hits,
            }]})
        print(f"[hunt] {len(iocs)} IOC évalués, {len(hits)} hit(s)")
        return len(hits)

    def run_scan(self, kind):
        if kind in ("inventory", "full"):
            self.do_inventory()
        if kind in ("vuln", "full"):
            self.do_vuln()
        if kind in ("oval", "full"):
            self.do_oval()
        if kind in ("av", "full"):
            self.do_av()
        if kind in ("hunt", "full"):
            self.do_hunt()

    def checkin(self):
        st, d = self._post("/api/agent/checkin", {})
        if st != 200:
            print(f"[checkin] erreur {st} : {d.get('error')}")
            return
        jobs = d.get("jobs", [])
        for j in jobs:
            kind = j.get("kind", "full")
            print(f"[checkin] job {j.get('AgentJobID')} → scan « {kind} »")
            try:
                self.run_scan(kind)
                self._post(f"/api/agent/job/{j['AgentJobID']}/result", {"summary": f"{kind} done"})
            except Exception as e:  # noqa: BLE001
                self._post(f"/api/agent/job/{j['AgentJobID']}/result", {"summary": f"error: {e}"})

    def run(self, interval):
        print(f"[xor] démon démarré — check-in toutes les {interval}s (serveur {self.server})")
        # Inventaire au démarrage
        self.do_inventory()
        while True:
            try:
                self.checkin()
            except Exception as e:  # noqa: BLE001
                print(f"[xor] boucle: {e}")
            time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description="Agent XOR (EDR) pour XORCISM")
    ap.add_argument("--conf", default=DEFAULT_CONF)
    ap.add_argument("--server", help="URL du serveur XORCISM (ex. https://host:9292)")
    ap.add_argument("--enroll", action="store_true")
    ap.add_argument("--enroll-key", help="clé d'enrôlement (XOR_ENROLL_KEY côté serveur)")
    ap.add_argument("--insecure", action="store_true", help="ignorer la vérif TLS (lab)")
    ap.add_argument("--inventory", action="store_true")
    ap.add_argument("--scan", choices=["inventory", "vuln", "oval", "av", "hunt", "full"])
    ap.add_argument("--once", action="store_true", help="un seul check-in puis sortie")
    ap.add_argument("--run", action="store_true", help="démon (check-in périodique)")
    ap.add_argument("--interval", type=int, default=300)
    args = ap.parse_args()

    conf = load_conf(args.conf)
    if args.server:
        conf["server"] = args.server
    if args.insecure:
        conf["insecure"] = True
    if not conf.get("server"):
        ap.error("--server requis (ou présent dans la conf)")

    agent = XorAgent(conf, args.conf)

    if args.enroll:
        if not agent.enroll(args.enroll_key or os.environ.get("XOR_ENROLL_KEY")):
            sys.exit(1)
        return
    if not agent.token:
        ap.error("agent non enrôlé : lancez d'abord --enroll")

    if args.inventory:
        agent.do_inventory()
    elif args.scan:
        agent.run_scan(args.scan)
    elif args.once:
        agent.checkin()
    elif args.run:
        agent.run(args.interval)
    else:
        agent.run_scan("full")


if __name__ == "__main__":
    main()
