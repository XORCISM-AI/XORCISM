#!/usr/bin/env python3
"""
XOR — Agent endpoint (EDR amélioré) pour XORCISM. Windows / macOS / Linux.

Sans dépendance (stdlib uniquement) → déployable partout où Python 3.8+ existe.

Capacités :
  • Enrôlement auprès de XORCISM → l'endpoint devient un ASSET.
  • Inventaire logiciel (Windows registre, Linux dpkg/rpm, macOS system_profiler)
    → CPE liés à l'asset (CPEFORASSET).
  • Scan de vulnérabilités (corrélation CPE→CVE via le serveur) → ASSETVULNERABILITY.
  • Scan de configuration / conformité OVAL/SCAP (OpenSCAP `oscap` si présent — Linux et
    Windows ; sur Windows sans oscap, évaluateur OVAL natif intégré : registre/fichiers/
    famille/env/WMI ; sinon checks intégrés portables).
  • Antivirus (ClamAV `clamscan`/`clamdscan` si présent).
  • Threat hunting : récupère les IOC (threat intel : XTHREAT, connecteurs CTI, feeds,
    STIX/TAXII) et les chasse localement (process, connexions, fichiers, hashes).
  • Pont EDR Rustinel : lit (tail) les alertes ECS NDJSON du capteur Rustinel
    (ETW/eBPF/ESF + Sigma/YARA/IOC) et les remonte à XORCISM en événements — détection
    noyau sans réécrire de cœur natif (lecture seule, curseur par fichier).
  • Scan YARA : exécute le binaire `yara` local avec les règles du dépôt YARARULE de
    XORCISM (ou XOR_YARA_RULES) et remonte chaque correspondance en événement.
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
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import bz2
import gzip
import glob
import shutil
import tempfile
import xml.etree.ElementTree as ET

try:
    import winreg as _winreg  # Windows-only; used by the native OVAL evaluator
except Exception:
    _winreg = None
from datetime import datetime, timezone, timedelta

# Console Windows : la sortie par défaut (cp1252) ne sait pas encoder « → » ni
# les accents → on force UTF-8 (errors=replace) pour éviter tout UnicodeEncodeError.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

# Sortie des outils système (tasklist, netstat, Get-Process…) : en mode texte,
# subprocess décode avec l'encodage local (cp1252) et lève UnicodeDecodeError sur
# des octets non mappés. On rend ce décodage tolérant (errors=replace) globalement.
_orig_subprocess_run = subprocess.run


def _tolerant_run(*args, **kwargs):
    if kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding"):
        kwargs.setdefault("errors", "replace")
    return _orig_subprocess_run(*args, **kwargs)


subprocess.run = _tolerant_run  # type: ignore[assignment]

# Dossier de référence : à côté de l'exécutable une fois « gelé » (PyInstaller
# onefile place __file__ dans un dossier temporaire _MEI…), sinon à côté du script.
if getattr(sys, "frozen", False):
    HERE = os.path.dirname(sys.executable)
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONF = os.path.join(HERE, "xor_agent.conf")
AGENT_VERSION = "1.1.0"


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
def _which(cmd):
    return subprocess.run(["which" if platform.system() != "Windows" else "where", cmd],
                          capture_output=True).returncode == 0


def _os_release():
    info = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    info[k] = v.strip().strip('"')
    except Exception:
        pass
    return info


def _download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "XOR-Agent-OVAL"})
    with urllib.request.urlopen(req, timeout=180) as r, open(dest, "wb") as out:
        shutil.copyfileobj(r, out)
    if dest.endswith(".bz2"):
        plain = dest[:-4]
        with bz2.open(dest) as f, open(plain, "wb") as out:
            shutil.copyfileobj(f, out)
        return plain
    if dest.endswith(".gz"):
        plain = dest[:-3]
        with gzip.open(dest) as f, open(plain, "wb") as out:
            shutil.copyfileobj(f, out)
        return plain
    return dest


def _decompress(dest):
    if dest.endswith(".bz2"):
        plain = dest[:-4]
        with bz2.open(dest) as f, open(plain, "wb") as out:
            shutil.copyfileobj(f, out)
        return plain
    if dest.endswith(".gz"):
        plain = dest[:-3]
        with gzip.open(dest) as f, open(plain, "wb") as out:
            shutil.copyfileobj(f, out)
        return plain
    return dest


def _fetch_server_content(server, token, insecure, platform, workdir):
    """Pull OVAL/SCAP content served by XORCISM (GET /api/agent/oval-content)."""
    url = server.rstrip("/") + "/api/agent/oval-content?platform=" + urllib.parse.quote(platform or "")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    ctx = ssl._create_unverified_context() if insecure else None
    with urllib.request.urlopen(req, timeout=180, context=ctx) as r:
        name = r.headers.get("X-OVAL-Content-Name", "server-oval.xml")
        dest = os.path.join(workdir, os.path.basename(name) or "server-oval.xml")
        with open(dest, "wb") as out:
            shutil.copyfileobj(r, out)
    return _decompress(dest), name


def _oval_content(workdir, server="", token="", insecure=False, platform=""):
    """Locate OVAL definitions for this host (the chosen 'distro feed / SSG' source):
       env override → XORCISM-served content → local SSG datastream → distro CVE feed."""
    env = os.environ.get("XOR_OVAL_CONTENT")
    if env and os.path.exists(env):
        return env, os.path.basename(env)
    # XORCISM-served content (offline / centralized) — first choice when reachable
    if server and token and os.environ.get("XOR_OVAL_FROM_SERVER", "1") != "0":
        try:
            return _fetch_server_content(server, token, insecure, platform, workdir)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                print(f"[oval] contenu serveur erreur {e.code}", file=sys.stderr)
        except Exception as e:
            print(f"[oval] contenu serveur indisponible : {e}", file=sys.stderr)
    url = os.environ.get("XOR_OVAL_URL")
    if url:
        try:
            ext = ".bz2" if url.endswith(".bz2") else ".gz" if url.endswith(".gz") else ".xml"
            return _download(url, os.path.join(workdir, "oval-content" + ext)), url.rsplit("/", 1)[-1]
        except Exception as e:
            print(f"[oval] téléchargement {url} échoué : {e}", file=sys.stderr)
    # `platform` here is the platform-token string parameter (not the stdlib module) — use
    # sys.platform to gate the Linux-only local SSG / distro CVE feeds. On Windows/macOS the
    # content comes from env / the XORCISM server / XOR_OVAL_URL above (returns None here).
    if sys.platform != "linux":
        return None, None
    for p in glob.glob("/usr/share/xml/scap/ssg/content/ssg-*-ds.xml"):  # SCAP Security Guide (compliance)
        return p, os.path.basename(p)
    rel = _os_release()                                                  # distro CVE OVAL (vulnerability)
    rid = (rel.get("ID") or "").lower()
    code = (rel.get("VERSION_CODENAME") or "").lower()
    try:
        if rid == "ubuntu" and code:
            u = f"https://security-metadata.canonical.com/oval/com.ubuntu.{code}.cve.oval.xml.bz2"
            return _download(u, os.path.join(workdir, "ubuntu.cve.oval.xml.bz2")), f"com.ubuntu.{code}.cve.oval"
        if rid == "debian" and code:
            u = f"https://www.debian.org/security/oval/oval-definitions-{code}.xml"
            return _download(u, os.path.join(workdir, "debian.oval.xml")), f"debian-{code}.oval"
    except Exception as e:
        print(f"[oval] flux distro indisponible : {e}", file=sys.stderr)
    return None, None


def _ns(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_oval_results(results_path, content_path, limit=20000):
    """Merge oscap OVAL results (definition→result) with the content (definition→
    class / title / CVE / CPE references). Streamed (iterparse) for large feeds."""
    meta = {}
    try:
        for _, el in ET.iterparse(content_path, events=("end",)):
            if _ns(el.tag) == "definition" and el.get("id"):
                title = ""; cves = []; cpes = []; sev = ""
                for sub in el.iter():
                    t = _ns(sub.tag)
                    if t == "title" and not title:
                        title = (sub.text or "").strip()
                    elif t == "reference":
                        src = (sub.get("source") or "").upper(); rid = sub.get("ref_id") or ""
                        if src == "CVE" and rid:
                            cves.append(rid)
                        elif src == "CPE" and rid:
                            cpes.append(rid)
                    elif t == "severity" and not sev:
                        sev = (sub.text or "").strip()
                meta[el.get("id")] = {"class": el.get("class", ""), "title": title[:1000],
                                      "cves": cves, "cpes": cpes, "severity": sev}
                el.clear()
    except Exception as e:
        print(f"[oval] parse contenu : {e}", file=sys.stderr)
    out = []
    try:
        for _, el in ET.iterparse(results_path, events=("end",)):
            if _ns(el.tag) == "definition" and el.get("definition_id"):
                m = meta.get(el.get("definition_id"), {})
                out.append({
                    "definition_id": el.get("definition_id"),
                    "class": m.get("class") or el.get("class", ""),
                    "result": el.get("result", ""),
                    "title": m.get("title", ""), "severity": m.get("severity", ""),
                    "cves": m.get("cves", []), "cpes": m.get("cpes", []),
                })
                el.clear()
                if len(out) >= limit:
                    break
    except Exception as e:
        print(f"[oval] parse résultats : {e}", file=sys.stderr)
    return out


def _is_datastream(path):
    """A SCAP datastream / XCCDF benchmark (needs `oscap xccdf eval`, not `oval eval`)."""
    try:
        with open(path, "rb") as f:
            head = f.read(4000).decode("utf-8", "replace").lower()
        return ("data-stream" in head) or ("<benchmark" in head) or ("xccdf" in head)
    except Exception:
        return False


def _xccdf_profile(content):
    """Pick an XCCDF profile for `oscap xccdf eval`: env `XOR_XCCDF_PROFILE`, else the
    benchmark's profiles via `oscap info` (prefer cis/stig/standard/pci), else None."""
    env = os.environ.get("XOR_XCCDF_PROFILE")
    if env:
        return env
    try:
        r = subprocess.run(["oscap", "info", content], capture_output=True, text=True, timeout=60)
        profs = list(dict.fromkeys(re.findall(r"xccdf_[\w.\-]+_profile_[\w.\-]+", r.stdout)))
        if not profs:
            return None
        for kw in ("cis", "stig", "standard", "pci", "hipaa"):
            for p in profs:
                if kw in p.lower():
                    return p
        return profs[0]
    except Exception:
        return None


def parse_arf_results(path, limit=20000):
    """Unified parse of an oscap ARF / XCCDF-results report (both OVAL definitions+results
    and XCCDF rule-results) → the same item list /api/agent/oval expects."""
    try:
        root = ET.parse(path).getroot()
    except Exception as e:
        print(f"[oval] parse ARF : {e}", file=sys.stderr)
        return []
    meta = {}
    for el in root.iter():
        if _ns(el.tag) == "definition" and el.get("id"):
            title = ""; cves = []; cpes = []
            for sub in el.iter():
                st = _ns(sub.tag)
                if st == "title" and not title:
                    title = (sub.text or "").strip()
                elif st == "reference":
                    src = (sub.get("source") or "").upper(); rid = sub.get("ref_id") or ""
                    if src == "CVE" and rid:
                        cves.append(rid)
                    elif src == "CPE" and rid:
                        cpes.append(rid)
            meta[el.get("id")] = {"class": el.get("class", ""), "title": title[:1000], "cves": cves, "cpes": cpes}
    out = []
    for el in root.iter():                                  # OVAL results
        if _ns(el.tag) == "definition" and el.get("definition_id"):
            m = meta.get(el.get("definition_id"), {})
            out.append({"definition_id": el.get("definition_id"), "class": m.get("class") or el.get("class", ""),
                        "result": el.get("result", ""), "title": m.get("title", ""), "severity": "",
                        "cves": m.get("cves", []), "cpes": m.get("cpes", [])})
    rules = {}
    for el in root.iter():                                  # XCCDF rule titles/severity
        if _ns(el.tag) == "Rule" and el.get("id"):
            title = ""
            for sub in el:
                if _ns(sub.tag) == "title":
                    title = (sub.text or "").strip(); break
            rules[el.get("id")] = {"title": title, "severity": el.get("severity", "")}
    for el in root.iter():                                  # XCCDF rule-results → compliance
        if _ns(el.tag) == "rule-result" and el.get("idref"):
            result = ""
            for sub in el:
                if _ns(sub.tag) == "result":
                    result = (sub.text or "").strip(); break
            if result:
                ru = rules.get(el.get("idref"), {})
                out.append({"definition_id": el.get("idref"), "class": "compliance", "result": result,
                            "title": ru.get("title", ""), "severity": ru.get("severity", ""), "cves": [], "cpes": []})
            if len(out) >= limit:
                break
    return out


# ── Native OVAL 5.x evaluator for Windows ────────────────────────────────────────
# OpenSCAP's `oscap` has no native Windows build, so the agent evaluates Windows OVAL
# definitions itself: it parses the OVAL XML (definitions / tests / objects / states /
# variables), evaluates the Windows-relevant tests against the live system (registry via
# winreg, files, OS family, environment variables, WMI best-effort), walks each
# definition's criteria tree with the OVAL result algebra, and returns the same classified
# verdict list `do_oval` posts to /api/agent/oval. Unsupported constructs degrade to
# "not evaluated" (→ unknown) instead of failing, so partial content still yields results.
_OT, _OF, _OE, _OU, _ONE, _ONA = ("true", "false", "error", "unknown", "not evaluated", "not applicable")

# OVAL 5.x operator truth tables (definitions §5.3).
_OVAL_AND = {
    _OT:  {_OT: _OT, _OF: _OF, _OE: _OE, _OU: _OU, _ONE: _ONE, _ONA: _OT},
    _OF:  {_OT: _OF, _OF: _OF, _OE: _OF, _OU: _OF, _ONE: _OF,  _ONA: _OF},
    _OE:  {_OT: _OE, _OF: _OF, _OE: _OE, _OU: _OE, _ONE: _OE,  _ONA: _OE},
    _OU:  {_OT: _OU, _OF: _OF, _OE: _OE, _OU: _OU, _ONE: _OU,  _ONA: _OU},
    _ONE: {_OT: _ONE,_OF: _OF, _OE: _OE, _OU: _OU, _ONE: _ONE, _ONA: _ONE},
    _ONA: {_OT: _OT, _OF: _OF, _OE: _OE, _OU: _OU, _ONE: _ONE, _ONA: _ONA},
}
_OVAL_OR = {
    _OT:  {_OT: _OT, _OF: _OT, _OE: _OT, _OU: _OT, _ONE: _OT,  _ONA: _OT},
    _OF:  {_OT: _OT, _OF: _OF, _OE: _OE, _OU: _OU, _ONE: _ONE, _ONA: _OF},
    _OE:  {_OT: _OT, _OF: _OE, _OE: _OE, _OU: _OE, _ONE: _OE,  _ONA: _OE},
    _OU:  {_OT: _OT, _OF: _OU, _OE: _OE, _OU: _OU, _ONE: _OU,  _ONA: _OU},
    _ONE: {_OT: _OT, _OF: _ONE,_OE: _OE, _OU: _OU, _ONE: _ONE, _ONA: _ONE},
    _ONA: {_OT: _OT, _OF: _OF, _OE: _OE, _OU: _OU, _ONE: _ONE, _ONA: _ONA},
}


def _oval_negate(r):
    return _OF if r == _OT else _OT if r == _OF else r


def _oval_combine(op, results):
    if not results:
        return _OU
    op = (op or "AND").upper()
    if op == "OR":
        acc = _OF
        for r in results:
            acc = _OVAL_OR[acc][r]
        return acc
    if op == "ONE":
        if _OE in results:
            return _OE
        t = results.count(_OT)
        if t > 1:
            return _OF
        if _OU in results:
            return _OU
        if _ONE in results:
            return _ONE
        return _OT if t == 1 else _OF
    if op == "XOR":
        if _OE in results:
            return _OE
        if _OU in results:
            return _OU
        if _ONE in results:
            return _ONE
        return _OT if (results.count(_OT) % 2 == 1) else _OF
    acc = _OT  # AND (default)
    for r in results:
        acc = _OVAL_AND[acc][r]
    return acc


def _oval_ver(v):
    out = []
    for p in re.split(r"[.\-+]", str(v).strip()):
        m = re.match(r"\d+", p)
        out.append(int(m.group()) if m else 0)
    return tuple(out)


def _oval_cast(v, dt):
    dt = (dt or "string").lower()
    try:
        if dt == "int":
            return int(str(v).strip(), 0) if isinstance(v, str) else int(v)
        if dt == "boolean":
            return str(v).strip().lower() in ("1", "true", "t", "yes", "on")
        if dt in ("float", "double"):
            return float(v)
        if dt == "version":
            return _oval_ver(v)
    except Exception:
        return v
    return str(v)


def _oval_compare(item_val, op, state_val, dt):
    op = (op or "equals").lower()
    if op == "pattern match":
        try:
            return re.search(state_val or "", str(item_val)) is not None
        except Exception:
            return False
    try:
        a = _oval_cast(item_val, dt)
        b = _oval_cast(state_val, dt)
        if op == "equals":
            return a == b
        if op == "not equal":
            return a != b
        if op == "case insensitive equals":
            return str(item_val).lower() == str(state_val).lower()
        if op == "case insensitive not equal":
            return str(item_val).lower() != str(state_val).lower()
        if op == "greater than":
            return a > b
        if op == "greater than or equal":
            return a >= b
        if op == "less than":
            return a < b
        if op == "less than or equal":
            return a <= b
        if op == "bitwise and":
            return (int(a) & int(b)) == int(b)
        if op == "bitwise or":
            return (int(a) | int(b)) != 0
        return a == b
    except Exception:
        return False


_REG_HIVES = {}
_REG_TYPE = {}
if _winreg is not None:
    _REG_HIVES = {
        "HKEY_LOCAL_MACHINE": _winreg.HKEY_LOCAL_MACHINE, "HKLM": _winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": _winreg.HKEY_CURRENT_USER, "HKCU": _winreg.HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT": _winreg.HKEY_CLASSES_ROOT, "HKCR": _winreg.HKEY_CLASSES_ROOT,
        "HKEY_USERS": _winreg.HKEY_USERS, "HKU": _winreg.HKEY_USERS,
        "HKEY_CURRENT_CONFIG": _winreg.HKEY_CURRENT_CONFIG, "HKCC": _winreg.HKEY_CURRENT_CONFIG,
    }
    _REG_TYPE = {
        _winreg.REG_SZ: "reg_sz", _winreg.REG_EXPAND_SZ: "reg_expand_sz",
        _winreg.REG_BINARY: "reg_binary", _winreg.REG_DWORD: "reg_dword",
        _winreg.REG_MULTI_SZ: "reg_multi_sz", _winreg.REG_QWORD: "reg_qword",
    }


def _reg_norm(val, typ):
    if typ in (getattr(_winreg, "REG_DWORD", -1), getattr(_winreg, "REG_QWORD", -2)):
        return int(val)
    if typ == getattr(_winreg, "REG_BINARY", -3):
        try:
            return val.hex()
        except Exception:
            return str(val)
    if typ == getattr(_winreg, "REG_MULTI_SZ", -4):
        return "\n".join(val) if isinstance(val, (list, tuple)) else str(val)
    return str(val)


class _XmlUnsupported(Exception):
    pass


class _WinOval:
    """Indexes an OVAL definitions document and evaluates it against the live host."""

    def __init__(self, root):
        self.defs, self.tests, self.objects, self.states, self.variables = {}, {}, {}, {}, {}
        self._tc, self._dc, self._vc, self._stack = {}, {}, {}, set()
        for el in root.iter():
            tag = _ns(el.tag)
            oid = el.get("id")
            if not oid:
                continue
            if tag == "definition" and el.get("class"):
                self.defs[oid] = el
            elif tag.endswith("_test"):
                self.tests[oid] = el
            elif tag.endswith("_object"):
                self.objects[oid] = el
            elif tag.endswith("_state"):
                self.states[oid] = el
            elif tag in ("local_variable", "constant_variable", "external_variable"):
                self.variables[oid] = el

    # ── variables ──
    def var_values(self, vid):
        if vid in self._vc:
            return self._vc[vid]
        self._vc[vid] = []  # cycle guard
        el = self.variables.get(vid)
        vals = []
        if el is not None:
            tag = _ns(el.tag)
            if tag == "constant_variable":
                vals = [(c.text or "") for c in el if _ns(c.tag) == "value"]
            elif tag == "local_variable":
                comp = next((c for c in el if _ns(c.tag) not in ("notes",)), None)
                vals = self._component(comp)
            # external_variable → no values file → unresolved
        self._vc[vid] = vals
        return vals

    def _component(self, comp):
        if comp is None:
            return []
        tag = _ns(comp.tag)
        if tag == "literal_component":
            return [comp.text or ""]
        if tag == "variable_component":
            return self.var_values(comp.get("var_ref"))
        if tag == "concat":
            out = [""]
            for child in comp:
                vs = self._component(child) or [""]
                out = [a + b for a in out for b in vs]
            return out
        if tag == "object_component":
            try:
                items = self._collect(comp.get("object_ref"), "")
            except Exception:
                items = []
            field = comp.get("item_field")
            return [str(it[field]) for it in (items or []) if field in it]
        return []  # arithmetic / regex_capture / unsupported

    # ── object collection ──
    def _entity(self, parent, name):
        """Return (values, nil) for a child entity, resolving var_ref. values=[None] if absent."""
        el = next((c for c in parent if _ns(c.tag) == name), None)
        if el is None:
            return [None], False, None
        if (el.get("{http://www.w3.org/2001/XMLSchema-instance}nil") or "").lower() == "true":
            return [None], True, None
        op = el.get("operation", "equals")
        vr = el.get("var_ref")
        if vr:
            return (self.var_values(vr) or []), False, op
        return [el.text or ""], False, op

    def _collect(self, obj_ref, _test_tag):
        obj = self.objects.get(obj_ref)
        if obj is None:
            return None
        otag = _ns(obj.tag)
        if otag == "family_object":
            return [{"family": "windows"}]
        if otag in ("registry_object", "registry58_object"):
            return self._collect_registry(obj)
        if otag in ("environmentvariable_object", "environmentvariable58_object"):
            return self._collect_env(obj)
        if otag in ("file_object", "file58_object"):
            return self._collect_file(obj)
        if otag == "textfilecontent54_object":
            return self._collect_textfile(obj)
        if otag == "variable_object":
            vr = next((c.text for c in obj if _ns(c.tag) == "var_ref"), None)
            return [{"value": v} for v in (self.var_values(vr) if vr else [])]
        raise _XmlUnsupported(otag)

    def _reg_view(self, obj):
        view = _winreg.KEY_WOW64_64KEY
        beh = next((c for c in obj if _ns(c.tag) == "behaviors"), None)
        if beh is not None and (beh.get("windows_view") or "").lower() == "32_bit":
            view = _winreg.KEY_WOW64_32KEY
        return view

    def _collect_registry(self, obj):
        if _winreg is None:
            raise _XmlUnsupported("registry")
        hives, _, _ = self._entity(obj, "hive")
        keys, _, _ = self._entity(obj, "key")
        names, name_nil, name_op = self._entity(obj, "name")
        view = self._reg_view(obj)
        items = []
        for hv in hives:
            for ky in keys:
                if name_op == "pattern match" and not name_nil:
                    items += self._reg_enum_values(hv, ky, names, view)
                    continue
                for nm in names:
                    it = self._reg_read(hv, ky, None if name_nil else nm, view)
                    if it is not None:
                        items.append(it)
                if len(items) > 1000:
                    return items
        return items

    def _reg_open(self, hive, key, view):
        h = _REG_HIVES.get((hive or "").strip().upper())
        if h is None:
            return None
        return _winreg.OpenKey(h, key or "", 0, _winreg.KEY_READ | view)

    def _reg_read(self, hive, key, name, view):
        try:
            hk = self._reg_open(hive, key, view)
        except OSError:
            return None
        if hk is None:
            return None
        try:
            if name in (None, ""):  # default value, else bare key existence
                try:
                    val, typ = _winreg.QueryValueEx(hk, "")
                    return {"hive": hive, "key": key, "name": "", "type": _REG_TYPE.get(typ, ""), "value": _reg_norm(val, typ)}
                except OSError:
                    return {"hive": hive, "key": key, "name": ""}
            try:
                val, typ = _winreg.QueryValueEx(hk, name)
            except OSError:
                return None
            return {"hive": hive, "key": key, "name": name, "type": _REG_TYPE.get(typ, ""), "value": _reg_norm(val, typ)}
        finally:
            hk.Close()

    def _reg_enum_values(self, hive, key, patterns, view):
        out = []
        try:
            hk = self._reg_open(hive, key, view)
        except OSError:
            return out
        if hk is None:
            return out
        try:
            i = 0
            while True:
                try:
                    nm, val, typ = _winreg.EnumValue(hk, i)
                except OSError:
                    break
                i += 1
                if any(re.search(p or "", nm) for p in patterns if p is not None):
                    out.append({"hive": hive, "key": key, "name": nm, "type": _REG_TYPE.get(typ, ""), "value": _reg_norm(val, typ)})
                if i > 2000:
                    break
        finally:
            hk.Close()
        return out

    def _collect_env(self, obj):
        names, _, _ = self._entity(obj, "name")
        out = []
        for nm in names:
            if nm is not None and nm in os.environ:
                out.append({"name": nm, "value": os.environ[nm]})
        return out

    def _collect_file(self, obj):
        paths, _, _ = self._entity(obj, "filepath")
        cand = []
        if paths != [None]:
            cand = [p for p in paths if p]
        else:
            dirs, _, _ = self._entity(obj, "path")
            files, _, _ = self._entity(obj, "filename")
            for d in dirs:
                for f in files:
                    if d is not None and f is not None:
                        cand.append(os.path.join(d, f))
        out = []
        for fp in cand:
            try:
                exists = os.path.exists(os.path.expandvars(fp))
            except Exception:
                exists = False
            if exists:
                out.append({"filepath": fp, "path": os.path.dirname(fp), "filename": os.path.basename(fp)})
        return out

    def _collect_textfile(self, obj):
        paths, _, _ = self._entity(obj, "filepath")
        pats, _, _ = self._entity(obj, "pattern")
        out = []
        for fp in paths:
            if not fp:
                continue
            try:
                with open(os.path.expandvars(fp), "r", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            for p in pats:
                if p is None:
                    continue
                for m in re.finditer(p, text):
                    out.append({"filepath": fp, "pattern": p,
                                "subexpression": (m.group(1) if m.groups() else m.group(0)),
                                "text": m.group(0)})
                    if len(out) > 1000:
                        return out
        return out

    # ── state matching ──
    def _match(self, st, item):
        op = (st.get("operator", "AND") or "AND").upper()
        vals = []
        for ent in st:
            et = _ns(ent.tag)
            if et in ("notes",):
                continue
            if et not in item:
                vals.append(None)
                continue
            dt = ent.get("datatype", "string")
            operation = ent.get("operation", "equals")
            vr = ent.get("var_ref")
            svals = self.var_values(vr) if vr else [ent.text or ""]
            vals.append(any(_oval_compare(item[et], operation, sv, dt) for sv in svals) if svals else None)
        if not vals:
            return True
        if op == "OR":
            if any(v is True for v in vals):
                return True
            return None if any(v is None for v in vals) else False
        if any(v is False for v in vals):
            return False
        return None if any(v is None for v in vals) else True

    @staticmethod
    def _check(check, matches):
        n = len(matches)
        tr = sum(1 for m in matches if m is True)
        fa = sum(1 for m in matches if m is False)
        c = (check or "all").replace("_", " ").lower()
        if c == "all":
            return _OT if (tr == n and n > 0) else (_OF if fa > 0 else _OU)
        if c == "at least one":
            return _OT if tr >= 1 else (_OF if fa == n else _OU)
        if c == "none satisfy":
            return _OT if (tr == 0 and fa == n) else (_OF if tr > 0 else _OU)
        if c == "only one":
            return _OT if tr == 1 else _OF
        return _OT if tr == n and n > 0 else _OF

    @staticmethod
    def _existence(check_existence, cnt):
        c = (check_existence or "at_least_one_exists").lower()
        if c == "none_exist":
            return _OT if cnt == 0 else _OF
        if c == "any_exist":
            return _OT
        if c == "only_one_exists":
            return _OT if cnt == 1 else _OF
        return _OT if cnt >= 1 else _OF  # at_least_one_exists / all_exist

    # ── test / definition evaluation ──
    def eval_test(self, tid):
        if tid in self._tc:
            return self._tc[tid]
        self._tc[tid] = _ONE
        el = self.tests.get(tid)
        if el is None:
            return _ONE
        r = self._eval_test(el)
        self._tc[tid] = r
        return r

    def _eval_test(self, el):
        check = el.get("check", "all")
        check_existence = el.get("check_existence", "at_least_one_exists")
        state_op = el.get("state_operator", "AND")
        obj_ref, state_refs = None, []
        for c in el:
            ct = _ns(c.tag)
            if ct == "object":
                obj_ref = c.get("object_ref")
            elif ct == "state":
                state_refs.append(c.get("state_ref"))
        try:
            items = self._collect(obj_ref, _ns(el.tag))
        except _XmlUnsupported:
            return _ONE
        except Exception:
            return _OE
        if items is None:
            return _ONE
        exist = self._existence(check_existence, len(items))
        if not state_refs:
            return exist
        if not items:
            return exist
        st_results = []
        for sref in state_refs:
            st = self.states.get(sref)
            if st is None:
                st_results.append(_ONE)
                continue
            st_results.append(self._check(check, [self._match(st, it) for it in items]))
        return _OVAL_AND[exist][_oval_combine(state_op, st_results)]

    def eval_def(self, did):
        if did in self._dc:
            return self._dc[did]
        if did in self._stack:
            return _OE  # circular extend_definition
        self._stack.add(did)
        el = self.defs.get(did)
        crit = next((c for c in el if _ns(c.tag) == "criteria"), None) if el is not None else None
        r = self._eval_criteria(crit) if crit is not None else _ONE
        self._stack.discard(did)
        self._dc[did] = r
        return r

    def _eval_criteria(self, node):
        tag = _ns(node.tag)
        if tag == "criterion":
            r = self.eval_test(node.get("test_ref"))
        elif tag == "extend_definition":
            r = self.eval_def(node.get("definition_ref"))
        elif tag == "criteria":
            rs = [self._eval_criteria(c) for c in node if _ns(c.tag) in ("criteria", "criterion", "extend_definition")]
            r = _oval_combine(node.get("operator", "AND"), rs)
        else:
            return _ONE
        if str(node.get("negate", "")).lower() in ("true", "1"):
            r = _oval_negate(r)
        return r


def evaluate_oval_windows(content_path, limit=20000, oval_class=None):
    """Evaluate a Windows OVAL definitions document natively (no oscap). Returns the same
    item list `/api/agent/oval` expects: {definition_id, class, result, title, severity,
    cves, cpes}. `oval_class` (compliance/vulnerability/inventory/patch) restricts evaluation
    to a single class; None / "all" evaluates every class."""
    oc = (oval_class or "").strip().lower()
    if oc in ("all", "any"):
        oc = ""
    try:
        root = ET.parse(content_path).getroot()
    except Exception as e:
        print(f"[oval] parse contenu Windows : {e}", file=sys.stderr)
        return []
    ev = _WinOval(root)
    out = []
    for did, el in ev.defs.items():
        if oc and (el.get("class", "").lower() != oc):
            continue  # skip other classes (faster + honours the filter)
        title = ""; cves = []; cpes = []; sev = ""
        for sub in el.iter():
            t = _ns(sub.tag)
            if t == "title" and not title:
                title = (sub.text or "").strip()
            elif t == "reference":
                src = (sub.get("source") or "").upper(); rid = sub.get("ref_id") or ""
                if src == "CVE" and rid:
                    cves.append(rid)
                elif src == "CPE" and rid:
                    cpes.append(rid)
            elif t == "severity" and not sev:
                sev = (sub.text or "").strip()
        try:
            res = ev.eval_def(did)
        except Exception:
            res = _OE
        out.append({"definition_id": did, "class": el.get("class", ""), "result": res,
                    "title": title[:1000], "severity": sev, "cves": cves, "cpes": cpes})
        if len(out) >= limit:
            break
    return out


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


# ── BAS atomic-test execution (opt-in, read-only recon ONLY) ─────────────────────
# Executing attacker procedures on an endpoint is sensitive: emulation runs only when the
# operator opts in (XOR_ALLOW_EMULATION=1), and even then ONLY commands on a conservative
# read-only-recon allowlist are run. Everything else (writes, persistence, downloads,
# credential dumping, exec chains, anything with shell metacharacters) is reported as
# "Skipped" for manual execution — the agent never auto-runs destructive injects.
_EMU_SAFE = [
    r"^whoami(\s+/[a-z]+)?$", r"^hostname$", r"^systeminfo$", r"^ver$", r"^ipconfig(\s+/all)?$",
    r"^getmac$", r"^arp\s+-a$", r"^route\s+print$", r"^tasklist$", r"^klist$",
    r"^(query\s+user|quser)$", r"^net\s+(config|view|accounts|user|group|localgroup|share|session|time)$",
    r"^nltest\s+/dclist:?\S*$", r"^id$", r"^uname(\s+-[a-z]+)*$", r"^sw_vers$", r"^w$", r"^last$",
    r"^env$", r"^printenv$", r"^ifconfig$", r"^ip\s+(addr|a|route|r)$", r"^netstat(\s+-[a-z]+)*$",
    r"^ps(\s+-[a-zA-Z]+)*$", r"^cat\s+/etc/(os-release|hostname|passwd)$", r"^nslookup\s+[a-z0-9.\-]+$",
]
_EMU_DENY = re.compile(
    r"[;&|><`$]|/add\b|/del\b|/create\b|\badd\b|\bdel(ete)?\b|\brm\b|reg\s+add|new-|set-|remove-|"
    r"invoke-|iex|downloadstring|-enc\b|-e\b|curl|wget|ncat|\bnc\b|base64|format|schtasks|rundll32|mimikatz",
    re.I,
)


def _emu_is_safe(command, executor):
    c = re.sub(r"(?i)^cmd(\.exe)?\s+/c\s+", "", (command or "").strip())
    if not c or c.startswith("#") or _EMU_DENY.search(c):
        return False
    cl = c.lower()
    return any(re.match(p, cl) for p in _EMU_SAFE)


def _emu_exec(test):
    """Execute one atomic test if it is a safe read-only recon command. Returns (outcome, notes).
    Outcomes: Executed (ran, not prevented) / Prevented (blocked) / Skipped (manual/unsafe) / Error."""
    command = (test.get("command") or "").strip()
    executor = (test.get("executor") or "").lower()
    host = platform.system().lower()
    want = (test.get("platform") or "").lower()
    plat_ok = (not want) or ("multi" in want) or ("cross" in want) \
        or ("windows" in want and host == "windows") \
        or (("linux" in want or "unix" in want) and host == "linux") \
        or (("macos" in want or "darwin" in want or "osx" in want) and host == "darwin")
    if not plat_ok:
        return "Skipped", f"platform mismatch (test={want or 'n/a'}, host={host})"
    if executor in ("manual", "") or command.startswith("#"):
        return "Skipped", "manual inject — run by hand and record the outcome"
    if not _emu_is_safe(command, executor):
        return "Skipped", "not auto-run (only read-only recon is executed automatically) — run manually"
    try:
        if executor == "powershell":
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
        elif executor in ("command_prompt", "cmd"):
            cmd = ["cmd", "/c", re.sub(r"(?i)^cmd(\.exe)?\s+/c\s+", "", command)]
        elif executor in ("sh", "bash"):
            cmd = [executor, "-c", command]
        else:
            return "Skipped", f"unsupported executor '{executor}'"
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        if r.returncode != 0 and re.search(r"access is denied|blocked|not permitted|virus|defender|quarantin", out, re.I):
            return "Prevented", out[:300]
        if r.returncode == 0:
            return "Executed", (out[:300] or "ran (no output)")
        return "Error", (out[:300] or f"exit {r.returncode}")
    except subprocess.TimeoutExpired:
        return "Error", "timeout"
    except FileNotFoundError:
        return "Skipped", f"executor '{executor}' unavailable on host"
    except Exception as e:  # noqa: BLE001
        return "Error", str(e)[:200]


# ── Detection attribution (did the executed inject actually fire a detection?) ──────
# After an inject runs, query the host's security telemetry in the post-inject window to
# upgrade the outcome from "Executed" (ran, no detection seen — a visibility gap) to
# "Logged" (telemetry captured it) or "Detected" (a security product alerted). Best-effort
# and read-only; honest by design — benign recon on an unconfigured host stays "Executed".
def _emu_detect_parse(line):
    """Parse the telemetry probe's verdict line 'Outcome|Source' → (outcome, source)."""
    line = (line or "").strip()
    if "|" in line:
        oc, src = line.split("|", 1)
        oc = oc.strip()
        if oc in ("Detected", "Logged", "Prevented", "Alerted"):
            return oc, src.strip()
    return None, None


def _emu_keyword(command):
    c = re.sub(r"(?i)^(cmd(\.exe)?\s+/c\s+|powershell(\.exe)?\s+(-\w+\s+)*-command\s+|powershell(\.exe)?\s+)", "", (command or "").strip())
    toks = c.split()
    return re.sub(r"[^A-Za-z0-9_.\-]", "", toks[0]) if toks else ""


def _emu_detect(start_dt, test):
    """Correlate an executed inject with local detection telemetry. Returns (outcome, source)
    or (None, None). Windows: Defender threats / Defender + Sysmon + PowerShell-ScriptBlock +
    Security-4688 event logs. Linux/macOS: journald/auditd best-effort."""
    kw = _emu_keyword(test.get("command"))
    if not kw:
        return None, None
    if platform.system() == "Windows":
        s = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$t=[datetime]::ParseExact('{s}','yyyy-MM-ddTHH:mm:ss',$null);$kw='{kw}';$r=@();"
            "if(Get-MpThreatDetection|?{$_.InitialDetectionTime -ge $t}){$r+='Detected|Microsoft Defender'};"
            "try{if(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117;StartTime=$t} -MaxEvents 1 -EA Stop){$r+='Detected|Microsoft Defender (1116/1117)'}}catch{};"
            "try{if(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=$t} -EA Stop|?{$_.Message -match $kw}|select -First 1){$r+='Logged|Sysmon (process create, EID1)'}}catch{};"
            "try{if(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$t} -EA Stop|?{$_.Message -match $kw}|select -First 1){$r+='Logged|PowerShell ScriptBlock (4104)'}}catch{};"
            "try{if(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=$t} -EA Stop|?{$_.Message -match $kw}|select -First 1){$r+='Logged|Security audit (process create, 4688)'}}catch{};"
            "if($r){($r|Sort-Object -Unique)[0]}else{'none'}"
        )
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=50)
            lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
            return _emu_detect_parse(lines[-1]) if lines else (None, None)
        except Exception:  # noqa: BLE001
            return None, None
    # Linux / macOS — best-effort journald/auditd scan in the window
    try:
        since = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        r = subprocess.run(["journalctl", "--since", since, "--no-pager"], capture_output=True, text=True, timeout=20)
        if re.search(re.escape(kw), r.stdout or ""):
            return "Logged", "journald"
    except Exception:  # noqa: BLE001
        pass
    return None, None


# ── Advanced forensics (live DFIR triage) ────────────────────────────────────────
# A read-only "live response" snapshot of forensically-relevant host state: running
# processes (path/cmdline/parent), network connections (with PID/state), persistence
# (autoruns / scheduled tasks / services / cron / systemd), logon sessions & users,
# recently-modified files in key dirs, network artifacts (ARP / DNS cache / routes),
# loaded drivers/kernel modules and an event-log summary. Cross-OS, stdlib-only, bounded,
# every collector wrapped — collection NEVER modifies the host. Conservative heuristics add
# triage "flags" (process/autorun from a temp dir, failed-logon spike).
_FZ_PROC, _FZ_CONN, _FZ_TASK, _FZ_FILE, _FZ_MOD = 500, 500, 300, 200, 400
_SUSP_DIRS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\downloads\\",
              "/tmp/", "/var/tmp/", "/dev/shm/")
_RECENT_DIRS_WIN = ["TEMP", "TMP"]
_FLAGS = []  # collected during a triage run


def _is_susp_path(p):
    p = (p or "").lower()
    return any(s in p for s in _SUSP_DIRS)


def _run_text(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:  # noqa: BLE001
        return ""


def _fz_processes():
    out = []
    if platform.system() == "Windows":
        txt = _run_text(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                         "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,Path,CommandLine | ConvertTo-Json -Compress"], 60)
        try:
            data = json.loads(txt) if txt.strip() else []
            if isinstance(data, dict):
                data = [data]
            for p in data[:_FZ_PROC]:
                path = p.get("Path") or ""
                out.append({"pid": p.get("ProcessId"), "ppid": p.get("ParentProcessId"),
                            "name": p.get("Name"), "path": path,
                            "cmdline": (p.get("CommandLine") or "")[:500]})
        except Exception:  # noqa: BLE001
            pass
    else:
        txt = _run_text(["ps", "-eo", "pid,ppid,user,comm,args"], 30)
        for line in txt.splitlines()[1:][:_FZ_PROC]:
            parts = line.split(None, 4)
            if len(parts) >= 5:
                out.append({"pid": parts[0], "ppid": parts[1], "user": parts[2],
                            "name": parts[3], "path": "", "cmdline": parts[4][:500]})
    for p in out:
        if _is_susp_path(p.get("path") or p.get("cmdline")):
            _FLAGS.append({"category": "process", "severity": "warning",
                           "detail": f"process from temp/unusual path: {p.get('name')} (pid {p.get('pid')}) {p.get('path') or p.get('cmdline')[:120]}"})
    return out


def _fz_connections():
    out = []
    if platform.system() == "Windows":
        txt = _run_text(["netstat", "-ano"], 30)
        import re as _re
        for line in txt.splitlines():
            m = _re.match(r"\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(\d+)?\s*$", line)
            if m:
                out.append({"proto": m.group(1), "local": m.group(2), "remote": m.group(3),
                            "state": (m.group(4) or "").strip(), "pid": m.group(5)})
            if len(out) >= _FZ_CONN:
                break
    else:
        txt = _run_text(["ss", "-tunap"], 20) or _run_text(["netstat", "-tunap"], 20)
        for line in txt.splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 5:
                out.append({"proto": cols[0], "state": cols[1] if len(cols) > 5 else "",
                            "local": cols[-3] if len(cols) >= 3 else "", "remote": cols[-2] if len(cols) >= 2 else "",
                            "proc": cols[-1][:120]})
            if len(out) >= _FZ_CONN:
                break
    return out


def _fz_autoruns():
    out = []
    if platform.system() == "Windows":
        try:
            import winreg  # type: ignore
            keys = [(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")]
            for hive, sub in keys:
                hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                try:
                    h = winreg.OpenKey(hive, sub)
                except OSError:
                    continue
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(h, i)
                    except OSError:
                        break
                    out.append({"location": f"{hive_name}\\{sub}", "name": name, "command": str(val)[:300]})
                    i += 1
                winreg.CloseKey(h)
        except Exception:  # noqa: BLE001
            pass
    else:
        out += [{"location": "crontab", "name": "", "command": l[:300]}
                for l in _run_text(["crontab", "-l"], 10).splitlines() if l.strip() and not l.startswith("#")]
        en = _run_text(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager", "--no-legend"], 15)
        out += [{"location": "systemd", "name": l.split()[0], "command": "enabled"} for l in en.splitlines()[:60] if l.split()]
    for a in out:
        if _is_susp_path(a.get("command")):
            _FLAGS.append({"category": "autorun", "severity": "warning",
                           "detail": f"autorun from temp/unusual path: {a.get('name')} → {a.get('command')[:120]}"})
    return out


def _fz_scheduled_tasks():
    if platform.system() != "Windows":
        return []
    out = []
    txt = _run_text(["schtasks", "/query", "/fo", "csv", "/nh"], 40)
    for line in txt.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if parts and parts[0]:
            name = parts[0].strip('"')
            if name.startswith("\\Microsoft\\"):  # built-ins: keep but de-prioritise count
                continue
            out.append({"name": name, "next_run": parts[1] if len(parts) > 1 else "",
                        "status": parts[2] if len(parts) > 2 else ""})
        if len(out) >= _FZ_TASK:
            break
    return out


def _fz_services():
    if platform.system() != "Windows":
        return []
    txt = _run_text(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName | ConvertTo-Json -Compress"], 40)
    try:
        data = json.loads(txt) if txt.strip() else []
        if isinstance(data, dict):
            data = [data]
        return [{"name": s.get("Name"), "display": s.get("DisplayName")} for s in data[:300]]
    except Exception:  # noqa: BLE001
        return []


def _fz_logons():
    out = {"sessions": [], "recent": []}
    if platform.system() == "Windows":
        out["sessions"] = [l.strip() for l in _run_text(["query", "user"], 15).splitlines()[1:] if l.strip()][:30]
    else:
        out["sessions"] = [l.strip() for l in _run_text(["who"], 10).splitlines() if l.strip()][:30]
        out["recent"] = [l.strip() for l in _run_text(["last", "-n", "15"], 10).splitlines() if l.strip() and "wtmp" not in l][:15]
    return out


def _fz_recent_files():
    import time as _t
    out, cutoff = [], _t.time() - 7 * 86400
    dirs = []
    if platform.system() == "Windows":
        for ev in _RECENT_DIRS_WIN:
            if os.environ.get(ev):
                dirs.append(os.environ[ev])
        up = os.environ.get("USERPROFILE", "")
        if up:
            dirs += [os.path.join(up, "Downloads"), os.path.join(up, "Desktop"),
                     os.path.join(up, r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")]
    else:
        home = os.path.expanduser("~")
        dirs += ["/tmp", "/var/tmp", os.path.join(home, "Downloads")]
    for d in dirs:
        try:
            for entry in os.scandir(d):
                if not entry.is_file():
                    continue
                st = entry.stat()
                if st.st_mtime >= cutoff:
                    out.append({"path": entry.path, "size": st.st_size,
                                "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")})
                if len(out) >= _FZ_FILE:
                    return out
        except Exception:  # noqa: BLE001
            continue
    return out


def _fz_network_artifacts():
    art = {"arp": [], "dns": [], "routes": []}
    art["arp"] = [l.strip() for l in _run_text(["arp", "-a"], 15).splitlines() if l.strip()][:200]
    if platform.system() == "Windows":
        dns = _run_text(["ipconfig", "/displaydns"], 20)
        art["dns"] = [l.strip()[len("Record Name . . . . . :"):].strip() for l in dns.splitlines()
                      if "Record Name" in l][:200]
        art["routes"] = [l.strip() for l in _run_text(["route", "print", "-4"], 15).splitlines() if l.strip()][:80]
    else:
        art["routes"] = [l.strip() for l in (_run_text(["ip", "route"], 10) or _run_text(["netstat", "-rn"], 10)).splitlines() if l.strip()][:80]
    return art


def _fz_modules():
    if platform.system() == "Windows":
        out = []
        for line in _run_text(["driverquery", "/fo", "csv", "/nh"], 40).splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if parts and parts[0]:
                out.append({"name": parts[0].strip('"'), "type": parts[1] if len(parts) > 1 else ""})
            if len(out) >= _FZ_MOD:
                break
        return out
    return [l.split()[0] for l in _run_text(["lsmod"], 10).splitlines()[1:][:_FZ_MOD] if l.split()]


def _fz_eventlog():
    out = {}
    if platform.system() == "Windows":
        ps = ("$e=@{};"
              "try{$e['failed_logons_24h']=(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue).Count}catch{};"
              "try{$e['system_errors_24h']=(Get-WinEvent -FilterHashtable @{LogName='System';Level=2;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue).Count}catch{};"
              "$e|ConvertTo-Json -Compress")
        try:
            out = json.loads(_run_text(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], 50) or "{}")
        except Exception:  # noqa: BLE001
            out = {}
    else:
        errs = _run_text(["journalctl", "-p", "err", "--since", "24 hours ago", "--no-pager", "-q"], 20)
        out = {"journal_errors_24h": len([l for l in errs.splitlines() if l.strip()])}
    fl = out.get("failed_logons_24h")
    if isinstance(fl, int) and fl >= 20:
        _FLAGS.append({"category": "auth", "severity": "warning",
                       "detail": f"failed-logon spike: {fl} failed logons (event 4625) in the last 24h"})
    return out


def forensic_triage():
    """Collect a read-only live-forensics triage bundle of the host."""
    global _FLAGS
    _FLAGS = []
    art = {
        "processes": _fz_processes(),
        "connections": _fz_connections(),
        "autoruns": _fz_autoruns(),
        "scheduled_tasks": _fz_scheduled_tasks(),
        "services": _fz_services(),
        "logons": _fz_logons(),
        "recent_files": _fz_recent_files(),
        "network": _fz_network_artifacts(),
        "modules": _fz_modules(),
        "event_log": _fz_eventlog(),
    }
    counts = {k: (len(v) if isinstance(v, list) else (sum(len(x) for x in v.values() if isinstance(x, list)) if isinstance(v, dict) else 1))
              for k, v in art.items()}
    return {
        "os": f"{platform.system()} {platform.release()}",
        "collectedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {"counts": counts, "host": platform.node()},
        "flags": list(_FLAGS),
        "artifacts": art,
    }


# ── Rustinel EDR bridge (kernel-level ETW / eBPF / ESF detection) ─────────────────
# Rustinel (https://github.com/Karib0u/rustinel) is an open-source cross-platform EDR
# sensor: it collects native telemetry via ETW (Windows), eBPF (Linux) and Endpoint
# Security (macOS), evaluates it against Sigma rules, YARA signatures and atomic IOCs, and
# writes ECS-compatible NDJSON alerts to logs/alerts.json.<date>. This bridge gives the XOR
# agent genuine kernel-level detection — the "native ETW/eBPF core" from the roadmap —
# without reimplementing it: the agent simply *tails* Rustinel's alert files and ships the
# new alerts to XORCISM as events. Read-only: the agent never controls or configures the
# sensor. A per-file byte cursor (persisted in the conf) makes each run forward only new
# alerts — nothing is shipped twice, nothing is missed across log rotations.
_RUSTINEL_GLOBS_WIN = [
    r"C:\Program Files\Rustinel\logs\alerts.json*",
    r"C:\ProgramData\Rustinel\logs\alerts.json*",
    r"C:\Rustinel\logs\alerts.json*",
]
_RUSTINEL_GLOBS_NIX = [
    "/var/log/rustinel/alerts.json*",
    "/opt/rustinel/logs/alerts.json*",
    "/usr/local/rustinel/logs/alerts.json*",
    os.path.expanduser("~/rustinel/logs/alerts.json*"),
]
# Sigma rule levels (also surfaced via ECS event.severity / log.level) → event severity.
_RUSTINEL_SEV = {"critical": "critical", "high": "high", "medium": "medium",
                 "low": "low", "informational": "info", "info": "info"}


def _rustinel_globs():
    """Glob patterns for Rustinel's ECS NDJSON alert files (env override wins)."""
    env = os.environ.get("XOR_RUSTINEL_GLOB")
    if env:
        return [g.strip() for g in env.split(os.pathsep) if g.strip()]
    return list(_RUSTINEL_GLOBS_WIN if platform.system() == "Windows" else _RUSTINEL_GLOBS_NIX)


def _ecs_get(d, *paths):
    """Read a value from an ECS record by dotted path, trying a flat dotted key first
    (ECS may be emitted nested {rule:{name}} or flattened {'rule.name':…})."""
    for path in paths:
        if path in d and not isinstance(d[path], (dict, list)):
            return d[path]
        cur = d
        ok = True
        for k in path.split("."):
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok and cur not in (None, "", {}, []):
            return cur
    return None


def _rustinel_alert_to_event(rec):
    """Map one Rustinel ECS NDJSON alert → a XORCISM agent event payload."""
    rule_name = str(_ecs_get(rec, "rule.name", "rule.description", "message") or "Rustinel detection")
    rule_id = _ecs_get(rec, "rule.id", "rule.uuid")
    level = str(_ecs_get(rec, "rule.level", "log.level") or "").lower()
    sev = _RUSTINEL_SEV.get(level, "high")
    engine = _ecs_get(rec, "rule.ruleset", "rule.category", "event.module")
    proc = _ecs_get(rec, "process.name", "process.executable", "process.command_line")
    host = _ecs_get(rec, "host.name", "host.hostname", "agent.name")
    technique = _ecs_get(rec, "threat.technique.id")
    indicator = _ecs_get(rec, "file.hash.sha256", "process.hash.sha256", "destination.ip", "file.path")
    detail = {k: v for k, v in {
        "ts": _ecs_get(rec, "@timestamp", "event.created"),
        "rule": rule_name, "ruleId": rule_id, "level": level or None, "engine": engine,
        "action": _ecs_get(rec, "event.action"), "process": proc, "host": host,
        "technique": technique, "indicator": indicator,
    }.items() if v}
    return {"type": "rustinel_alert", "severity": sev, "title": f"Rustinel: {rule_name[:160]}", "detail": detail}


def rustinel_collect(offsets, limit=500):
    """Tail Rustinel's ECS NDJSON alert files past the stored per-file byte offsets. Returns
    (events, new_offsets, files). Bounded by `limit`; advances a file's cursor only over the
    lines actually consumed, so the next run resumes exactly where this one stopped."""
    events = []
    new_offsets = dict(offsets or {})
    files = []
    for pattern in _rustinel_globs():
        files += glob.glob(pattern)
    files = sorted(set(files))
    for path in files:
        if len(events) >= limit:
            break
        try:
            start = int((offsets or {}).get(path, 0))
            if start > os.path.getsize(path):   # file rotated / truncated → restart
                start = 0
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(start)
                while len(events) < limit:
                    line = fh.readline()
                    if not line:
                        break
                    new_offsets[path] = fh.tell()
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue  # partial/last line of a file being written → skip
                    if isinstance(rec, dict):
                        events.append(_rustinel_alert_to_event(rec))
        except Exception as e:  # noqa: BLE001
            print(f"[rustinel] {path}: {e}", file=sys.stderr)
    return events, new_offsets, files


# ── YARA scanning (malware classification) ───────────────────────────────────────
# The agent runs the local `yara` binary against a path using rules from XORCISM's YARARULE
# store (served at /api/agent/yara-rules) or a local rules file (XOR_YARA_RULES), and reports
# each match as an event. Read-only; bounded; a graceful no-op when `yara` or rules are absent.
_YARA_MATCH = re.compile(r"^([A-Za-z_]\w*)\s+(?:\[[^\]]*\]\s+)?(\S.*)$")


def _yara_exe():
    if subprocess.run(["where" if platform.system() == "Windows" else "which", "yara"],
                      capture_output=True).returncode == 0:
        return "yara"
    return None


def _yara_targets():
    """Paths to scan (env override, else conservative defaults: temp + Downloads)."""
    env = os.environ.get("XOR_YARA_TARGET")
    if env:
        return [t for t in env.split(os.pathsep) if t]
    if platform.system() == "Windows":
        return [p for p in (os.environ.get("TEMP"),
                            os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")) if p]
    return [p for p in ("/tmp", "/var/tmp", os.path.expanduser("~/Downloads")) if os.path.isdir(p)]


def yara_scan(rules_path, targets, timeout=1800):
    """Run `yara -r -w <rules> <target>` for each target; return matches (rule + file)."""
    exe = _yara_exe()
    if not exe:
        return {"available": False, "matches": []}
    matches = []
    for tgt in targets:
        if not os.path.exists(tgt):
            continue
        try:
            r = subprocess.run([exe, "-r", "-w", rules_path, tgt], capture_output=True, text=True, timeout=timeout)
        except Exception:  # noqa: BLE001
            continue
        for line in (r.stdout or "").splitlines():
            line = line.rstrip()
            if not line or line.startswith("0x"):  # `-s` string-detail lines aren't matches
                continue
            m = _YARA_MATCH.match(line)
            if m and m.group(2).strip():
                matches.append({"rule": m.group(1), "file": m.group(2).strip()})
            if len(matches) >= 1000:
                return {"available": True, "matches": matches}
    return {"available": True, "matches": matches}


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

    def do_oval(self, oval_class=None):
        """Real OVAL evaluation against distro/SSG/Windows content; posts the classified
        verdicts to /api/agent/oval (→ OVALRESULTS + ASSETVULNERABILITY/CPE). Uses OpenSCAP
        `oscap` when present (Linux), the native Python OVAL evaluator on Windows (no oscap
        build exists there), and falls back to the built-in config checks otherwise.

        `oval_class` (compliance / vulnerability / inventory / patch) restricts the scan to
        a single OVAL class; None / "all" evaluates every class in the content."""
        oc = (oval_class or "").strip().lower()
        if oc in ("all", "any", ""):
            oc = ""
        workdir = tempfile.mkdtemp(prefix="xor-oval-")
        try:
            rel = _os_release()
            plat_token = f"{(rel.get('ID') or '').lower()}-{(rel.get('VERSION_CODENAME') or '').lower()}".strip("-")
            if not plat_token and platform.system() == "Windows":
                plat_token = "windows"  # hint the XORCISM server which OVAL content to serve
            content, cid = _oval_content(workdir, self.server, self.token, self.insecure, plat_token)
            items, engine = [], None
            # Native OVAL evaluation is possible on Windows for plain OVAL definition files.
            native_win = bool(content) and platform.system() == "Windows" and not _is_datastream(content)
            # Prefer oscap when available, unless XOR_OVAL_NATIVE=1 forces the built-in evaluator
            # (useful on Windows hosts where oscap's probe coverage is incomplete).
            prefer_native = os.environ.get("XOR_OVAL_NATIVE") == "1"
            if content and _which("oscap") and not (prefer_native and native_win):
                engine = "openscap"
                if _is_datastream(content):  # SCAP/XCCDF datastream → xccdf eval (compliance + OVAL via ARF)
                    arf = os.path.join(workdir, "arf.xml")
                    cmd = ["oscap", "xccdf", "eval", "--results-arf", arf]
                    prof = _xccdf_profile(content)
                    if prof:
                        cmd += ["--profile", prof]
                        print(f"[oval] XCCDF profile: {prof}")
                    cmd.append(content)
                    _tolerant_run(cmd, timeout=1800)
                    items = parse_arf_results(arf) if os.path.exists(arf) else []
                else:                        # plain OVAL definitions → oval eval
                    results = os.path.join(workdir, "oval-results.xml")
                    _tolerant_run(["oscap", "oval", "eval", "--results", results, content], timeout=1800)
                    items = parse_oval_results(results, content) if os.path.exists(results) else []
                if oc:  # oscap evaluated every class — keep only the requested one
                    items = [it for it in items if str(it.get("class", "")).lower() == oc]
            elif native_win:
                # Windows without (usable) oscap → evaluate the OVAL definitions natively
                # (registry / file / family / env / WMI). Datastreams (XCCDF) aren't supported
                # natively yet — those still need oscap. The class filter is applied at parse time.
                engine = "native-oval-win"
                items = evaluate_oval_windows(content, oval_class=oc or None)
            # Post when we have verdicts, or when a class was explicitly requested (record an
            # empty scan honouring the filter rather than falling back to all-compliance checks).
            if engine and (items or oc):
                label = cid + (f" [{oc}]" if oc else "")
                st, d = self._post("/api/agent/oval", {"engine": engine, "content": label,
                                                       "system": self.si, "results": items})
                print(f"[oval] {len(items)} verdicts via {engine} ({label}) → "
                      f"{d.get('vulnerabilities', 0)} CVE, conformité {d.get('compliance')} ({st})")
                return len(items)
            # A non-compliance class was requested but no OVAL content covered it → nothing to do
            # (the built-in checks are compliance-only).
            if oc and oc != "compliance":
                print(f"[oval] aucun contenu OVAL de classe « {oc} » disponible — rien à évaluer")
                return 0
            # fallback: portable built-in config/compliance checks
            checks = _builtin_compliance()
            items = [{"definition_id": c["id"], "class": "compliance",
                      "result": "true" if c["result"] == "pass" else "false" if c["result"] == "fail" else "unknown",
                      "title": c["title"], "severity": ""} for c in checks]
            st, d = self._post("/api/agent/oval", {"engine": "builtin", "content": "builtin-compliance",
                                                   "system": self.si, "results": items})
            print(f"[oval] oscap/contenu OVAL absent — {len(items)} contrôles intégrés → {st}")
            return len(items)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

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

    def do_emulate(self, scenario_id):
        """Execute a BAS emulation scenario's atomic-test injects and post outcomes to
        /api/agent/emulation (→ EMULATIONRUN/EMULATIONRESULT). Closes the Threat-Informed
        Defense loop: techniques go from 'test defined' to 'test executed / validated'.
        Execution is opt-in (XOR_ALLOW_EMULATION=1) and limited to read-only recon — see _emu_exec."""
        if not scenario_id:
            print("[emulate] aucun scenarioId — rien à exécuter", file=sys.stderr)
            return 0
        st, d = self._get(f"/api/agent/emulation?scenario={int(scenario_id)}")
        if st != 200:
            print(f"[emulate] récupération scénario {scenario_id} : {st} {d.get('error')}", file=sys.stderr)
            return 0
        tests = d.get("tests", [])
        allow = os.environ.get("XOR_ALLOW_EMULATION") == "1"
        results = []
        for t in tests:
            detected_by = None
            if not allow:
                outcome, notes = "Skipped", "execution disabled — set XOR_ALLOW_EMULATION=1 to run the safe injects"
            else:
                start = datetime.now(timezone.utc) - timedelta(seconds=2)
                outcome, notes = _emu_exec(t)
                cu = (t.get("cleanup") or "").strip()
                if outcome == "Executed" and cu and not cu.startswith("#") and _emu_is_safe(cu, t.get("executor")):
                    try:
                        _emu_exec({"command": cu, "executor": t.get("executor"), "platform": t.get("platform")})
                    except Exception:  # noqa: BLE001
                        pass
                # detection attribution: did the executed inject actually fire a detection?
                if outcome == "Executed":
                    det, src = _emu_detect(start, t)
                    if det:
                        outcome, detected_by = det, src
                        notes = (f"{notes} | detected via {src}")[:300]
                    else:
                        notes = (f"{notes} | ran undetected (no local detection telemetry)")[:300]
            results.append({"atomicTestId": t.get("atomicTestId"), "attackId": t.get("attackId"),
                            "outcome": outcome, "detectedBy": detected_by, "notes": notes})
        st, d = self._post("/api/agent/emulation", {"scenario": int(scenario_id), "results": results})
        nprev = sum(1 for r in results if r["outcome"] == "Prevented")
        nexec = sum(1 for r in results if r["outcome"] == "Executed")
        nskip = sum(1 for r in results if r["outcome"] == "Skipped")
        print(f"[emulate] scénario {scenario_id} : {len(results)} inject(s) → {nprev} prevented / {nexec} executed / {nskip} skipped (run #{d.get('runId')}, {st})")
        return len(results)

    def do_forensics(self):
        """Collect a read-only live-forensics triage snapshot and post it to
        /api/agent/forensics (→ FORENSICTRIAGE + a forensic_triage event). Collection never
        modifies the host; conservative heuristics raise triage flags (temp-path processes /
        autoruns, failed-logon spikes)."""
        bundle = forensic_triage()
        st, d = self._post("/api/agent/forensics", bundle)
        counts = bundle["summary"]["counts"]
        nflags = len(bundle["flags"])
        print(f"[forensics] triage collected ({counts.get('processes',0)} proc / {counts.get('connections',0)} conn / "
              f"{counts.get('autoruns',0)} autoruns), {nflags} flag(s) → triage #{d.get('triageId')} ({st})")
        return nflags

    def do_rustinel(self):
        """Bridge: tail Rustinel's ECS NDJSON detection alerts (kernel-level ETW/eBPF/ESF +
        Sigma/YARA/IOC) and ship the new ones to XORCISM as events (/api/agent/events). The
        agent only *reads* Rustinel's alert files — it never controls the sensor. A per-file
        byte cursor is persisted in the conf so each run forwards only new alerts. A graceful
        no-op when Rustinel isn't installed (no alert file found)."""
        offsets = self.conf.get("rustinel_offsets", {})
        events, new_offsets, files = rustinel_collect(offsets)
        if not files:
            print("[rustinel] no Rustinel alert file found "
                  "(install the sensor or set XOR_RUSTINEL_GLOB) — nothing to forward")
            return 0
        for i in range(0, len(events), 200):   # chunk to keep each POST modest
            self._post("/api/agent/events", {"events": events[i:i + 200]})
        self.conf["rustinel_offsets"] = new_offsets
        save_conf(self.conf_path, self.conf)
        print(f"[rustinel] {len(files)} alert file(s), {len(events)} new detection(s) → events")
        return len(events)

    def do_yara(self):
        """Run a local YARA scan using rules from XORCISM's YARARULE store (served at
        /api/agent/yara-rules) or a local rules file (XOR_YARA_RULES), and post matches as
        events. Read-only; a graceful no-op if the `yara` binary or rules are absent. Targets
        default to temp + Downloads; override with XOR_YARA_TARGET."""
        if not _yara_exe():
            print("[yara] yara binary not installed (skip) — install YARA to enable on-host scanning")
            return 0
        workdir = tempfile.mkdtemp(prefix="xor-yara-")
        try:
            rules_path = os.environ.get("XOR_YARA_RULES")
            if not rules_path:
                st, d = self._get("/api/agent/yara-rules")
                rules = d.get("rules", []) if st == 200 else []
                if not rules:
                    print("[yara] no rules available — set XOR_YARA_RULES or populate XTHREAT.YARARULE")
                    return 0
                rules_path = os.path.join(workdir, "xorcism.yar")
                with open(rules_path, "w", encoding="utf-8", errors="replace") as fh:
                    for r in rules:
                        fh.write((r.get("source") or "") + "\n\n")
                print(f"[yara] fetched {len(rules)} rule(s) from XORCISM")
            targets = _yara_targets()
            res = yara_scan(rules_path, targets)
            matches = res.get("matches", [])
            if matches:
                self._post("/api/agent/events", {"events": [{
                    "type": "yara_match", "severity": "high",
                    "title": f"YARA: {len(matches)} match(es)", "detail": matches[:200],
                }]})
            print(f"[yara] {len(matches)} match(es) over {len(targets)} target(s)")
            return len(matches)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def run_scan(self, kind, oval_class=None, scenario_id=None):
        if kind in ("inventory", "full"):
            self.do_inventory()
        if kind in ("vuln", "full"):
            self.do_vuln()
        if kind in ("oval", "full"):
            self.do_oval(oval_class)
        if kind == "emulate":
            self.do_emulate(scenario_id)
        if kind in ("av", "full"):
            self.do_av()
        if kind in ("hunt", "full"):
            self.do_hunt()
        if kind in ("rustinel", "full"):
            self.do_rustinel()
        if kind in ("yara", "full"):
            self.do_yara()
        if kind == "forensics":
            self.do_forensics()

    def checkin(self):
        st, d = self._post("/api/agent/checkin", {})
        if st != 200:
            print(f"[checkin] erreur {st} : {d.get('error')}")
            return
        jobs = d.get("jobs", [])
        for j in jobs:
            kind = j.get("kind", "full")
            # job params (e.g. {"ovalClass": "compliance"} or {"scenarioId": 5}) — may be a JSON string
            oval_class = None
            scenario_id = None
            params = j.get("params")
            if params:
                try:
                    p = json.loads(params) if isinstance(params, str) else params
                    oval_class = (p or {}).get("ovalClass")
                    scenario_id = (p or {}).get("scenarioId")
                except Exception:
                    oval_class = scenario_id = None
            print(f"[checkin] job {j.get('AgentJobID')} → scan « {kind} »"
                  + (f" [OVAL {oval_class}]" if oval_class else "") + (f" [scenario {scenario_id}]" if scenario_id else ""))
            try:
                self.run_scan(kind, oval_class, scenario_id)
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
    ap.add_argument("--scan", choices=["inventory", "vuln", "oval", "av", "hunt", "full", "emulate", "forensics", "rustinel", "yara"])
    ap.add_argument("--oval-class", choices=["compliance", "vulnerability", "inventory", "patch", "all"],
                    help="restrict an OVAL scan to one class (default: all classes in the content)")
    ap.add_argument("--scenario", type=int, help="EMULATIONSCENARIO id for --scan emulate (BAS run)")
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
        agent.run_scan(args.scan, args.oval_class, args.scenario)
    elif args.once:
        agent.checkin()
    elif args.run:
        agent.run(args.interval)
    else:
        agent.run_scan("full")


if __name__ == "__main__":
    main()
