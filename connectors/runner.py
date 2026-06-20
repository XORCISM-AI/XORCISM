"""
runner.py — Asynchronous worker for the XORCISM connectors (XJOB job queue).

Loop: claims a "queued" job in XJOB.db, loads the manifest, validates the
parameters, builds the argv (no shell → no injection), runs the tool,
logs, parses the output, imports the normalized result into XORCISM, updates
the status/summary.

⚠️ Authorized use only (pentest / lab in scope). RBAC + audit on the web side.

Usage:
    python runner.py                 # loop (worker)
    python runner.py --once          # processes a single job then exits
    python runner.py --selftest connectors/nmap/sample.xml   # parse+import (without tool)
"""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# Auto-PK for the importers (tables without a declared PRIMARY KEY) — registered on the models.
from sqlalchemy import event, text, bindparam, Integer, BigInteger, SmallInteger  # noqa: E402
from sqlalchemy.orm import Mapper  # noqa: E402

_pk_counters: dict = {}
_INT = (Integer, BigInteger, SmallInteger)


def _auto_pk(mapper, connection, target) -> None:
    pk = mapper.primary_key
    if len(pk) != 1 or not isinstance(pk[0].type, _INT):
        return
    attr = mapper.get_property_by_column(pk[0]).key
    if getattr(target, attr, None) is not None:
        return
    tbl = mapper.local_table.name
    key = (str(connection.engine.url), tbl)
    dbmax = connection.execute(text(f'SELECT COALESCE(MAX("{pk[0].name}"),0) FROM "{tbl}"')).scalar()
    nxt = max(_pk_counters.get(key, 0), int(dbmax or 0)) + 1
    _pk_counters[key] = nxt
    setattr(target, attr, nxt)


event.listen(Mapper, "before_insert", _auto_pk)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _db_dir() -> str:
    d = os.getenv("XORCISM_DB_DIR")
    if d:
        return d
    cand = r"C:\Users\jerom\XORCISM_databases"
    return cand if os.path.isdir(cand) else os.path.join(ROOT, "databases")


XJOB_PATH = os.path.join(_db_dir(), "XJOB.db")


# ── Job queue (XJOB.db) ───────────────────────────────────────────────────────
def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(XJOB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=15000")
    return con


def ensure_schema() -> None:
    with _conn() as con:
        con.execute(
            """CREATE TABLE IF NOT EXISTS XJOB(
                 JobID INTEGER PRIMARY KEY AUTOINCREMENT,
                 connector TEXT NOT NULL, params TEXT, target TEXT, engagement_id INTEGER,
                 status TEXT NOT NULL DEFAULT 'queued', user_id INTEGER,
                 created_at TEXT, started_at TEXT, finished_at TEXT,
                 exit_code INTEGER, log TEXT, result_summary TEXT, error TEXT)"""
        )
        con.execute(
            """CREATE TABLE IF NOT EXISTS XENGAGEMENT(
                 EngagementID INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL, scope TEXT, active INTEGER DEFAULT 1,
                 roe TEXT, created_at TEXT, created_by INTEGER)"""
        )
        cols = [r[1] for r in con.execute('PRAGMA table_info("XJOB")').fetchall()]
        for c, typ in (("engagement_id", "INTEGER"), ("worker", "TEXT"), ("result_json", "TEXT")):
            if c not in cols:
                try:
                    con.execute(f'ALTER TABLE "XJOB" ADD COLUMN {c} {typ}')
                except sqlite3.OperationalError:
                    pass
        con.commit()


# ── Engagement scope (ROE) — authoritative revalidation ──────────────────────
def _scope_match(target: str, entry: str) -> bool:
    target, entry = target.strip(), entry.strip()
    if target == entry:
        return True
    try:
        tnet = ipaddress.ip_network(target, strict=False)
        enet = ipaddress.ip_network(entry, strict=False)
        return tnet.version == enet.version and tnet.subnet_of(enet)
    except ValueError:
        pass
    if "-" in target:  # range a.b.c.d-e.f.g.h
        try:
            a, b = target.split("-", 1)
            en = ipaddress.ip_network(entry, strict=False)
            return ipaddress.ip_address(a.strip()) in en and ipaddress.ip_address(b.strip()) in en
        except ValueError:
            pass
    if re.match(r"^[A-Za-z0-9.\-]+$", target) and re.match(r"^[A-Za-z0-9.\-]+$", entry):
        return target == entry or target.endswith("." + entry)
    return False


def target_in_scope(target: str, scope: List[str]) -> bool:
    return any(_scope_match(target, e) for e in scope if e)


def engagement_scope(eng_id: Optional[int]) -> Optional[List[str]]:
    if not eng_id:
        return None
    with _conn() as con:
        row = con.execute("SELECT scope, active FROM XENGAGEMENT WHERE EngagementID=?", (eng_id,)).fetchone()
    if not row or not row["active"]:
        return None
    try:
        return json.loads(row["scope"] or "[]")
    except json.JSONDecodeError:
        return []


def claim_job(local_name: str = "local") -> Optional[sqlite3.Row]:
    """Atomically claims a local queued job (the oldest one).
    The local runner takes ONLY the unassigned jobs (worker IS NULL) or
    explicitly destined for "local" — never those of a remote worker."""
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM XJOB WHERE status='queued' AND (worker IS NULL OR worker=?) ORDER BY JobID LIMIT 1",
            (local_name,)).fetchone()
        if not row:
            return None
        n = con.execute(
            "UPDATE XJOB SET status='running', started_at=? WHERE JobID=? AND status='queued'",
            (_now(), row["JobID"])).rowcount
        con.commit()
        if n == 0:
            return None  # another worker took it
        return con.execute("SELECT * FROM XJOB WHERE JobID=?", (row["JobID"],)).fetchone()


def claim_collected() -> Optional[sqlite3.Row]:
    """Claims a 'collected' job (result returned by a remote worker) to
    import it locally (the local runner has access to the databases)."""
    with _conn() as con:
        row = con.execute("SELECT * FROM XJOB WHERE status='collected' ORDER BY JobID LIMIT 1").fetchone()
        if not row:
            return None
        n = con.execute(
            "UPDATE XJOB SET status='importing' WHERE JobID=? AND status='collected'",
            (row["JobID"],)).rowcount
        con.commit()
        if n == 0:
            return None
        return con.execute("SELECT * FROM XJOB WHERE JobID=?", (row["JobID"],)).fetchone()


def import_collected(job: sqlite3.Row) -> None:
    """Imports the normalized result returned by a remote worker."""
    jid = job["JobID"]
    try:
        result = json.loads(job["result_json"] or "{}")
        # The mapping is ignored (unified import_findings); no manifest needed —
        # which allows sources without a connector (XOR agent: xor-inventory/xor-vuln)
        # to use the same import pipeline.
        try:
            man = load_manifest(job["connector"])
            mapping = man.get("mapping", man["id"])
        except Exception:
            mapping = job["connector"]
        counts = import_result(mapping, result)
        update_job(jid, status="done", finished_at=_now(), result_summary=json.dumps(counts))
        append_log(jid, f"\n[import distant] {json.dumps(counts)}\n")
        print(f"[runner] job {jid} importé (worker {job['worker']}): {json.dumps(counts)}")
    except Exception as e:  # noqa: BLE001
        update_job(jid, status="error", finished_at=_now(), error=str(e))
        append_log(jid, f"\n[erreur import distant] {e}\n")


def update_job(job_id: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with _conn() as con:
        con.execute(f"UPDATE XJOB SET {cols} WHERE JobID=?", (*fields.values(), job_id))
        con.commit()


def append_log(job_id: int, text_: str) -> None:
    with _conn() as con:
        con.execute("UPDATE XJOB SET log = COALESCE(log,'') || ? WHERE JobID=?", (text_, job_id))
        con.commit()


# ── Manifest + validation ───────────────────────────────────────────────────────
def load_manifest(connector: str) -> Dict[str, Any]:
    safe = re.sub(r"[^a-z0-9_-]", "", connector)
    path = os.path.join(HERE, safe, "connector.json")
    if not os.path.exists(path):
        raise ValueError(f"Connecteur inconnu : {connector}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


_HOST = re.compile(r"^[A-Za-z0-9_.\-:/]+$")


def _valid_target(v: str) -> bool:
    """Host / IP / CIDR / simple range. (The engagement scope = later phase.)"""
    v = v.strip()
    if not v or not _HOST.match(v) or len(v) > 255:
        return False
    try:
        ipaddress.ip_network(v, strict=False)  # ip / cidr
        return True
    except ValueError:
        pass
    if re.match(r"^[A-Za-z0-9.\-]+$", v):       # hostname / domain
        return True
    if re.match(r"^[\d.]+-[\d.]+$", v):          # range a.b.c.d-e
        return True
    return False


def validate_params(manifest: Dict[str, Any], raw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for p in manifest.get("parameters", []):
        name, typ = p["name"], p["type"]
        val = raw.get(name, p.get("default"))
        if val is None or val == "":
            if p.get("required"):
                raise ValueError(f"Paramètre requis manquant : {name}")
            continue
        if typ == "enum":
            if val not in (p.get("values") or []):
                raise ValueError(f"{name} hors liste autorisée")
        elif typ == "int":
            val = int(val)
            if "min" in p and val < p["min"]:
                raise ValueError(f"{name} < min")
            if "max" in p and val > p["max"]:
                raise ValueError(f"{name} > max")
        elif typ == "bool":
            val = bool(val)
        elif typ == "target":
            if not _valid_target(str(val)):
                raise ValueError(f"Cible invalide : {val}")
        elif typ == "url":
            u = urllib.parse.urlparse(str(val))
            if u.scheme not in ("http", "https") or not u.hostname:
                raise ValueError(f"URL invalide : {val}")
            val = str(val)
        elif typ == "string":
            val = str(val)
            if p.get("pattern") and not re.match(p["pattern"], val):
                raise ValueError(f"{name} ne respecte pas le format")
            if len(val) > 1024:
                raise ValueError(f"{name} trop long")
        out[name] = val
    return out


def build_argv(manifest: Dict[str, Any], params: Dict[str, Any], outfile: str, workdir: str) -> List[str]:
    argv: List[str] = []
    subst = {**{k: str(v) for k, v in params.items()}, "outfile": outfile, "workdir": workdir}
    for token in manifest["command"]:
        m = re.fullmatch(r"\{\{(\w+)\}\}", token)
        if m:
            key = m.group(1)
            if key not in subst:
                # optional parameter not provided → we skip this token
                continue
            argv.append(subst[key])
        else:
            argv.append(token)
    return argv


# ── Dynamic parser ─────────────────────────────────────────────────────────────
def run_parser(manifest: Dict[str, Any], output: str, params: Dict[str, Any]) -> Dict[str, Any]:
    ppath = os.path.join(HERE, manifest["id"], manifest["parser"])
    spec = importlib.util.spec_from_file_location(f"parser_{manifest['id']}", ppath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod.parse(output, params)


def run_module(manifest: Dict[str, Any], params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    """Connector of type "import": runs connectors/<id>/<run> and returns the
    normalized result (file reading, API call…)."""
    rpath = os.path.join(HERE, manifest["id"], manifest.get("run", "run.py"))
    spec = importlib.util.spec_from_file_location(f"run_{manifest['id']}", rpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod.run(params, workdir)


# ── Import into XORCISM (mappings) ────────────────────────────────────────────────
def import_result(mapping: str, result: Dict[str, Any]) -> Dict[str, int]:
    """Route a normalized connector result into XORCISM.

    Findings connectors (nmap, nuclei, depx, API imports…) return assets/vulns/cpes
    → import_findings (ASSET / CPE / VULNERABILITY). Threat-intel connectors
    (detections.ai…) return an "intel" list → import_threat_intel (XTHREAT). A
    result may carry both; counts are merged."""
    counts: Dict[str, int] = {}
    if result.get("intel"):
        counts.update(import_threat_intel(result))
    if result.get("detections") or result.get("sigma"):
        counts.update(import_sigma_rules(result))
    if any(result.get(k) for k in ("assets", "vulns", "cpes", "components", "services", "project")):
        counts.update(import_findings(result))
    if counts:
        return counts
    # nothing matched a specialized mapping → treat as findings (back-compat)
    return import_findings(result)


def _split_tags(s: Optional[str]) -> List[str]:
    return [t.strip() for t in (s or "").split(",") if t.strip()]


# Full INTELEXCHANGE schema (kept in sync with ensureThreatTables() in xorcism_ts/server/db.ts).
_INTEL_COLUMNS = {
    "IntelID": "INTEGER PRIMARY KEY", "IntelGUID": "TEXT", "IntelName": "TEXT",
    "IntelDescription": "TEXT", "CreatedDate": "DATE", "IntelReference": "TEXT",
    "IntelExternalID": "TEXT", "IntelAuthor": "TEXT", "IntelDate": "DATE",
    "IntelSource": "TEXT", "AttackTags": "TEXT", "ActorTags": "TEXT",
    "MalwareTags": "TEXT", "CveTags": "TEXT", "IntelTags": "TEXT",
    "Views": "INTEGER", "ValidFrom": "DATE", "ValidUntil": "DATE",
}


def import_threat_intel(result: Dict[str, Any]) -> Dict[str, int]:
    """Import normalized threat-intel items into XTHREAT.INTELEXCHANGE.

    Idempotent by IntelReference (the source URL): existing rows are updated, new
    ones inserted. MITRE ATT&CK technique ids found in AttackTags are cross-linked
    into INTELEXCHANGEATTACK (resolving AttackTechniqueID from ATTACKTECHNIQUE when
    ATT&CK is imported) so the items contribute to the ATT&CK matrix coverage.
    The tables are self-created/ALTERed so the importer runs against any DB version."""
    from uuid import uuid4

    items = result.get("intel") or []
    counts = {"intel": 0, "intel_updated": 0, "intel_attack_links": 0}
    if not items:
        return counts

    con = sqlite3.connect(os.path.join(_db_dir(), "XTHREAT.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()

    cols_sql = ", ".join(f"{n} {t}" for n, t in _INTEL_COLUMNS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS INTELEXCHANGE ({cols_sql})")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(INTELEXCHANGE)").fetchall()}
    for name, typ in _INTEL_COLUMNS.items():
        if name not in existing:
            cur.execute(f"ALTER TABLE INTELEXCHANGE ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_intelexchange_ref ON INTELEXCHANGE(IntelReference)")
    cur.execute(
        """CREATE TABLE IF NOT EXISTS INTELEXCHANGEATTACK (
             IntelAttackID INTEGER PRIMARY KEY, IntelID INTEGER, AttackID TEXT,
             AttackTechniqueID INTEGER, CreatedDate DATE, UNIQUE(IntelID, AttackID))"""
    )

    src = result.get("source") or "detections.ai"
    has_attack = cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'"
    ).fetchone() is not None

    for it in items:
        ref = it.get("reference") or it.get("external_id") or it.get("name")
        if not ref:
            continue
        row = cur.execute("SELECT IntelID FROM INTELEXCHANGE WHERE IntelReference=?", (ref,)).fetchone()
        common = (it.get("name"), it.get("description"), ref, it.get("external_id"),
                  it.get("author"), it.get("date"), src, it.get("attack_tags"),
                  it.get("actor_tags"), it.get("malware_tags"), it.get("cve_tags"),
                  it.get("tags"), it.get("views"))
        if row:
            intel_id = row[0]
            cur.execute(
                """UPDATE INTELEXCHANGE SET IntelName=?, IntelDescription=?, IntelReference=?,
                     IntelExternalID=?, IntelAuthor=?, IntelDate=?, IntelSource=?, AttackTags=?,
                     ActorTags=?, MalwareTags=?, CveTags=?, IntelTags=?, Views=? WHERE IntelID=?""",
                (*common, intel_id),
            )
            counts["intel_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO INTELEXCHANGE
                     (IntelName, IntelDescription, IntelReference, IntelExternalID, IntelAuthor,
                      IntelDate, IntelSource, AttackTags, ActorTags, MalwareTags, CveTags,
                      IntelTags, Views, IntelGUID, CreatedDate)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*common, str(uuid4()), _now()),
            )
            intel_id = cur.lastrowid
            counts["intel"] += 1

        for aid in _split_tags(it.get("attack_tags")):
            techid = None
            if has_attack:
                t = cur.execute(
                    "SELECT AttackTechniqueID FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1", (aid,)
                ).fetchone()
                techid = t[0] if t else None
            cur.execute(
                "INSERT OR IGNORE INTO INTELEXCHANGEATTACK (IntelID, AttackID, AttackTechniqueID, CreatedDate) VALUES (?,?,?,?)",
                (intel_id, aid, techid, _now()),
            )
            counts["intel_attack_links"] += cur.rowcount

    con.commit()
    con.close()
    return counts


# SIGMARULE schema (kept in sync with ensureThreatTables() in xorcism_ts/server/db.ts).
_SIGMA_COLUMNS = {
    "SigmaRuleID": "INTEGER PRIMARY KEY", "SigmaRuleGUID": "TEXT", "SigmaRuleName": "TEXT",
    "SigmaRuleDescription": "TEXT", "SigmaYaml": "TEXT", "LogSource": "TEXT", "Level": "TEXT",
    "Status": "TEXT", "Author": "TEXT", "SigmaReference": "TEXT", "AttackTags": "TEXT",
    "CreatedDate": "DATE",
}
_SIGMA_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def import_sigma_rules(result: Dict[str, Any]) -> Dict[str, int]:
    """Import normalized Sigma detection rules into XTHREAT.SIGMARULE (detection content
    connectors: SOC Prime TDM, SigmaHQ…). Idempotent by SigmaReference (the source URL/id):
    existing rules are updated, new ones inserted. Each rule item (dict):
        {"name"/"title", "description", "yaml", "logsource", "level", "status", "author",
         "reference"/"id" (unique), "attack_tags" (CSV Txxxx; else derived from yaml)}
    Self-creates/ALTERs the table so it runs against any DB version."""
    from uuid import uuid4

    items = result.get("detections") or result.get("sigma") or []
    counts = {"sigma": 0, "sigma_updated": 0}
    if not items:
        return counts

    con = sqlite3.connect(os.path.join(_db_dir(), "XTHREAT.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cols_sql = ", ".join(f"{n} {t}" for n, t in _SIGMA_COLUMNS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS SIGMARULE ({cols_sql})")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(SIGMARULE)").fetchall()}
    for name, typ in _SIGMA_COLUMNS.items():
        if name not in existing:
            cur.execute(f"ALTER TABLE SIGMARULE ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_sigmarule_ref ON SIGMARULE(SigmaReference)")
    src = result.get("source") or "SOC Prime"

    for it in items:
        ref = it.get("reference") or it.get("id") or it.get("name") or it.get("title")
        if not ref:
            continue
        yaml_text = it.get("yaml") or ""
        attack = it.get("attack_tags")
        if not attack and yaml_text:
            attack = ", ".join(sorted({m.upper() for m in _SIGMA_ATTACK_RE.findall(yaml_text)}))
        common = (it.get("name") or it.get("title"), it.get("description"), yaml_text,
                  it.get("logsource"), (it.get("level") or "medium"),
                  (it.get("status") or "experimental"), (it.get("author") or src),
                  ref, attack)
        row = cur.execute("SELECT SigmaRuleID FROM SIGMARULE WHERE SigmaReference=?", (ref,)).fetchone()
        if row:
            cur.execute(
                """UPDATE SIGMARULE SET SigmaRuleName=?, SigmaRuleDescription=?, SigmaYaml=?,
                     LogSource=?, Level=?, Status=?, Author=?, SigmaReference=?, AttackTags=?
                   WHERE SigmaRuleID=?""",
                (*common, row[0]),
            )
            counts["sigma_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO SIGMARULE (SigmaRuleName, SigmaRuleDescription, SigmaYaml, LogSource,
                     Level, Status, Author, SigmaReference, AttackTags, SigmaRuleGUID, CreatedDate)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (*common, it.get("guid") or str(uuid4()), _now()),
            )
            counts["sigma"] += 1
    con.commit()
    con.close()
    return counts


def _import_tenant_id() -> Optional[int]:
    """Tenant to stamp on connector/agent-created rows. Configurable per deployment
    via XORCISM_IMPORT_TENANT_ID. None ⇒ leave NULL (legacy) — but NULL-tenant rows
    are HIDDEN from tenant-scoped users in the UI, so set this on multi-tenant setups."""
    v = (os.getenv("XORCISM_IMPORT_TENANT_ID") or "").strip()
    return int(v) if v.lstrip("-").isdigit() else None


def _assign_tenant(asset_ids: set, tid: int) -> None:
    """Best-effort: stamp TenantID on the tenant-scoped rows of the given assets that
    are still NULL (ASSET + its CPE / vulnerability links), so connector/agent imports
    are visible to tenant-scoped users. The TenantID columns are added at runtime by
    ensureTenantColumns() (absent on some deployments → ignored)."""
    from xorcism_python.models.base import session_scope

    ids = [int(a) for a in asset_ids if a is not None]
    if not ids:
        return
    with session_scope("XORCISM") as s:
        for tbl in ("ASSET", "CPEFORASSET", "ASSETVULNERABILITY"):
            try:
                stmt = text(
                    f'UPDATE "{tbl}" SET "TenantID"=:tid WHERE "AssetID" IN :ids AND "TenantID" IS NULL'
                ).bindparams(bindparam("ids", expanding=True))
                s.execute(stmt, {"tid": tid, "ids": ids})
            except Exception:  # noqa: BLE001 — column/table not present in this deployment
                pass


def import_findings(result: Dict[str, Any]) -> Dict[str, int]:
    """Generic mapping of a normalized result into XORCISM.
    Accepted schema (all keys optional):
      project   : str  ("application/SBOM" attachment asset)
      assets    : [{ip, hostname, key, os}]
      services  : [{asset, cpe, ...}]
      cpes      : [str]                 (CPE catalog)
      components: [{name, version, purl, cpe}]   (SBOM → CPE linked to the project)
      vulns     : [{asset, ref, severity, name, ...}]
    """
    from xorcism_python.models.base import session_scope
    from xorcism_python.models.xorcism import ASSET, CPE, CPEFORASSET, ASSETVULNERABILITY
    from xorcism_python.models.xvulnerability import VULNERABILITY

    counts = {"assets": 0, "cpes": 0, "cpe_links": 0, "vulns": 0, "vuln_links": 0}
    key2aid: Dict[str, int] = {}
    proj_aid: Optional[int] = None

    with session_scope("XORCISM") as s:
        def ensure_asset(name: Optional[str]) -> Optional[int]:
            if not name:
                return None
            o = s.query(ASSET).filter_by(AssetName=name).first()
            if o is None:
                o = ASSET(AssetName=name, CreatedDate=_now())
                s.add(o)
                s.flush()
                counts["assets"] += 1
            return o.AssetID

        for a in result.get("assets", []):
            aid = ensure_asset(a.get("hostname") or a.get("ip") or a.get("key"))
            if aid:
                if a.get("key"):
                    key2aid[a["key"]] = aid
                if a.get("ip"):
                    key2aid[a["ip"]] = aid
        if result.get("project"):
            proj_aid = ensure_asset(result["project"])

        cpe_id: Dict[str, int] = {}

        def ensure_cpe(name: Optional[str]) -> Optional[int]:
            if not name:
                return None
            if name in cpe_id:
                return cpe_id[name]
            o = s.query(CPE).filter_by(CPEName=name).first()
            if o is None:
                o = CPE(CPEName=name, CreatedDate=_now())
                s.add(o)
                s.flush()
                counts["cpes"] += 1
            cpe_id[name] = o.CPEID
            return o.CPEID

        def link_cpe(aid: Optional[int], cid: Optional[int]) -> None:
            if aid and cid and s.query(CPEFORASSET).filter_by(AssetID=aid, CPEID=cid).first() is None:
                s.add(CPEFORASSET(AssetID=aid, CPEID=cid, CreatedDate=_now()))
                counts["cpe_links"] += 1

        for c in result.get("cpes", []):
            ensure_cpe(c)
        for comp in result.get("components", []):
            cname = comp.get("cpe") or comp.get("purl") or (
                f"{comp.get('name')}@{comp.get('version')}" if comp.get("name") else None)
            link_cpe(proj_aid, ensure_cpe(cname))
        for sv in result.get("services", []):
            if sv.get("cpe"):
                link_cpe(key2aid.get(sv.get("asset")), ensure_cpe(sv.get("cpe")))

    vulns = result.get("vulns", [])
    if vulns:
        vid_by_ref: Dict[str, int] = {}
        with session_scope("XVULNERABILITY") as sv_:
            for v in vulns:
                ref = v.get("ref")
                if not ref or ref in vid_by_ref:
                    continue
                vo = sv_.query(VULNERABILITY).filter_by(VULGUID=ref).first()
                if vo is None:
                    desc = f"{v.get('name') or ''} [{v.get('severity') or '?'}]".strip()
                    vo = VULNERABILITY(VULGUID=ref, VULReferentialID=ref, VULDescription=desc, CreatedDate=_now())
                    sv_.add(vo)
                    sv_.flush()
                    counts["vulns"] += 1
                vid_by_ref[ref] = vo.VulnerabilityID
        with session_scope("XORCISM") as s:
            seen: set = set()
            for v in vulns:
                aid = key2aid.get(v.get("asset")) or proj_aid
                vid = vid_by_ref.get(v.get("ref"))
                if aid is None or vid is None or (aid, vid) in seen:
                    continue
                seen.add((aid, vid))
                if s.query(ASSETVULNERABILITY).filter_by(AssetID=aid, VulnerabilityID=vid).first() is None:
                    s.add(ASSETVULNERABILITY(AssetID=aid, VulnerabilityID=vid, CreatedDate=_now()))
                    counts["vuln_links"] += 1

    # Multi-tenant: stamp the configured tenant on the assets this import touched,
    # so connector/agent-created rows aren't hidden from tenant-scoped users.
    tid = _import_tenant_id()
    if tid is not None:
        touched = set(key2aid.values())
        if proj_aid is not None:
            touched.add(proj_aid)
        _assign_tenant(touched, tid)
    return counts


def import_nuclei(result: Dict[str, Any]) -> Dict[str, int]:
    """Nuclei findings → ASSET + VULNERABILITY (severity in the description) +
    ASSETVULNERABILITY link. Idempotent (get-or-create by AssetName / VULGUID)."""
    from xorcism_python.models.base import session_scope
    from xorcism_python.models.xorcism import ASSET, ASSETVULNERABILITY
    from xorcism_python.models.xvulnerability import VULNERABILITY

    counts = {"assets": 0, "vulns": 0, "vuln_links": 0}
    key2aid: Dict[str, int] = {}

    with session_scope("XORCISM") as s:
        for a in result.get("assets", []):
            name = a.get("hostname") or a.get("ip") or a.get("key")
            if not name:
                continue
            obj = s.query(ASSET).filter_by(AssetName=name).first()
            if obj is None:
                obj = ASSET(AssetName=name, CreatedDate=_now())
                s.add(obj)
                s.flush()
                counts["assets"] += 1
            if a.get("key"):
                key2aid[a["key"]] = obj.AssetID

    if result.get("vulns"):
        vid_by_ref: Dict[str, int] = {}
        with session_scope("XVULNERABILITY") as sv_:
            for v in result["vulns"]:
                ref = v.get("ref")
                if not ref or ref in vid_by_ref:
                    continue
                vo = sv_.query(VULNERABILITY).filter_by(VULGUID=ref).first()
                if vo is None:
                    desc = f"{v.get('name') or ''} [{v.get('severity') or '?'}]".strip()
                    vo = VULNERABILITY(VULGUID=ref, VULReferentialID=ref, VULDescription=desc, CreatedDate=_now())
                    sv_.add(vo)
                    sv_.flush()
                    counts["vulns"] += 1
                vid_by_ref[ref] = vo.VulnerabilityID
        with session_scope("XORCISM") as s:
            seen: set = set()
            for v in result["vulns"]:
                aid, vid = key2aid.get(v.get("asset")), vid_by_ref.get(v.get("ref"))
                if aid is None or vid is None or (aid, vid) in seen:
                    continue
                seen.add((aid, vid))
                if s.query(ASSETVULNERABILITY).filter_by(AssetID=aid, VulnerabilityID=vid).first() is None:
                    s.add(ASSETVULNERABILITY(AssetID=aid, VulnerabilityID=vid, CreatedDate=_now()))
                    counts["vuln_links"] += 1
    return counts


def import_nmap(result: Dict[str, Any]) -> Dict[str, int]:
    from xorcism_python.models.base import session_scope
    from xorcism_python.models.xorcism import ASSET, CPE, CPEFORASSET, ASSETVULNERABILITY
    from xorcism_python.models.xvulnerability import VULNERABILITY

    counts = {"assets": 0, "cpes": 0, "cpe_links": 0, "vulns": 0, "vuln_links": 0}
    ip2aid: Dict[str, int] = {}        # ip → AssetID (integer, stable outside the session)

    with session_scope("XORCISM") as s:
        for a in result.get("assets", []):
            name = a.get("hostname") or a.get("ip")
            if not name:
                continue
            obj = s.query(ASSET).filter_by(AssetName=name).first()
            if obj is None:
                obj = ASSET(AssetName=name, AssetDescription=f"OS: {a.get('os') or '?'}", CreatedDate=_now())
                s.add(obj)
                s.flush()
                counts["assets"] += 1
            if a.get("ip"):
                ip2aid[a["ip"]] = obj.AssetID

        cpe_id: Dict[str, int] = {}
        for c in result.get("cpes", []):
            o = s.query(CPE).filter_by(CPEName=c).first()
            if o is None:
                o = CPE(CPEName=c, CreatedDate=_now())
                s.add(o)
                s.flush()
                counts["cpes"] += 1
            cpe_id[c] = o.CPEID

        for sv in result.get("services", []):
            cpe, aid = sv.get("cpe"), ip2aid.get(sv.get("asset"))
            if cpe and aid is not None and cpe in cpe_id:
                cid = cpe_id[cpe]
                if s.query(CPEFORASSET).filter_by(AssetID=aid, CPEID=cid).first() is None:
                    s.add(CPEFORASSET(AssetID=aid, CPEID=cid, CreatedDate=_now()))
                    counts["cpe_links"] += 1

    # Vulnerabilities: XVULNERABILITY database (cross-database) + link in XORCISM
    if result.get("vulns"):
        vid_by_ref: Dict[str, int] = {}
        with session_scope("XVULNERABILITY") as sv_:
            for v in result["vulns"]:
                ref = v.get("ref")
                if not ref:
                    continue
                vo = sv_.query(VULNERABILITY).filter_by(VULGUID=ref).first()
                if vo is None:
                    vo = VULNERABILITY(VULGUID=ref, VULReferentialID=ref, CreatedDate=_now())
                    sv_.add(vo)
                    sv_.flush()
                    counts["vulns"] += 1
                vid_by_ref[ref] = vo.VulnerabilityID
        with session_scope("XORCISM") as s:
            for v in result["vulns"]:
                aid, vid = ip2aid.get(v.get("asset")), vid_by_ref.get(v.get("ref"))
                if aid is None or vid is None:
                    continue
                if s.query(ASSETVULNERABILITY).filter_by(AssetID=aid, VulnerabilityID=vid).first() is None:
                    s.add(ASSETVULNERABILITY(AssetID=aid, VulnerabilityID=vid, CreatedDate=_now()))
                    counts["vuln_links"] += 1
    return counts


# ── Job processing ───────────────────────────────────────────────────────────
def process_job(job: sqlite3.Row) -> None:
    jid = job["JobID"]
    try:
        manifest = load_manifest(job["connector"])
        params = validate_params(manifest, json.loads(job["params"] or "{}"))

        # Authoritative scope guard: every target must be in the engagement.
        tparam = next((p for p in manifest.get("parameters", []) if p["type"] in ("target", "url")), None)
        if tparam and params.get(tparam["name"]):
            raw_tgt = str(params[tparam["name"]])
            tgt = urllib.parse.urlparse(raw_tgt).hostname or raw_tgt if tparam["type"] == "url" else raw_tgt
            scope = engagement_scope(job["engagement_id"])
            if not scope or not target_in_scope(tgt, scope):
                raise PermissionError(f"cible « {tgt} » hors du périmètre d'engagement (refus)")

        workdir = tempfile.mkdtemp(prefix=f"xjob_{jid}_")
        exit_code = 0

        if manifest.get("type") == "tool-runner":
            out_kind = (manifest.get("output") or {}).get("kind", "stdout")
            ext = (manifest.get("output") or {}).get("ext", "out")
            outfile = os.path.join(workdir, f"output.{ext}")
            argv = build_argv(manifest, params, outfile, workdir)
            append_log(jid, f"$ {' '.join(argv)}\n")
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=3600)
            exit_code = proc.returncode
            if proc.stdout:
                append_log(jid, proc.stdout)
            if proc.stderr:
                append_log(jid, proc.stderr)
            if proc.returncode != 0:
                raise RuntimeError(f"{manifest.get('binary', argv[0])} a échoué (code {proc.returncode})")
            output = outfile if out_kind == "file" else proc.stdout
            result = run_parser(manifest, output, params)
        else:
            # Import / API connector: run.py module → normalized result
            append_log(jid, f"[import:{manifest['id']}] exécution du module\n")
            result = run_module(manifest, params, workdir)

        counts = import_result(manifest.get("mapping", manifest["id"]), result)
        # Retain the normalized result so the tool-chaining engine (chain.ts) can read
        # the facts (open ports / services / detected tech / vulns) of a finished job.
        update_job(jid, status="done", finished_at=_now(), exit_code=exit_code,
                   result_summary=json.dumps(counts), result_json=json.dumps(result)[:500000])
        append_log(jid, f"\n[import] {json.dumps(counts)}\n")
    except FileNotFoundError as e:
        update_job(jid, status="failed", finished_at=_now(), error=f"binaire introuvable: {e}")
        append_log(jid, f"\n[erreur] binaire introuvable: {e}\n")
    except Exception as e:  # noqa: BLE001
        update_job(jid, status="failed", finished_at=_now(), error=str(e))
        append_log(jid, f"\n[erreur] {e}\n")


def worker_loop(once: bool, local_name: str = "local") -> None:
    """LOCAL runner: runs the local jobs AND imports the results returned
    by the remote workers ('collected' jobs)."""
    ensure_schema()
    print(f"[runner] file = {XJOB_PATH} (worker local = {local_name})")
    while True:
        collected = claim_collected()
        if collected:
            print(f"[runner] import distant job {collected['JobID']} ({collected['connector']})")
            import_collected(collected)
            if once:
                return
            continue
        job = claim_job(local_name)
        if job:
            print(f"[runner] job {job['JobID']} ({job['connector']})")
            process_job(job)
            if once:
                return
        else:
            if once:
                print("[runner] aucun job en attente")
                return
            time.sleep(2)


def run_job_local(connector: str, params_raw: Dict[str, Any], log_fn) -> Dict[str, Any]:
    """Runs a connector (tool or import module) and returns the normalized
    result — WITHOUT touching the database. Used by the remote worker mode."""
    manifest = load_manifest(connector)
    params = validate_params(manifest, params_raw)
    workdir = tempfile.mkdtemp(prefix="xremote_")
    if manifest.get("type") == "tool-runner":
        out_kind = (manifest.get("output") or {}).get("kind", "stdout")
        ext = (manifest.get("output") or {}).get("ext", "out")
        outfile = os.path.join(workdir, f"output.{ext}")
        argv = build_argv(manifest, params, outfile, workdir)
        log_fn(f"$ {' '.join(argv)}\n")
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=3600)
        if proc.stdout:
            log_fn(proc.stdout)
        if proc.stderr:
            log_fn(proc.stderr)
        if proc.returncode != 0:
            raise RuntimeError(f"{manifest.get('binary', argv[0])} a échoué (code {proc.returncode})")
        output = outfile if out_kind == "file" else proc.stdout
        return run_parser(manifest, output, params)
    log_fn(f"[import:{connector}] exécution du module\n")
    return run_module(manifest, params, workdir)


def remote_loop(url: str, token: str, name: str, capabilities: List[str], once: bool) -> None:
    """REMOTE AGENT mode: claims jobs from the XORCISM server via HTTP (token),
    runs the tool locally and returns the normalized result. No DB access required."""
    import requests  # lazy
    base = url.rstrip("/")
    hdr = {"Authorization": f"Bearer {token}"}
    print(f"[agent {name}] connecté à {base} ; capabilities={capabilities or 'toutes'}")
    while True:
        try:
            r = requests.post(f"{base}/api/worker/claim", headers=hdr,
                              json={"capabilities": capabilities}, timeout=30)
            if r.status_code == 401:
                print("[agent] jeton refusé — arrêt")
                return
            r.raise_for_status()
            job = r.json().get("job")
        except Exception as e:  # noqa: BLE001
            print(f"[agent] erreur de claim : {e}")
            if once:
                return
            time.sleep(5)
            continue

        if not job:
            if once:
                print("[agent] aucun job assigné")
                return
            time.sleep(3)
            continue

        jid = job["JobID"]
        print(f"[agent {name}] job {jid} ({job['connector']})")

        def _log(chunk: str, _jid=jid) -> None:
            try:
                requests.post(f"{base}/api/worker/job/{_jid}/log", headers=hdr,
                              json={"chunk": chunk}, timeout=15)
            except Exception:  # noqa: BLE001
                pass

        try:
            params_raw = json.loads(job.get("params") or "{}")
            result = run_job_local(job["connector"], params_raw, _log)
            requests.post(f"{base}/api/worker/job/{jid}/result", headers=hdr,
                          json={"ok": True, "result": result, "exit_code": 0}, timeout=60)
            print(f"[agent {name}] job {jid} terminé → résultat renvoyé")
        except FileNotFoundError:
            requests.post(f"{base}/api/worker/job/{jid}/result", headers=hdr,
                          json={"ok": False, "error": "binaire introuvable sur l'agent"}, timeout=30)
        except Exception as e:  # noqa: BLE001
            requests.post(f"{base}/api/worker/job/{jid}/result", headers=hdr,
                          json={"ok": False, "error": str(e)}, timeout=30)
            print(f"[agent {name}] job {jid} échec : {e}")
        if once:
            return


def main() -> None:
    ap = argparse.ArgumentParser(description="Worker des connecteurs XORCISM")
    ap.add_argument("--once", action="store_true", help="traite un seul job puis sort")
    ap.add_argument("--selftest", metavar="FILE", help="parse+import d'un fichier de sortie/rapport (sans exécuter d'outil)")
    ap.add_argument("--connector", default="nmap", help="connecteur pour --selftest (défaut: nmap)")
    ap.add_argument("--param", action="append", default=[], metavar="k=v", help="paramètre supplémentaire pour --selftest")
    ap.add_argument("--name", default="local", help="nom du worker local (jobs assignés)")
    ap.add_argument("--remote", metavar="URL", help="mode agent distant : URL du serveur XORCISM")
    ap.add_argument("--token", help="jeton du worker (mode --remote)")
    ap.add_argument("--capabilities", default="", help="connecteurs supportés, séparés par des virgules (mode --remote)")
    args = ap.parse_args()
    if args.remote:
        if not args.token:
            ap.error("--remote nécessite --token")
        caps = [c.strip() for c in args.capabilities.split(",") if c.strip()]
        remote_loop(args.remote, args.token, args.name, caps, args.once)
        return
    if args.selftest:
        man = load_manifest(args.connector)
        params: Dict[str, Any] = {}
        for kv in args.param:
            k, _, v = kv.partition("=")
            params[k] = v
        if man.get("type") == "tool-runner":
            result = run_parser(man, args.selftest, params)
        else:
            params.setdefault("file", args.selftest)
            result = run_module(man, params, tempfile.mkdtemp(prefix="selftest_"))
        counts = import_result(man.get("mapping", man["id"]), result)
        print(f"selftest {args.connector} import:", json.dumps(counts))
        return
    worker_loop(args.once, args.name)


if __name__ == "__main__":
    main()
