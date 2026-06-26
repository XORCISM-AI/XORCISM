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


def import_ai_guardrail(result: Dict[str, Any]) -> Dict[str, int]:
    """Import inline AI-guardrail-gateway telemetry (blocked/flagged prompts) into
    XAGENT.AIGUARDRAILVIOLATION so enforcement events appear in the AI Guardrails cockpit
    alongside the endpoint agent's posture data. The table is created by the server at boot."""
    import datetime
    viols = result.get("guardrail_violations") or []
    if not viols:
        return {}
    host = str(result.get("host") or "ai-gateway")
    src = str(result.get("source") or "gateway")
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(os.path.join(_db_dir(), "XAGENT.db"), timeout=15)
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='AIGUARDRAILVIOLATION'")
        if not cur.fetchone():
            return {}
        n = 0
        for v in viols:
            action = str(v.get("action") or "blocked").lower()
            if action not in ("blocked", "flagged"):
                continue
            cur.execute(
                "INSERT INTO AIGUARDRAILVIOLATION(agent,host,ai_agent,technique,name,severity,evidence,source,ai_used,hunt_id,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("gateway:" + src, host, v.get("ai_agent"), str(v.get("technique") or "AIX-01")[:40],
                 ("Gateway %s: %s" % (action, v.get("rule") or v.get("name") or "guardrail rule"))[:200],
                 str(v.get("severity") or "medium").lower(), str(v.get("detail") or "")[:240],
                 "gateway:" + src, 0, None, now))
            n += 1
        con.commit()
        return {"guardrail_violations": n}
    except sqlite3.OperationalError:
        return {}
    finally:
        con.close()


# ── Import into XORCISM (mappings) ────────────────────────────────────────────────
def import_ai_systems(result: Dict[str, Any]) -> Dict[str, int]:
    """Import agentlessly-discovered AI/LLM services into XORCISM.AISYSTEM (the AI-SPM inventory).
    Used by the cloud-ai-discovery connector. Idempotent by (Name, Provider) — existing rows are
    refreshed with the latest model/endpoint + discovery stamp; Owner / Frameworks / Guardrails are
    NOT clobbered (so a system a human later governs stays governed). New rows are inserted with
    Discovered=1 and no governance fields, so they surface as Shadow AI on /ai-systems until adopted.
    Stamps XORCISM_IMPORT_TENANT_ID. Each item: {name, provider, model, modelType, hosting, endpoint,
    discovered, discoverySource}."""
    from uuid import uuid4

    items = result.get("aisystems") or []
    counts = {"aisystems": 0, "aisystems_updated": 0}
    if not items:
        return counts

    tid = _import_tenant_id()
    con = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS AISYSTEM (
             AISystemID INTEGER PRIMARY KEY, AISystemGUID TEXT, Name TEXT, Description TEXT, Purpose TEXT,
             Owner TEXT, Provider TEXT, ModelName TEXT, ModelType TEXT, Hosting TEXT, DataClassification TEXT,
             UsesPersonalData INTEGER DEFAULT 0, RiskTier TEXT, Lifecycle TEXT, Guardrails TEXT, Frameworks TEXT,
             Notes TEXT, Status TEXT, Endpoint TEXT, Discovered INTEGER, DiscoverySource TEXT,
             TenantID INTEGER, CreatedDate TEXT)""")
    have = {r[1] for r in cur.execute("PRAGMA table_info(AISYSTEM)").fetchall()}
    for n, t in (("Endpoint", "TEXT"), ("Discovered", "INTEGER"), ("DiscoverySource", "TEXT")):
        if n not in have:
            cur.execute(f"ALTER TABLE AISYSTEM ADD COLUMN {n} {t}")
    now = datetime.now(timezone.utc).isoformat()
    nid = (cur.execute("SELECT COALESCE(MAX(AISystemID),0) FROM AISYSTEM").fetchone()[0] or 0) + 1

    for it in items:
        name = (it.get("name") or it.get("model") or "").strip()
        prov = (it.get("provider") or "Cloud").strip()
        if not name:
            continue
        src = it.get("discoverySource") or result.get("source") or "cloud-ai-discovery"
        row = cur.execute("SELECT AISystemID FROM AISYSTEM WHERE Name=? AND COALESCE(Provider,'')=?", (name, prov)).fetchone()
        if row:
            cur.execute(
                "UPDATE AISYSTEM SET ModelName=?, ModelType=?, Hosting=?, Endpoint=?, Discovered=1, DiscoverySource=? WHERE AISystemID=?",
                (it.get("model"), it.get("modelType") or "LLM", it.get("hosting"), it.get("endpoint"), src, row[0]))
            counts["aisystems_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO AISYSTEM (AISystemID, AISystemGUID, Name, Provider, ModelName, ModelType, Hosting,
                     Endpoint, RiskTier, Lifecycle, Status, Discovered, DiscoverySource, Owner, Frameworks, Guardrails,
                     TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?)""",
                (nid, str(uuid4()), name, prov, it.get("model"), it.get("modelType") or "LLM", it.get("hosting"),
                 it.get("endpoint"), "Limited", "Production", "Active", src, "", "", "", tid, now))
            nid += 1
            counts["aisystems"] += 1
    con.commit()
    con.close()
    return counts


def import_result(mapping: str, result: Dict[str, Any]) -> Dict[str, int]:
    """Route a normalized connector result into XORCISM.

    Findings connectors (nmap, nuclei, depx, API imports…) return assets/vulns/cpes
    → import_findings (ASSET / CPE / VULNERABILITY). Threat-intel connectors
    (detections.ai…) return an "intel" list → import_threat_intel (XTHREAT). A
    result may carry both; counts are merged."""
    counts: Dict[str, int] = {}
    # Outbound / action connectors (e.g. ChatOps: Slack / Mattermost) don't import data — they
    # report what they sent via "notify". Short-circuit so the importer never touches a DB.
    if "notify" in result:
        return {"notified": int(result.get("notify") or 0)}
    if result.get("intel"):
        counts.update(import_threat_intel(result))
    if result.get("euvd"):
        counts.update(import_euvd(result))
    if result.get("detections") or result.get("sigma"):
        counts.update(import_sigma_rules(result))
    if result.get("yara"):
        counts.update(import_yara_rules(result))
    if result.get("identities"):
        counts.update(import_identities(result))
    if result.get("signins"):
        counts.update(import_signins(result))
    if result.get("zt_policies"):
        counts.update(import_zt_policies(result))
    if result.get("monitors") or result.get("monitoring_incidents"):
        counts.update(import_monitoring(result))
    if result.get("documents"):
        counts.update(import_documents(result))
    if result.get("netflow"):
        counts.update(import_netflow(result))
    if result.get("alerts") or result.get("incidents"):
        counts.update(import_incidents(result))
    if result.get("compliance"):
        counts.update(import_compliance(result))
    if result.get("wifi") or result.get("wifi_networks"):
        counts.update(import_wifi(result))
    if result.get("emulation_results"):
        counts.update(import_emulation(result))
    if result.get("guardrail_violations"):
        counts.update(import_ai_guardrail(result))
    if result.get("aisystems"):
        counts.update(import_ai_systems(result))
    if any(result.get(k) for k in ("assets", "vulns", "cpes", "components", "services", "project")):
        counts.update(import_findings(result))
    # DevSecOps: a SAST/Secrets/SCA/DAST connector result is also a pipeline security scan — recorded
    # here (not at a single call site) so EVERY import path (worker, local run, attack-chain step) counts.
    if mapping in _DEVSECOPS_TOOLS:
        try:
            counts.update(record_devsecops_scan(mapping, result))
        except Exception:  # noqa: BLE001
            pass
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
    # lossless retention of the connector's original normalized item (indexed into STIXOBJECT by the
    # in-process STIX-store sweeper, see stixstore.ts) — keeps anything not mapped to a column above
    "RawJson": "TEXT",
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
        try:
            raw_json = json.dumps(it, default=str)
        except Exception:
            raw_json = None
        common = (it.get("name"), it.get("description"), ref, it.get("external_id"),
                  it.get("author"), it.get("date"), src, it.get("attack_tags"),
                  it.get("actor_tags"), it.get("malware_tags"), it.get("cve_tags"),
                  it.get("tags"), it.get("views"), raw_json)
        if row:
            intel_id = row[0]
            cur.execute(
                """UPDATE INTELEXCHANGE SET IntelName=?, IntelDescription=?, IntelReference=?,
                     IntelExternalID=?, IntelAuthor=?, IntelDate=?, IntelSource=?, AttackTags=?,
                     ActorTags=?, MalwareTags=?, CveTags=?, IntelTags=?, Views=?, RawJson=? WHERE IntelID=?""",
                (*common, intel_id),
            )
            counts["intel_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO INTELEXCHANGE
                     (IntelName, IntelDescription, IntelReference, IntelExternalID, IntelAuthor,
                      IntelDate, IntelSource, AttackTags, ActorTags, MalwareTags, CveTags,
                      IntelTags, Views, RawJson, IntelGUID, CreatedDate)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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


# YARARULE schema (kept in sync with ensureThreatTables() in xorcism_ts/server/db.ts).
_YARA_COLUMNS = {
    "YaraRuleID": "INTEGER PRIMARY KEY", "YaraRuleGUID": "TEXT", "YaraRuleName": "TEXT",
    "YaraRuleDescription": "TEXT", "YaraSource": "TEXT", "Namespace": "TEXT", "Tags": "TEXT",
    "Meta": "TEXT", "Author": "TEXT", "YaraReference": "TEXT", "AttackTags": "TEXT",
    "StringCount": "INTEGER", "Status": "TEXT", "CreatedDate": "DATE",
}
_YARA_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def import_yara_rules(result: Dict[str, Any]) -> Dict[str, int]:
    """Import normalized YARA rules into XTHREAT.YARARULE (the YARA "support" store —
    browsable in the explorer, served to agents, used by the yara connector / import_yara.py).
    Idempotent by YaraReference (else name+namespace). Each rule item (dict):
        {"name", "description", "source" (full rule text), "namespace", "tags" (CSV),
         "meta", "author", "reference"/"id" (unique), "attack_tags", "string_count"}
    Self-creates/ALTERs the table so it runs against any DB version."""
    from uuid import uuid4

    items = result.get("yara") or []
    counts = {"yara": 0, "yara_updated": 0}
    if not items:
        return counts

    con = sqlite3.connect(os.path.join(_db_dir(), "XTHREAT.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cols_sql = ", ".join(f"{n} {t}" for n, t in _YARA_COLUMNS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS YARARULE ({cols_sql})")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(YARARULE)").fetchall()}
    for name, typ in _YARA_COLUMNS.items():
        if name not in existing:
            cur.execute(f"ALTER TABLE YARARULE ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_yararule_ref ON YARARULE(YaraReference)")
    src = result.get("source") or "YARA import"

    for it in items:
        name = it.get("name") or it.get("rule") or ""
        ns = it.get("namespace") or ""
        ref = it.get("reference") or it.get("id") or (f"yara:{ns}:{name}" if name else None)
        if not ref:
            continue
        source_text = it.get("source") or it.get("body") or ""
        attack = it.get("attack_tags")
        if not attack and source_text:
            attack = ", ".join(sorted({m.upper() for m in _YARA_ATTACK_RE.findall(source_text)}))
        common = (name, it.get("description"), source_text, ns,
                  it.get("tags"), it.get("meta"), (it.get("author") or src),
                  ref, attack, it.get("string_count"), (it.get("status") or "active"))
        row = cur.execute("SELECT YaraRuleID FROM YARARULE WHERE YaraReference=?", (ref,)).fetchone()
        if row:
            cur.execute(
                """UPDATE YARARULE SET YaraRuleName=?, YaraRuleDescription=?, YaraSource=?,
                     Namespace=?, Tags=?, Meta=?, Author=?, YaraReference=?, AttackTags=?,
                     StringCount=?, Status=? WHERE YaraRuleID=?""",
                (*common, row[0]),
            )
            counts["yara_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO YARARULE (YaraRuleName, YaraRuleDescription, YaraSource, Namespace,
                     Tags, Meta, Author, YaraReference, AttackTags, StringCount, Status,
                     YaraRuleGUID, CreatedDate)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*common, it.get("guid") or str(uuid4()), _now()),
            )
            counts["yara"] += 1
    con.commit()
    con.close()
    return counts


# IDENTITY schema (subset kept in sync with XORCISM_sqlite.sql / ensureIdentityTables()).
_IDENTITY_COLUMNS = {
    "IdentityID": "INTEGER PRIMARY KEY", "IdentityGUID": "TEXT", "IdentityName": "TEXT",
    "IdentityType": "TEXT", "IdentityClass": "TEXT", "Description": "TEXT", "Status": "TEXT",
    "OwnerPersonID": "INTEGER", "AssetID": "INTEGER", "Provider": "TEXT", "ExternalID": "TEXT",
    "PrivilegeLevel": "TEXT", "Environment": "TEXT", "CredentialType": "TEXT", "MFAEnabled": "TEXT",
    "LastRotatedDate": "DATE", "ExpiryDate": "DATE", "LastUsedDate": "DATE", "RiskLevel": "TEXT",
    "CreatedDate": "DATE", "ModifiedDate": "DATE", "TenantID": "INTEGER",
}


def import_identities(result: Dict[str, Any]) -> Dict[str, int]:
    """Import normalized identities into XORCISM.IDENTITY (the IAM inventory: human users +
    non-human / NHI service principals, managed identities, …). Used by the Microsoft Entra
    ID connector. Idempotent by (Provider, ExternalID) — existing identities are updated, new
    ones inserted. Device identities can carry an AssetID (link to the ASSET created by the
    findings path). Stamps XORCISM_IMPORT_TENANT_ID so tenant-scoped users see the rows.
    Each identity item (dict):
        {"name", "type" (human/non-human), "class" (user/servicePrincipal/managedIdentity/
         device/…), "description", "status", "provider", "external_id" (unique per provider),
         "privilege", "environment", "credential_type", "mfa", "last_used", "risk", "asset"}
    Self-creates/ALTERs the table so it runs against any DB version."""
    from uuid import uuid4

    items = result.get("identities") or []
    counts = {"identities": 0, "identities_updated": 0}
    if not items:
        return counts

    tid = _import_tenant_id()
    con = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cols_sql = ", ".join(f"{n} {t}" for n, t in _IDENTITY_COLUMNS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS IDENTITY ({cols_sql})")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(IDENTITY)").fetchall()}
    for name, typ in _IDENTITY_COLUMNS.items():
        if name not in existing:
            cur.execute(f"ALTER TABLE IDENTITY ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_identity_extid ON IDENTITY(Provider, ExternalID)")
    provider = result.get("source") or "Microsoft Entra ID"

    # Resolve a device identity's asset name → AssetID (assets were created by import_findings).
    def _asset_id(name: Optional[str]) -> Optional[int]:
        if not name:
            return None
        r = cur.execute("SELECT AssetID FROM ASSET WHERE AssetName=? LIMIT 1", (name,)).fetchone()
        return r[0] if r else None

    for it in items:
        ext = it.get("external_id") or it.get("id")
        prov = it.get("provider") or provider
        if not ext:
            continue
        aid = _asset_id(it.get("asset"))
        common = (it.get("name") or ext, it.get("type"), it.get("class"), it.get("description"),
                  it.get("status"), prov, str(ext), it.get("privilege"), it.get("environment"),
                  it.get("credential_type"), it.get("mfa"), it.get("last_used"), it.get("risk"), aid)
        row = cur.execute(
            "SELECT IdentityID FROM IDENTITY WHERE Provider=? AND ExternalID=?", (prov, str(ext))
        ).fetchone()
        if row:
            cur.execute(
                """UPDATE IDENTITY SET IdentityName=?, IdentityType=?, IdentityClass=?, Description=?,
                     Status=?, Provider=?, ExternalID=?, PrivilegeLevel=?, Environment=?,
                     CredentialType=?, MFAEnabled=?, LastUsedDate=?, RiskLevel=?, AssetID=?,
                     ModifiedDate=? WHERE IdentityID=?""",
                (*common, _now(), row[0]),
            )
            counts["identities_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO IDENTITY (IdentityName, IdentityType, IdentityClass, Description,
                     Status, Provider, ExternalID, PrivilegeLevel, Environment, CredentialType,
                     MFAEnabled, LastUsedDate, RiskLevel, AssetID, IdentityGUID, CreatedDate, TenantID)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*common, str(uuid4()), _now(), tid),
            )
            counts["identities"] += 1
    con.commit()
    con.close()
    return counts


# IDENTITYSIGNIN schema (kept in sync with ensureZtSigninTable() in db.ts).
_SIGNIN_COLUMNS = {
    "SigninID": "INTEGER PRIMARY KEY", "SigninGUID": "TEXT", "IdentityName": "TEXT", "IdentityID": "INTEGER",
    "Timestamp": "TEXT", "SourceIP": "TEXT", "Country": "TEXT", "City": "TEXT", "Device": "TEXT", "ClientApp": "TEXT",
    "MFAUsed": "TEXT", "Result": "TEXT", "FailureReason": "TEXT", "RiskLevel": "TEXT",
    "Source": "TEXT", "ExternalID": "TEXT", "TenantID": "INTEGER", "CreatedDate": "TEXT",
}


def import_signins(result: Dict[str, Any]) -> Dict[str, int]:
    """Import normalized sign-in / access events into XORCISM.IDENTITYSIGNIN — the continuous-
    verification telemetry that matures the Zero Trust Identity pillar (zerotrust.ts sessionRisk()).
    Used by the inbound IdP/ZTNA connectors (entra-signin, okta-signin, …). Idempotent by
    (Source, ExternalID); resolves IdentityID by IdentityName. Each item (dict):
        {"user"/"identity", "timestamp", "ip", "country", "city", "device", "client_app",
         "mfa" (yes/no), "result" (success/failure), "failure_reason", "risk", "id" (unique)}"""
    from uuid import uuid4

    items = result.get("signins") or []
    counts = {"signins": 0, "signins_updated": 0}
    if not items:
        return counts
    tid = _import_tenant_id()
    con = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cols_sql = ", ".join(f"{n} {t}" for n, t in _SIGNIN_COLUMNS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS IDENTITYSIGNIN ({cols_sql})")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(IDENTITYSIGNIN)").fetchall()}
    for name, typ in _SIGNIN_COLUMNS.items():
        if name not in existing:
            cur.execute(f"ALTER TABLE IDENTITYSIGNIN ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_signin_extid ON IDENTITYSIGNIN(Source, ExternalID)")
    src = result.get("source") or "IdP sign-in import"

    def _identity_id(name):
        if not name:
            return None
        r = cur.execute("SELECT IdentityID FROM IDENTITY WHERE IdentityName=? LIMIT 1", (name,)).fetchone()
        return r[0] if r else None

    for it in items:
        ext = it.get("id") or it.get("external_id")
        user = it.get("user") or it.get("identity") or it.get("userPrincipalName")
        if not ext or not user:
            continue
        common = (user, _identity_id(user), it.get("timestamp"), it.get("ip"), it.get("country"), it.get("city"),
                  it.get("device"), it.get("client_app"), it.get("mfa"), it.get("result"), it.get("failure_reason"),
                  it.get("risk"), src, str(ext))
        row = cur.execute("SELECT SigninID FROM IDENTITYSIGNIN WHERE Source=? AND ExternalID=?", (src, str(ext))).fetchone()
        if row:
            cur.execute(
                """UPDATE IDENTITYSIGNIN SET IdentityName=?, IdentityID=?, Timestamp=?, SourceIP=?, Country=?, City=?,
                     Device=?, ClientApp=?, MFAUsed=?, Result=?, FailureReason=?, RiskLevel=?, Source=?, ExternalID=?
                   WHERE SigninID=?""", (*common, row[0]))
            counts["signins_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO IDENTITYSIGNIN (IdentityName, IdentityID, Timestamp, SourceIP, Country, City, Device,
                     ClientApp, MFAUsed, Result, FailureReason, RiskLevel, Source, ExternalID, SigninGUID, CreatedDate, TenantID)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*common, str(uuid4()), _now(), tid))
            counts["signins"] += 1
    con.commit()
    con.close()
    return counts


# ZTPOLICY schema (kept in sync with ensureZtPolicyTable() in db.ts), in XCOMPLIANCE.
_ZTPOLICY_COLUMNS = {
    "PolicyID": "INTEGER PRIMARY KEY", "PolicyGUID": "TEXT", "Name": "TEXT", "Source": "TEXT", "ExternalID": "TEXT",
    "State": "TEXT", "Subjects": "TEXT", "Resources": "TEXT", "Conditions": "TEXT", "GrantControls": "TEXT",
    "RequireMfa": "INTEGER", "RequireCompliantDevice": "INTEGER", "Block": "INTEGER",
    "TenantID": "INTEGER", "CreatedDate": "TEXT",
}


def import_zt_policies(result: Dict[str, Any]) -> Dict[str, int]:
    """Import normalized Zero Trust access policies into XCOMPLIANCE.ZTPOLICY (the policy register
    behind the /zero-trust Automation/Governance pillars). Used by the inbound conditional-access /
    ZTNA-policy connectors. Idempotent by (Source, ExternalID). Each item (dict):
        {"name", "state", "subjects", "resources", "conditions", "grant_controls",
         "require_mfa" (bool), "require_compliant_device" (bool), "block" (bool), "id"}"""
    from uuid import uuid4

    items = result.get("zt_policies") or []
    counts = {"zt_policies": 0, "zt_policies_updated": 0}
    if not items:
        return counts
    tid = _import_tenant_id()
    con = sqlite3.connect(os.path.join(_db_dir(), "XCOMPLIANCE.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cols_sql = ", ".join(f"{n} {t}" for n, t in _ZTPOLICY_COLUMNS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS ZTPOLICY ({cols_sql})")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(ZTPOLICY)").fetchall()}
    for name, typ in _ZTPOLICY_COLUMNS.items():
        if name not in existing:
            cur.execute(f"ALTER TABLE ZTPOLICY ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_ztpolicy_extid ON ZTPOLICY(Source, ExternalID)")
    src = result.get("source") or "Conditional Access import"
    b = lambda v: 1 if v else 0  # noqa: E731
    for it in items:
        ext = it.get("id") or it.get("external_id")
        if not ext:
            continue
        common = (it.get("name") or str(ext), src, str(ext), it.get("state"), it.get("subjects"), it.get("resources"),
                  it.get("conditions"), it.get("grant_controls"), b(it.get("require_mfa")),
                  b(it.get("require_compliant_device")), b(it.get("block")))
        row = cur.execute("SELECT PolicyID FROM ZTPOLICY WHERE Source=? AND ExternalID=?", (src, str(ext))).fetchone()
        if row:
            cur.execute(
                """UPDATE ZTPOLICY SET Name=?, Source=?, ExternalID=?, State=?, Subjects=?, Resources=?, Conditions=?,
                     GrantControls=?, RequireMfa=?, RequireCompliantDevice=?, Block=? WHERE PolicyID=?""", (*common, row[0]))
            counts["zt_policies_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO ZTPOLICY (Name, Source, ExternalID, State, Subjects, Resources, Conditions, GrantControls,
                     RequireMfa, RequireCompliantDevice, Block, PolicyGUID, CreatedDate, TenantID)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*common, str(uuid4()), _now(), tid))
            counts["zt_policies"] += 1
    con.commit()
    con.close()
    return counts


# MONITORINGCHECK / MONITORINGINCIDENT schema (kept in sync with ensureMonitoringTables() in db.ts).
_MONCHECK_COLS = {
    "CheckID": "INTEGER PRIMARY KEY", "CheckGUID": "TEXT", "AssetID": "INTEGER", "Name": "TEXT",
    "CheckType": "TEXT", "Target": "TEXT", "IntervalSeconds": "INTEGER", "Enabled": "INTEGER",
    "Status": "TEXT", "UptimePercent": "REAL", "ResponseTimeMs": "INTEGER", "LastCheckedAt": "TEXT",
    "SSLExpiryDate": "DATE", "SSLIssuer": "TEXT", "OwnerPersonID": "INTEGER", "Source": "TEXT",
    "ExternalID": "TEXT", "CreatedDate": "TEXT", "TenantID": "INTEGER",
}
_MONINC_COLS = {
    "IncidentID": "INTEGER PRIMARY KEY", "IncidentGUID": "TEXT", "CheckID": "INTEGER", "AssetID": "INTEGER",
    "Title": "TEXT", "Status": "TEXT", "Severity": "TEXT", "StartedAt": "TEXT", "ResolvedAt": "TEXT",
    "DurationMinutes": "INTEGER", "Description": "TEXT", "Source": "TEXT", "ExternalID": "TEXT",
    "CreatedDate": "TEXT", "TenantID": "INTEGER",
}


def import_monitoring(result: Dict[str, Any]) -> Dict[str, int]:
    """Import Asset Monitoring data into XORCISM.MONITORINGCHECK / MONITORINGINCIDENT (the CheckCle
    connector and any uptime source). Idempotent by (Source, ExternalID) — existing monitors/incidents
    are updated, new ones inserted. AssetID is resolved from ASSET by name (assets are created by the
    findings path in the same run). Self-creates/ALTERs the tables so it runs against any DB version.
        monitors:  [{name, type, target, asset, status, uptime, response_time, ssl_expiry, ssl_issuer,
                     interval, external_id, source}]
        monitoring_incidents: [{title, monitor (external id/name), asset, status, severity, started_at,
                     resolved_at, duration, external_id, source}]"""
    from uuid import uuid4

    monitors = result.get("monitors") or []
    incidents = result.get("monitoring_incidents") or []
    counts = {"monitors": 0, "monitors_updated": 0, "monitoring_incidents": 0, "monitoring_incidents_updated": 0}
    if not monitors and not incidents:
        return counts
    tid = _import_tenant_id()
    src = result.get("source") or "monitoring"
    con = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    for table, schema in (("MONITORINGCHECK", _MONCHECK_COLS), ("MONITORINGINCIDENT", _MONINC_COLS)):
        cur.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(f'{n} {t}' for n, t in schema.items())})")
        have = {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}
        for name, typ in schema.items():
            if name not in have:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")

    def asset_id(name):
        if not name:
            return None
        r = cur.execute("SELECT AssetID FROM ASSET WHERE AssetName=? LIMIT 1", (str(name),)).fetchone()
        return r[0] if r else None

    ext2check = {}
    for m in monitors:
        provider = m.get("source") or src
        ext = m.get("external_id") or m.get("id") or m.get("name")
        if not ext:
            continue
        aid = asset_id(m.get("asset"))
        vals = (aid, m.get("name") or str(ext), (m.get("type") or "http"), m.get("target"),
                m.get("interval"), 1 if m.get("enabled", True) else 0, m.get("status"),
                m.get("uptime"), m.get("response_time"), m.get("last_checked"),
                m.get("ssl_expiry"), m.get("ssl_issuer"), provider, str(ext))
        row = cur.execute("SELECT CheckID FROM MONITORINGCHECK WHERE Source=? AND ExternalID=?", (provider, str(ext))).fetchone()
        if row:
            cur.execute("""UPDATE MONITORINGCHECK SET AssetID=?, Name=?, CheckType=?, Target=?, IntervalSeconds=?,
                             Enabled=?, Status=?, UptimePercent=?, ResponseTimeMs=?, LastCheckedAt=?,
                             SSLExpiryDate=?, SSLIssuer=?, Source=?, ExternalID=? WHERE CheckID=?""", (*vals, row[0]))
            ext2check[str(ext)] = row[0]; counts["monitors_updated"] += 1
        else:
            nid = cur.execute("SELECT COALESCE(MAX(CheckID),0)+1 FROM MONITORINGCHECK").fetchone()[0]
            cur.execute("""INSERT INTO MONITORINGCHECK (CheckID, CheckGUID, AssetID, Name, CheckType, Target, IntervalSeconds,
                             Enabled, Status, UptimePercent, ResponseTimeMs, LastCheckedAt, SSLExpiryDate, SSLIssuer,
                             Source, ExternalID, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (nid, str(uuid4()), *vals, _now(), tid))
            ext2check[str(ext)] = nid; counts["monitors"] += 1

    for it in incidents:
        provider = it.get("source") or src
        ext = it.get("external_id") or it.get("id")
        if not ext:
            continue
        cid = ext2check.get(str(it.get("monitor") or "")) or None
        aid = asset_id(it.get("asset"))
        vals = (cid, aid, it.get("title") or "Incident", it.get("status"), it.get("severity"),
                it.get("started_at"), it.get("resolved_at"), it.get("duration"), it.get("description"), provider, str(ext))
        row = cur.execute("SELECT IncidentID FROM MONITORINGINCIDENT WHERE Source=? AND ExternalID=?", (provider, str(ext))).fetchone()
        if row:
            cur.execute("""UPDATE MONITORINGINCIDENT SET CheckID=?, AssetID=?, Title=?, Status=?, Severity=?,
                             StartedAt=?, ResolvedAt=?, DurationMinutes=?, Description=?, Source=?, ExternalID=? WHERE IncidentID=?""", (*vals, row[0]))
            counts["monitoring_incidents_updated"] += 1
        else:
            nid = cur.execute("SELECT COALESCE(MAX(IncidentID),0)+1 FROM MONITORINGINCIDENT").fetchone()[0]
            cur.execute("""INSERT INTO MONITORINGINCIDENT (IncidentID, IncidentGUID, CheckID, AssetID, Title, Status, Severity,
                             StartedAt, ResolvedAt, DurationMinutes, Description, Source, ExternalID, CreatedDate, TenantID)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (nid, str(uuid4()), *vals, _now(), tid))
            counts["monitoring_incidents"] += 1
    con.commit()
    con.close()
    return counts


# DOCUMENT schema (subset kept in sync with XCOMPLIANCE / ensureGrcColumns()).
_DOCUMENT_COLS = {
    "DocumentID": "INTEGER PRIMARY KEY", "DocumentGUID": "TEXT", "DocumentName": "TEXT",
    "DocumentDescription": "TEXT", "DocumentDate": "TEXT", "Author": "TEXT", "DocumentURL": "TEXT",
    "Version": "TEXT", "Status": "TEXT", "Category": "TEXT", "DocumentType": "TEXT",
    "Classification": "TEXT", "Framework": "TEXT", "Language": "TEXT", "ExternalID": "TEXT",
    "Source": "TEXT", "TenantID": "INTEGER",
}


def import_documents(result: Dict[str, Any]) -> Dict[str, int]:
    """Import evidence + policy documents into XCOMPLIANCE.DOCUMENT (the controlled-document register).
    Used by the GRC connectors (Vanta, Drata, ServiceNow GRC, OneTrust, AuditBoard). Idempotent by
    (Source, ExternalID) — existing documents are updated, new ones inserted. Each document item (dict):
        {"name", "description", "type" (policy/evidence/report/…), "framework", "url", "external_id"
         (unique per source), "author", "date", "status", "category", "classification", "version",
         "language"}
    Self-creates/ALTERs the table so it runs against any DB version."""
    from uuid import uuid4

    docs = result.get("documents") or []
    counts = {"documents": 0, "documents_updated": 0}
    if not docs:
        return counts
    tid = _import_tenant_id()
    src = result.get("source") or "GRC"
    con = sqlite3.connect(os.path.join(_db_dir(), "XCOMPLIANCE.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cur.execute(f"CREATE TABLE IF NOT EXISTS DOCUMENT ({', '.join(f'{n} {t}' for n, t in _DOCUMENT_COLS.items())})")
    have = {r[1] for r in cur.execute("PRAGMA table_info(DOCUMENT)").fetchall()}
    for name, typ in _DOCUMENT_COLS.items():
        if name not in have:
            cur.execute(f"ALTER TABLE DOCUMENT ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_document_extid ON DOCUMENT(Source, ExternalID)")

    for d in docs:
        provider = d.get("source") or src
        ext = d.get("external_id") or d.get("id") or d.get("url") or d.get("name")
        if not ext:
            continue
        vals = (d.get("name") or str(ext), d.get("description"), d.get("date"), d.get("author"),
                d.get("url"), d.get("version"), (d.get("status") or "Active"), d.get("category"),
                (d.get("type") or "Evidence"), d.get("classification"), d.get("framework"),
                (d.get("language") or "en"), provider, str(ext))
        row = cur.execute("SELECT DocumentID FROM DOCUMENT WHERE Source=? AND ExternalID=?", (provider, str(ext))).fetchone()
        if row:
            cur.execute(
                """UPDATE DOCUMENT SET DocumentName=?, DocumentDescription=?, DocumentDate=?, Author=?,
                     DocumentURL=?, Version=?, Status=?, Category=?, DocumentType=?, Classification=?,
                     Framework=?, Language=?, Source=?, ExternalID=? WHERE DocumentID=?""",
                (*vals, row[0]),
            )
            counts["documents_updated"] += 1
        else:
            nid = cur.execute("SELECT COALESCE(MAX(DocumentID),0)+1 FROM DOCUMENT").fetchone()[0]
            cur.execute(
                """INSERT INTO DOCUMENT (DocumentID, DocumentGUID, DocumentName, DocumentDescription,
                     DocumentDate, Author, DocumentURL, Version, Status, Category, DocumentType,
                     Classification, Framework, Language, Source, ExternalID, TenantID)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (nid, str(uuid4()), *vals, tid),
            )
            counts["documents"] += 1
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


# Columns added to VULNERABILITY for ENISA EUVD cross-referencing (idempotent ALTER).
_EUVD_COLUMNS = {"EUVDId": "TEXT", "EUVDUrl": "TEXT"}


def import_euvd(result: Dict[str, Any]) -> Dict[str, int]:
    """Import ENISA EU Vulnerability Database (EUVD) entries into XVULNERABILITY.VULNERABILITY.

    Each EUVD entry has its own id (EUVD-YYYY-NNNNN) and usually aliases one or more CVE ids.
    We key on VULReferentialID (the CVE alias when present, else the EUVD id):
      - an existing row (e.g. an imported NVD CVE) is enriched in place — EUVDId / EUVDUrl are
        set, and CVSS / EPSS / description / published-date are filled only when missing (NVD
        stays authoritative for what it already provides);
      - an EUVD-only entry (or a CVE not yet present) is inserted as a new VULNERABILITY.
    Idempotent. VULNERABILITY has no SQLite PK, so VulnerabilityID is allocated as MAX+1 (the
    import convention). The EUVD columns are self-ALTERed so the importer runs on any DB version."""
    import re as _re

    items = result.get("euvd") or []
    counts = {"euvd": 0, "euvd_updated": 0}
    if not items:
        return counts

    con = sqlite3.connect(os.path.join(_db_dir(), "XVULNERABILITY.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    if not cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='VULNERABILITY'").fetchone():
        con.close()
        return counts
    have = {r[1] for r in cur.execute("PRAGMA table_info(VULNERABILITY)").fetchall()}
    for name, typ in _EUVD_COLUMNS.items():
        if name not in have:
            cur.execute(f"ALTER TABLE VULNERABILITY ADD COLUMN {name} {typ}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_vuln_ref ON VULNERABILITY(VULReferentialID)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_vuln_euvd ON VULNERABILITY(EUVDId)")

    next_id = (cur.execute("SELECT COALESCE(MAX(VulnerabilityID),0) FROM VULNERABILITY").fetchone()[0] or 0) + 1
    now = _now()
    cve_re = _re.compile(r"CVE-\d{4}-\d{3,7}", _re.I)

    for it in items:
        euvd_id = str(it.get("euvd_id") or it.get("id") or "").strip()
        cve = str(it.get("cve") or "").strip()
        if not cve:
            m = cve_re.search(" ".join(str(it.get(k) or "") for k in ("aliases", "ref", "name")))
            cve = m.group(0).upper() if m else ""
        ref = cve or euvd_id
        if not ref:
            continue
        url = str(it.get("url") or "").strip() or (f"https://euvd.enisa.europa.eu/vulnerability/{euvd_id}" if euvd_id else "")
        desc = str(it.get("name") or it.get("description") or "").strip()
        cvss = it.get("cvss")
        epss = it.get("epss")
        published = it.get("published")
        exploited = 1 if it.get("exploited") else 0

        row = cur.execute(
            "SELECT VulnerabilityID FROM VULNERABILITY WHERE VULReferentialID=? OR (EUVDId IS NOT NULL AND EUVDId=?) LIMIT 1",
            (ref, euvd_id or "\x00"),
        ).fetchone()
        if row:
            cur.execute(
                """UPDATE VULNERABILITY SET
                     EUVDId=COALESCE(NULLIF(?, ''), EUVDId),
                     EUVDUrl=COALESCE(NULLIF(?, ''), EUVDUrl),
                     CVSSBaseScore=CASE WHEN (CVSSBaseScore IS NULL OR CVSSBaseScore='') AND ? IS NOT NULL THEN ? ELSE CVSSBaseScore END,
                     EPSS=CASE WHEN (EPSS IS NULL OR EPSS='') AND ? IS NOT NULL THEN ? ELSE EPSS END,
                     VULDescription=CASE WHEN (VULDescription IS NULL OR VULDescription='') AND ?<>'' THEN ? ELSE VULDescription END,
                     VULPublishedDate=COALESCE(NULLIF(VULPublishedDate, ''), ?),
                     Exploited=CASE WHEN ?=1 THEN 1 ELSE Exploited END
                   WHERE VulnerabilityID=?""",
                (euvd_id, url, cvss, cvss, epss, epss, desc, desc, published, exploited, row[0]),
            )
            counts["euvd_updated"] += 1
        else:
            cols = ["VulnerabilityID", "VULGUID", "VULReferential", "VULReferentialID", "VULName", "VULShortName",
                    "VULDescription", "CVSSBaseScore", "EPSS", "VULPublishedDate", "EUVDId", "EUVDUrl", "CreatedDate"]
            vals = [next_id, ref, ref, ref, ref, ref, desc, cvss, epss, published, euvd_id, url, now]
            if "Exploited" in have or exploited:
                cols.append("Exploited"); vals.append(exploited)
            cur.execute(f"INSERT INTO VULNERABILITY ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", vals)
            next_id += 1
            counts["euvd"] += 1

    con.commit()
    con.close()
    return counts


def import_netflow(result: Dict[str, Any]) -> Dict[str, int]:
    """Import network-flow observability (Obserae) into XORCISM around ASSET.

    result["netflow"] = {assets:[{name,ip,hostname,os,zone}], services:[{asset,protocol,port,service,...}],
                         sessions:[{src,dst,protocol,src_port,dst_port,service,bytes,packets,flows,...}]}
      - hosts          -> ASSET (created if missing — discovery)
      - services       -> ASSETSERVICE (asset<->service: protocol/port, flow counts accumulated)
      - sessions/flows -> NETWORKSESSION (src<->dst asset/ip/port, bytes/packets, first/last seen)
    Raw sqlite3 on XORCISM.db (tables self-created, kept in sync with ensureNetflowTables in db.ts).
    Idempotent: ASSETSERVICE unique per asset+proto+port; NETWORKSESSION deduped by endpoints+firstseen.
    """
    import uuid as uuid_mod
    nf = result.get("netflow") or {}
    src_name = result.get("source") or "Obserae"
    counts = {"assets": 0, "services": 0, "sessions": 0}
    con = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cur.executescript(
        """CREATE TABLE IF NOT EXISTS ASSETSERVICE (
             AssetServiceID INTEGER PRIMARY KEY, AssetID INTEGER, Protocol TEXT, Port INTEGER, ServiceName TEXT,
             Banner TEXT, FlowCount INTEGER DEFAULT 0, FirstSeen TEXT, LastSeen TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
           CREATE TABLE IF NOT EXISTS NETWORKSESSION (
             NetworkSessionID INTEGER PRIMARY KEY, SessionGUID TEXT, SrcAssetID INTEGER, DstAssetID INTEGER,
             SrcIP TEXT, DstIP TEXT, Protocol TEXT, SrcPort INTEGER, DstPort INTEGER, ServiceName TEXT,
             Bytes INTEGER, Packets INTEGER, Flows INTEGER, Direction TEXT, State TEXT,
             FirstSeen TEXT, LastSeen TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
           CREATE UNIQUE INDEX IF NOT EXISTS ux_assetservice ON ASSETSERVICE(AssetID, Protocol, Port);""")

    cache: Dict[str, int] = {}

    def ensure_asset(name, hostname=None, os_name=None) -> "Optional[int]":
        key = str(name or "").strip()
        if not key:
            return None
        if key in cache:
            return cache[key]
        row = cur.execute("SELECT AssetID FROM ASSET WHERE AssetName = ? LIMIT 1", (key,)).fetchone()
        if row:
            cache[key] = row[0]
            return row[0]
        cur.execute("INSERT INTO ASSET (AssetName, hostname, OSName, CreatedDate) VALUES (?,?,?,?)",
                    (key[:200], (hostname or None), (os_name or None), _now()))
        aid = cur.lastrowid
        cache[key] = aid
        counts["assets"] += 1
        return aid

    for a in nf.get("assets", []):
        aid = ensure_asset(a.get("name"), a.get("hostname"), a.get("os"))
        for alias in (a.get("ip"), a.get("hostname")):
            if alias and aid:
                cache[str(alias)] = aid

    for s in nf.get("services", []):
        aid = ensure_asset(s.get("asset"))
        port, proto = s.get("port"), str(s.get("protocol") or "tcp").lower()
        if not aid or port is None:
            continue
        row = cur.execute("SELECT AssetServiceID, FlowCount FROM ASSETSERVICE WHERE AssetID=? AND Protocol=? AND Port=?", (aid, proto, port)).fetchone()
        flows = int(s.get("flows") or 0)
        if row:
            cur.execute("UPDATE ASSETSERVICE SET FlowCount=?, LastSeen=COALESCE(?,LastSeen), ServiceName=COALESCE(?,ServiceName), Banner=COALESCE(?,Banner) WHERE AssetServiceID=?",
                        ((row[1] or 0) + flows, s.get("last_seen"), s.get("service"), s.get("banner"), row[0]))
        else:
            cur.execute("INSERT INTO ASSETSERVICE (AssetID, Protocol, Port, ServiceName, Banner, FlowCount, FirstSeen, LastSeen, Source, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (aid, proto, port, s.get("service"), s.get("banner"), flows, s.get("first_seen"), s.get("last_seen"), src_name, _now()))
            counts["services"] += 1

    seen = cur.execute("SELECT SrcIP, DstIP, Protocol, DstPort, FirstSeen FROM NETWORKSESSION").fetchall()
    seen_set = {tuple(str(x) for x in r) for r in seen}
    for f in nf.get("sessions", []):
        src, dst = str(f.get("src") or ""), str(f.get("dst") or "")
        if not src or not dst:
            continue
        sk = (src, dst, str(f.get("protocol") or "tcp").lower(), str(f.get("dst_port") or ""), str(f.get("first_seen") or ""))
        if sk in seen_set:
            continue
        seen_set.add(sk)
        saiid, daiid = ensure_asset(src), ensure_asset(dst)
        cur.execute(
            """INSERT INTO NETWORKSESSION (SessionGUID, SrcAssetID, DstAssetID, SrcIP, DstIP, Protocol, SrcPort, DstPort,
                 ServiceName, Bytes, Packets, Flows, Direction, State, FirstSeen, LastSeen, Source, CreatedDate)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (str(uuid_mod.uuid4()), saiid, daiid, src, dst, str(f.get("protocol") or "tcp").lower(), f.get("src_port"), f.get("dst_port"),
             f.get("service"), f.get("bytes"), f.get("packets"), f.get("flows") or 1, f.get("direction"), f.get("state"),
             f.get("first_seen"), f.get("last_seen"), src_name, _now()))
        counts["sessions"] += 1

    con.commit()
    con.close()
    return counts


# XINCIDENT.ALERT schema (kept in sync with ensureIncidentTables() in db.ts). Connector-imported
# SOC alerts/tickets/cases land here (the Defender-XDR-aligned alert layer that feeds incidents).
_ALERT_COLS = {
    "AlertID": "INTEGER PRIMARY KEY", "AlertGUID": "TEXT", "AlertName": "TEXT", "AlertDescription": "TEXT",
    "Severity": "TEXT", "Status": "TEXT", "Category": "TEXT", "AttackTechniques": "TEXT",
    "RecommendedActions": "TEXT", "ServiceSource": "TEXT", "DetectionSource": "TEXT",
    "Classification": "TEXT", "Determination": "TEXT", "AssignedTo": "TEXT", "Tags": "TEXT",
    "ExternalID": "TEXT", "ExternalUrl": "TEXT", "PersonID": "INTEGER", "CreatedDate": "DATE",
    "IncidentID": "INTEGER", "TenantID": "INTEGER",
}


def import_incidents(result: Dict[str, Any]) -> Dict[str, int]:
    """Import normalized SOC alerts/tickets/cases into XINCIDENT.ALERT (the Defender-XDR-aligned
    alert layer that feeds incidents). Used by the SOC-tool connectors — TheHive, ServiceNow,
    PagerDuty, Opsgenie, Zammad, … — which return an "alerts" list. Idempotent by
    (DetectionSource, ExternalID): an existing alert is updated, a new one inserted. Impacted
    assets (item "asset"/"assets") are resolved by name to ALERTFORASSET links (assets created by
    import_findings). Stamps XORCISM_IMPORT_TENANT_ID so tenant-scoped users see the rows.

    Each alert item (dict):
        {"name"|"title", "description", "severity" (crit/high/medium/low/info), "status",
         "category" (Ticket/Case/Incident/Alert/Offense…), "external_id" (unique per source),
         "url", "attack" (ATT&CK ids csv/list), "assignee", "tags" (csv/list), "actions",
         "classification", "determination", "asset"|"assets" (name or [names]), "created"}
    result-level "source" sets DetectionSource (default "Connector"). Self-creates/ALTERs the
    table so it runs against any DB version. Worker-safe (no db.ts import)."""
    from uuid import uuid4

    items = result.get("alerts") or result.get("incidents") or []
    counts = {"alerts": 0, "alerts_updated": 0, "alert_assets": 0}
    if not items:
        return counts

    def _csv(v: Any) -> Optional[str]:
        if v is None:
            return None
        if isinstance(v, (list, tuple, set)):
            return ", ".join(str(x).strip() for x in v if str(x).strip()) or None
        return str(v).strip() or None

    tid = _import_tenant_id()
    source = str(result.get("source") or "Connector").strip() or "Connector"
    con = sqlite3.connect(os.path.join(_db_dir(), "XINCIDENT.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cols_sql = ", ".join(f"{n} {t}" for n, t in _ALERT_COLS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS ALERT ({cols_sql})")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(ALERT)").fetchall()}
    for name, typ in _ALERT_COLS.items():
        if name not in existing:
            cur.execute(f"ALTER TABLE ALERT ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_alert_extid ON ALERT(DetectionSource, ExternalID)")
    # ALERTFORASSET (impacted-asset links) — best-effort, only if the table & assets exist.
    cur.execute(
        """CREATE TABLE IF NOT EXISTS ALERTFORASSET (
             AssetAlertID INTEGER PRIMARY KEY, AlertID INTEGER, AssetID INTEGER,
             Relationship TEXT, CreatedDate TEXT, TenantID INTEGER, UNIQUE(AlertID, AssetID))"""
    )
    have_asset_db = os.path.isfile(os.path.join(_db_dir(), "XORCISM.db"))
    acon = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=15) if have_asset_db else None

    def _asset_id(name: Optional[str]) -> Optional[int]:
        if not name or not acon:
            return None
        try:
            r = acon.execute("SELECT AssetID FROM ASSET WHERE AssetName=? LIMIT 1", (str(name),)).fetchone()
            return r[0] if r else None
        except sqlite3.Error:
            return None

    for it in items:
        ext = it.get("external_id") or it.get("id")
        if not ext:
            continue
        ext = str(ext)
        name = str(it.get("name") or it.get("title") or ext)[:300]
        common = (
            name, str(it.get("description") or "")[:4000] or None, _norm_sev(it.get("severity")),
            it.get("status"), it.get("category") or "Alert", _csv(it.get("attack") or it.get("techniques")),
            _csv(it.get("actions") or it.get("recommended_actions")), source, source,
            it.get("classification"), it.get("determination"), it.get("assignee") or it.get("assigned_to"),
            _csv(it.get("tags")), ext, it.get("url") or it.get("external_url"),
        )
        row = cur.execute(
            "SELECT AlertID FROM ALERT WHERE DetectionSource=? AND ExternalID=?", (source, ext)
        ).fetchone()
        if row:
            aid = row[0]
            cur.execute(
                """UPDATE ALERT SET AlertName=?, AlertDescription=?, Severity=?, Status=?, Category=?,
                     AttackTechniques=?, RecommendedActions=?, ServiceSource=?, DetectionSource=?,
                     Classification=?, Determination=?, AssignedTo=?, Tags=?, ExternalID=?, ExternalUrl=?
                   WHERE AlertID=?""",
                (*common, aid),
            )
            counts["alerts_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO ALERT (AlertName, AlertDescription, Severity, Status, Category,
                     AttackTechniques, RecommendedActions, ServiceSource, DetectionSource,
                     Classification, Determination, AssignedTo, Tags, ExternalID, ExternalUrl,
                     AlertGUID, CreatedDate, TenantID)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*common, str(uuid4()), it.get("created") or _now(), tid),
            )
            aid = cur.lastrowid
            counts["alerts"] += 1
        # Link impacted assets (by name) → ALERTFORASSET.
        names = it.get("assets") if isinstance(it.get("assets"), (list, tuple)) else [it.get("asset")]
        for nm in names or []:
            asid = _asset_id(nm)
            if asid:
                cur.execute(
                    "INSERT OR IGNORE INTO ALERTFORASSET (AlertID, AssetID, Relationship, CreatedDate, TenantID) VALUES (?,?,?,?,?)",
                    (aid, asid, "impacted", _now(), tid),
                )
                if cur.rowcount:
                    counts["alert_assets"] += 1
    con.commit()
    con.close()
    if acon:
        acon.close()
    return counts


# XTHREAT emulation schema (kept in sync with ensureEmulationTables() in db.ts). BAS/AEV atomic-test
# runs (atomic-red-team connector → remote worker) land here and feed the ATT&CK coverage heatmap.
_ATOMIC_COLS = {
    "AtomicTestID": "INTEGER PRIMARY KEY", "AtomicGUID": "TEXT UNIQUE", "Name": "TEXT", "Description": "TEXT",
    "AttackID": "TEXT", "AttackTechniqueID": "INTEGER", "Platform": "TEXT", "Executor": "TEXT",
    "Command": "TEXT", "Cleanup": "TEXT", "Source": "TEXT", "ExternalReferences": "TEXT", "CreatedDate": "DATE",
}
_EMRUN_COLS = {
    "RunID": "INTEGER PRIMARY KEY", "RunGUID": "TEXT", "ScenarioID": "INTEGER", "Name": "TEXT",
    "TargetAssetID": "INTEGER", "Status": "TEXT", "RunDate": "DATE", "Score": "INTEGER", "CreatedDate": "DATE",
}
_EMRES_COLS = {
    "EmulationResultID": "INTEGER PRIMARY KEY", "RunID": "INTEGER", "AtomicTestID": "INTEGER",
    "AttackID": "TEXT", "Outcome": "TEXT", "DetectedBy": "TEXT", "Notes": "TEXT", "CreatedDate": "DATE",
}


def import_emulation(result: Dict[str, Any]) -> Dict[str, int]:
    """Import a BAS/AEV atomic-test run (atomic-red-team connector) into XTHREAT: one EMULATIONRUN +
    one EMULATIONRESULT per atomic. Each `emulation_results` item: {technique, atomic_guid, name,
    executor, outcome, detail, host}. Resolves/creates ATOMICTEST by AtomicGUID (AttackTechniqueID
    from ATTACKTECHNIQUE), the run's TargetAssetID from the host name (XORCISM.ASSET), and a Score =
    % of tests that executed (= a coverage gap unless a control prevented/detected them). Each run is
    a distinct timestamped evaluation (not idempotent — that's correct for BAS). Worker-safe."""
    from uuid import uuid4

    items = result.get("emulation_results") or []
    counts = {"emulation_runs": 0, "emulation_results": 0, "atomic_tests": 0}
    if not items:
        return counts

    con = sqlite3.connect(os.path.join(_db_dir(), "XTHREAT.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    for tbl, cols in (("ATOMICTEST", _ATOMIC_COLS), ("EMULATIONRUN", _EMRUN_COLS), ("EMULATIONRESULT", _EMRES_COLS)):
        cur.execute(f"CREATE TABLE IF NOT EXISTS {tbl} ({', '.join(f'{n} {t}' for n, t in cols.items())})")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_atomic_attack ON ATOMICTEST(AttackID)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_emresult_run ON EMULATIONRESULT(RunID)")

    host = str(result.get("host") or "")
    # resolve the target asset by host name (best-effort, from XORCISM.ASSET)
    target_aid = None
    try:
        acon = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=10)
        r = acon.execute("SELECT AssetID FROM ASSET WHERE AssetName=? LIMIT 1", (host,)).fetchone()
        target_aid = r[0] if r else None
        acon.close()
    except sqlite3.Error:
        pass

    executed = sum(1 for it in items if str(it.get("outcome", "")).lower().startswith("execut"))
    score = round(executed / len(items) * 100) if items else 0
    planned = all("plan" in str(it.get("outcome", "")).lower() or "simulat" in str(it.get("outcome", "")).lower() for it in items)
    run_id = (cur.execute("SELECT COALESCE(MAX(RunID),0)+1 AS n FROM EMULATIONRUN").fetchone()[0])
    cur.execute(
        "INSERT INTO EMULATIONRUN (RunID, RunGUID, Name, TargetAssetID, Status, RunDate, Score, CreatedDate) VALUES (?,?,?,?,?,?,?,?)",
        (run_id, str(uuid4()), str(result.get("scenario") or "Atomic Red Team run")[:200], target_aid,
         "Planned" if planned else "Completed", _now()[:10], score, _now()),
    )
    counts["emulation_runs"] += 1

    def _atomic_id(it: Dict[str, Any]) -> int:
        guid = str(it.get("atomic_guid") or "") or f"{it.get('technique', 'T0000')}-{uuid4()}"
        row = cur.execute("SELECT AtomicTestID FROM ATOMICTEST WHERE AtomicGUID=?", (guid,)).fetchone()
        if row:
            return row[0]
        aid = (cur.execute("SELECT COALESCE(MAX(AtomicTestID),0)+1 AS n FROM ATOMICTEST").fetchone()[0])
        attack = str(it.get("technique") or "")
        tech_id = None
        try:
            tr = cur.execute("SELECT AttackTechniqueID FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1", (attack,)).fetchone()
            tech_id = tr[0] if tr else None
        except sqlite3.Error:
            pass
        cur.execute(
            "INSERT INTO ATOMICTEST (AtomicTestID, AtomicGUID, Name, AttackID, AttackTechniqueID, Executor, Source, CreatedDate) VALUES (?,?,?,?,?,?,?,?)",
            (aid, guid, str(it.get("name") or attack)[:300], attack, tech_id, str(it.get("executor") or ""), "atomic-red-team", _now()),
        )
        counts["atomic_tests"] += 1
        return aid

    for it in items:
        atid = _atomic_id(it)
        rid = (cur.execute("SELECT COALESCE(MAX(EmulationResultID),0)+1 AS n FROM EMULATIONRESULT").fetchone()[0])
        cur.execute(
            "INSERT INTO EMULATIONRESULT (EmulationResultID, RunID, AtomicTestID, AttackID, Outcome, Notes, CreatedDate) VALUES (?,?,?,?,?,?,?)",
            (rid, run_id, atid, str(it.get("technique") or ""), str(it.get("outcome") or "No result")[:60], str(it.get("detail") or "")[:2000], _now()),
        )
        counts["emulation_results"] += 1
    con.commit()
    con.close()
    return counts


# DevSecOps: connectors whose findings are a pipeline security scan of a given class.
_DEVSECOPS_TOOLS = {"semgrep": "SAST", "gitleaks": "Secrets", "trivy": "SCA", "burpwn": "DAST", "drogonsec": "SAST", "graphql-cop": "DAST", "oasis": "SAST"}


def _norm_sev(s: Any) -> str:
    v = str(s or "").strip().lower()
    if v.startswith("crit"):
        return "Critical"
    if v.startswith("high"):
        return "High"
    if v.startswith("low") or v in ("info", "informational", "note", "unknown", ""):
        return "Low"
    return "Medium"


def _devsecops_app_name(result: Dict[str, Any], tool: str) -> str:
    """Derive the application/repo name from a normalized connector result (works on every import
    path — worker, local run, chain step — since they all produce the same result shape)."""
    name = str(result.get("project") or "").strip()
    if not name:
        for a in result.get("assets") or []:
            name = str(a.get("hostname") or a.get("key") or a.get("ip") or "").strip()
            if name:
                break
    if not name:
        name = str(result.get("source") or "").strip()
    return (name or tool)[:200]


def record_devsecops_scan(tool: str, result: Dict[str, Any]) -> Dict[str, int]:
    """Record a DevSecOps pipeline scan (XORCISM.DEVSECOPSSCAN) from a semgrep/gitleaks/trivy/burpwn
    connector result — the scanned target becomes/links a DEVSECOPSAPP, findings tallied by severity."""
    from uuid import uuid4

    scan_type = _DEVSECOPS_TOOLS.get(tool)
    if not scan_type:
        return {}
    # trivy is multi-purpose: an image scan is the Container class, fs/repo is SCA (Trivy's ArtifactType)
    if tool == "trivy":
        at = str(result.get("artifact_type") or "").lower()
        if "image" in at or "container" in at:
            scan_type = "Container"
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in result.get("vulns") or []:
        sev[_norm_sev(v.get("severity"))] += 1
    app_name = _devsecops_app_name(result, tool)
    con = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS DEVSECOPSAPP (
          AppID INTEGER PRIMARY KEY, AppGUID TEXT, Name TEXT, Repo TEXT, Language TEXT, Team TEXT,
          OwnerPersonID INTEGER, Criticality TEXT, PipelineUrl TEXT, DefaultBranch TEXT,
          ApplicationID INTEGER, AssetID INTEGER, Status TEXT, TenantID INTEGER, CreatedDate TEXT);
        CREATE TABLE IF NOT EXISTS DEVSECOPSSCAN (
          ScanID INTEGER PRIMARY KEY, ScanGUID TEXT, AppID INTEGER, ScanType TEXT, Tool TEXT, Status TEXT,
          Critical INTEGER DEFAULT 0, High INTEGER DEFAULT 0, Medium INTEGER DEFAULT 0, Low INTEGER DEFAULT 0,
          Findings INTEGER DEFAULT 0, GatePassed INTEGER, Branch TEXT, Ref TEXT, Url TEXT, RanAt TEXT,
          DurationSec INTEGER, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
        """
    )
    row = cur.execute("SELECT AppID, AssetID FROM DEVSECOPSAPP WHERE Name=?", (app_name,)).fetchone()
    if row:
        app_id = row[0]
    else:
        app_id = (cur.execute("SELECT COALESCE(MAX(AppID),0)+1 FROM DEVSECOPSAPP").fetchone()[0])
        # link to the matching ASSET (created by import_findings) so the SBOM/SCA class can resolve
        aid = cur.execute("SELECT AssetID FROM ASSET WHERE AssetName=? LIMIT 1", (app_name,)).fetchone()
        cur.execute(
            "INSERT INTO DEVSECOPSAPP (AppID, AppGUID, Name, Criticality, AssetID, Status, CreatedDate) "
            "VALUES (?,?,?,?,?,?,?)",
            (app_id, str(uuid4()), app_name, "Medium", aid[0] if aid else None, "Active", _now()),
        )
    findings = sum(sev.values())
    status = "fail" if (sev["Critical"] or sev["High"] or (scan_type == "Secrets" and findings)) else "pass"
    scan_id = (cur.execute("SELECT COALESCE(MAX(ScanID),0)+1 FROM DEVSECOPSSCAN").fetchone()[0])
    cur.execute(
        "INSERT INTO DEVSECOPSSCAN (ScanID, ScanGUID, AppID, ScanType, Tool, Status, Critical, High, Medium, Low, "
        "Findings, Branch, RanAt, Source, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, str(uuid4()), app_id, scan_type, tool, status, sev["Critical"], sev["High"], sev["Medium"],
         sev["Low"], findings, "main", _now(), "connector", _now()),
    )
    con.commit()
    con.close()
    return {"devsecops_scan": 1, "devsecops_findings": findings}


def import_compliance(result: Dict[str, Any]) -> Dict[str, int]:
    """Import a compliance / hardening scan into XORCISM.XCOMPLIANCE (used by the macos-security /
    mSCP connector, and any connector returning a "compliance" block). Records ONE Compliance AUDIT
    per baseline+host and ONE AUDITFINDING per FAILED rule (passing rules counted in the audit
    description, not stored). Idempotent: AUDIT by AuditName(+tenant); AUDITFINDING by
    (AuditID, Source="mscp:<rule_id>"). Stamps XORCISM_IMPORT_TENANT_ID. Raw sqlite3, worker-safe.

    result["compliance"] = {benchmark, baseline, os, host,
        results:[{rule_id, title, result:"pass"|"fail"|"exempt", severity, references(str), discussion}]}"""
    from uuid import uuid4

    c = result.get("compliance") or {}
    rules = c.get("results") or []
    counts = {"audits": 0, "compliance_findings": 0, "compliance_findings_updated": 0}
    if not rules:
        return counts
    tid = _import_tenant_id()
    source = str(result.get("source") or "Compliance").strip() or "Compliance"
    benchmark = str(c.get("benchmark") or source)
    baseline = str(c.get("baseline") or "baseline")
    host = str(c.get("host") or "").strip()
    os_name = str(c.get("os") or "")
    total = len(rules)
    failed = [r for r in rules if str(r.get("result")).lower() == "fail"]
    passed = sum(1 for r in rules if str(r.get("result")).lower() == "pass")
    exempt = sum(1 for r in rules if str(r.get("result")).lower() == "exempt")
    audit_name = ("%s - %s%s" % (benchmark, baseline, (" (%s)" % host if host else "")))[:200]
    status = "Compliant" if not failed else ("Major findings" if len(failed) > total * 0.25 else "Minor findings")
    desc = ("%s baseline '%s'%s: %d/%d rules compliant (%d failed, %d exempt). Imported from %s." % (
        benchmark, baseline, (" on %s" % host if host else ""), passed, total, len(failed), exempt, source))[:4000]

    con = sqlite3.connect(os.path.join(_db_dir(), "XCOMPLIANCE.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS AUDIT (AuditID INTEGER PRIMARY KEY, AuditGUID TEXT, AuditDate TEXT,
        AuditStatus TEXT, AuditorName TEXT, AuditDescription TEXT, AuditScope TEXT, AuditType TEXT,
        AuditClosureDate TEXT, AuditName TEXT, AuditCategory TEXT, TenantID INTEGER)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS AUDITFINDING (AuditFindingID INTEGER PRIMARY KEY, AuditFindingGUID TEXT,
        FindingName TEXT, FindingDescription TEXT, FindingDate TEXT, FindingStatus TEXT, FindingStakeholder TEXT,
        FindingCriticity TEXT, WorkflowStatus TEXT, Severity TEXT, RemediationPlan TEXT, RemediationOwnerPersonID INTEGER,
        DueDate TEXT, AuditID INTEGER, Source TEXT)""")
    row = cur.execute("SELECT AuditID FROM AUDIT WHERE AuditName=? AND IFNULL(TenantID,0)=IFNULL(?,0)", (audit_name, tid)).fetchone()
    if row:
        aid = row[0]
        cur.execute("""UPDATE AUDIT SET AuditStatus=?, AuditorName=?, AuditDescription=?, AuditScope=?,
            AuditType=?, AuditCategory=?, AuditDate=? WHERE AuditID=?""",
            (status, source, desc, host or os_name, "Compliance", "macOS Hardening (mSCP)", _now(), aid))
    else:
        cur.execute("""INSERT INTO AUDIT (AuditGUID, AuditDate, AuditStatus, AuditorName, AuditDescription,
            AuditScope, AuditType, AuditName, AuditCategory, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (str(uuid4()), _now(), status, source, desc, host or os_name, "Compliance", audit_name, "macOS Hardening (mSCP)", tid))
        aid = cur.lastrowid
        counts["audits"] += 1
    for r in failed:
        rid = str(r.get("rule_id") or "").strip()
        if not rid:
            continue
        src = "mscp:%s" % rid
        fdesc = str(r.get("discussion") or "")[:1500]
        refs = str(r.get("references") or "")
        if refs:
            fdesc = (fdesc + ("\n\nNIST SP 800-53: %s" % refs)).strip()
        sev = _norm_sev(r.get("severity") or "medium")
        name = ("[%s] %s" % (rid, r.get("title") or rid))[:300]
        ex = cur.execute("SELECT AuditFindingID FROM AUDITFINDING WHERE AuditID=? AND Source=?", (aid, src)).fetchone()
        if ex:
            cur.execute("""UPDATE AUDITFINDING SET FindingName=?, FindingDescription=?, FindingCriticity=?,
                Severity=?, FindingDate=? WHERE AuditFindingID=?""", (name, fdesc, sev, sev, _now(), ex[0]))
            counts["compliance_findings_updated"] += 1
        else:
            cur.execute("""INSERT INTO AUDITFINDING (AuditFindingGUID, FindingName, FindingDescription, FindingDate,
                FindingStatus, FindingCriticity, WorkflowStatus, Severity, AuditID, Source)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (str(uuid4()), name, fdesc, _now(), "Open", sev, "New", sev, aid, src))
            counts["compliance_findings"] += 1
    con.commit()
    con.close()
    return counts


def import_wifi(result: Dict[str, Any]) -> Dict[str, int]:
    """Import discovered Wi-Fi networks into XORCISM.WIFINETWORK (used by the freeway connector and
    any Wi-Fi survey connector). Stores raw observations (SSID/BSSID/auth/cipher/band/channel/signal/
    WPS); Grade/RiskScore/Severity/Auth are left NULL on purpose — the /wifi-pentest module
    (wifipentest.ts) is the single source of truth and grades these rows on read. Idempotent by
    (BSSID, tenant). Stamps XORCISM_IMPORT_TENANT_ID. Raw sqlite3, worker-safe.

    result["wifi"] = {source, networks:[{ssid, bssid, enc|auth|security, cipher, band, channel|chan,
        signal, wps, radio}]} (also accepts top-level result["wifi_networks"])."""
    from uuid import uuid4

    w = result.get("wifi") or {}
    nets = w.get("networks") or result.get("wifi_networks") or []
    counts = {"wifi_networks": 0, "wifi_networks_updated": 0}
    if not nets:
        return counts
    tid = _import_tenant_id()
    source = ("import:%s" % str(w.get("source") or result.get("source") or "connector")).strip()[:60]

    con = sqlite3.connect(os.path.join(_db_dir(), "XORCISM.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS WIFINETWORK (NetworkID INTEGER PRIMARY KEY, NetworkGUID TEXT,
        SSID TEXT, BSSID TEXT, Auth TEXT, AuthRaw TEXT, Cipher TEXT, Band TEXT, Channel TEXT, Signal INTEGER,
        RadioType TEXT, Wps INTEGER, IsCurrent INTEGER DEFAULT 0, Grade TEXT, RiskScore INTEGER, Severity TEXT,
        FindingsJSON TEXT, RecommendationsJSON TEXT, ToolsJSON TEXT, AttackJSON TEXT, Source TEXT,
        ScanDate TEXT, TenantID INTEGER)""")

    def _int(v: Any) -> Any:
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    for n in nets:
        bssid = str(n.get("bssid") or "").strip().lower()
        if not bssid:
            continue
        ssid = str(n.get("ssid") or "").strip() or "(hidden)"
        authraw = str(n.get("enc") or n.get("auth") or n.get("authRaw") or n.get("security") or "")
        cipher = str(n.get("cipher") or "")
        band = str(n.get("band") or "")
        channel = str(n.get("channel") or n.get("chan") or "")
        signal = _int(n.get("signal"))
        wv = n.get("wps")
        wps = None if wv is None else (1 if (wv is True or str(wv).strip().lower() in ("1", "true", "yes", "on")) else 0)
        vals = (ssid, bssid, authraw, cipher, band, channel, signal, str(n.get("radio") or ""), wps, source, _now())
        row = cur.execute("SELECT NetworkID FROM WIFINETWORK WHERE BSSID=? AND IFNULL(TenantID,0)=IFNULL(?,0)", (bssid, tid)).fetchone()
        if row:
            cur.execute("""UPDATE WIFINETWORK SET SSID=?, BSSID=?, AuthRaw=?, Cipher=?, Band=?, Channel=?,
                Signal=?, RadioType=?, Wps=?, Source=?, ScanDate=?,
                Auth=NULL, Grade=NULL, RiskScore=NULL, Severity=NULL WHERE NetworkID=?""", (*vals, row[0]))
            counts["wifi_networks_updated"] += 1
        else:
            cur.execute("""INSERT INTO WIFINETWORK (NetworkGUID, SSID, BSSID, AuthRaw, Cipher, Band, Channel,
                Signal, RadioType, Wps, Source, ScanDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (str(uuid4()), *vals, tid))
            counts["wifi_networks"] += 1
    con.commit()
    con.close()
    return counts


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
