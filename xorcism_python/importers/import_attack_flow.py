"""import_attack_flow.py - import MITRE CTID Attack Flow STIX bundles into XORCISM (XTHREAT).

Attack Flow (github.com/center-for-threat-informed-defense/attack-flow, Apache 2.0) is a language - a
STIX 2.1 extension - for describing how adversaries SEQUENCE and combine ATT&CK techniques to reach
their goals (a directed graph of behaviours, not a flat technique list). MITRE publishes a corpus of
~40 real-world incidents (SolarWinds, NotPetya, Conti, Equifax, REvil, Target, Uber, …) as machine-
readable STIX 2.1 bundles.

This loads Attack Flow STIX bundles into XTHREAT, matching server/attackflow.ts so the /attack-flow
cockpit renders them as ATT&CK-mapped graphs:

  ATTACKFLOW      -> one row per flow (Name, Scope, Description, Author, StixId, …)
  ATTACKFLOWNODE  -> one row per attack-action / -asset / -condition / -operator (TechniqueId, …)
  ATTACKFLOWEDGE  -> control/asset edges (effect_refs, on_true_refs, on_false_refs, asset_refs)

Sources: --all (the whole published corpus), --name "SolarWinds" (one/many corpus flows), --url
<https .json>, or --file <path>. Idempotent by (StixId, TenantID): re-importing a flow replaces it in
place. Stdlib only (urllib). DB dir = --db-dir or $XORCISM_DB_DIR or the default XORCISM_databases path.

    python xorcism_python/importers/import_attack_flow.py --all
    python xorcism_python/importers/import_attack_flow.py --name SolarWinds --name NotPetya
    python xorcism_python/importers/import_attack_flow.py --url https://…/MyFlow.json --tenant 3
    python xorcism_python/importers/import_attack_flow.py --file ./MyFlow.json
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CORPUS_BASE = "https://center-for-threat-informed-defense.github.io/attack-flow/corpus/"
NODE_KINDS = {"attack-action", "attack-asset", "attack-condition", "attack-operator"}

# the published corpus (filename stems, without .json)
CORPUS = [
    "Black Basta Ransomware", "CISA AA22-138B VMWare Workspace (Alt)", "CISA AA22-138B VMWare Workspace (TA1)",
    "CISA AA22-138B VMWare Workspace (TA2)", "CISA Iranian APT", "Cobalt Kitty Campaign", "Conti CISA Alert",
    "Conti PWC", "Conti Ransomware", "DFIR - BumbleBee Round 2", "Equifax Breach", "Example Attack Tree",
    "FIN13 Case 1", "FIN13 Case 2", "Gootloader", "Hancitor DLL", "Ivanti Vulnerabilities", "JP Morgan Breach",
    "MITRE NERVE", "Maastricht University Ransomware", "Mac Malware Steals Crypto", "Marriott Breach",
    "Muddy Water", "NotPetya", "OceanLotus", "REvil", "Ragnar Locker", "SWIFT Heist", "SearchAwesome Adware",
    "Shamoon", "SolarWinds", "Sony Malware", "Target Breach", "Tesla Kubernetes Breach", "Uber Breach", "WhisperGate",
]


def _db(name: str, db_dir: str | None) -> str:
    d = db_dir or os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{name}.db")


def _ensure_tables(cur: sqlite3.Cursor) -> None:
    """Mirror ensureAttackFlowTables() in server/attackflow.ts."""
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS ATTACKFLOW(
      FlowID INTEGER PRIMARY KEY, TenantID INTEGER, StixId TEXT, Name TEXT, Scope TEXT,
      Description TEXT, Author TEXT, Confidence INTEGER, ExternalRefs TEXT, Source TEXT,
      Created TEXT, Modified TEXT, ImportedDate TEXT);
    CREATE TABLE IF NOT EXISTS ATTACKFLOWNODE(
      NodeID INTEGER PRIMARY KEY, FlowID INTEGER, StixId TEXT, Kind TEXT, Name TEXT,
      TechniqueId TEXT, TacticId TEXT, Description TEXT, Confidence INTEGER,
      ExecStart TEXT, ExecEnd TEXT, Operator TEXT, IsStart INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS ATTACKFLOWEDGE(
      EdgeID INTEGER PRIMARY KEY, FlowID INTEGER, SrcStixId TEXT, DstStixId TEXT, Kind TEXT);
    CREATE INDEX IF NOT EXISTS ix_attackflow_tenant ON ATTACKFLOW(TenantID);
    CREATE INDEX IF NOT EXISTS ix_aflownode_flow ON ATTACKFLOWNODE(FlowID);
    CREATE INDEX IF NOT EXISTS ix_aflowedge_flow ON ATTACKFLOWEDGE(FlowID);
    """)


def _next_id(cur: sqlite3.Cursor, table: str, col: str) -> int:
    return int(cur.execute(f"SELECT COALESCE(MAX({col}),0) FROM {table}").fetchone()[0] or 0) + 1


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "XORCISM-attackflow-importer"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (https only, from our constants/args)
        return json.loads(r.read().decode("utf-8"))


def _parse(bundle: dict) -> dict:
    """Parse an Attack Flow STIX 2.1 bundle → flow meta + nodes + edges (mirrors attackflow.ts)."""
    objects = bundle.get("objects") if isinstance(bundle.get("objects"), list) else \
        ([bundle] if bundle.get("type", "").startswith("attack-") else [])
    if not objects:
        raise ValueError("no STIX objects (expected a bundle with an attack-flow)")
    flow = next((o for o in objects if o.get("type") == "attack-flow"), None)
    if not flow:
        raise ValueError("no attack-flow object - not an Attack Flow export")

    idents = {o["id"]: o.get("name", "") for o in objects if o.get("type") == "identity"}
    author = idents.get(flow.get("created_by_ref", "")) or (next(iter(idents.values()), "") if idents else "")
    starts = set(flow.get("start_refs") or [])

    nodes, edges = [], []
    for o in objects:
        t = o.get("type", "")
        if t not in NODE_KINDS:
            continue
        name = o.get("name") or (o.get("description") if t == "attack-condition" else
                                 (o.get("operator") if t == "attack-operator" else t.replace("attack-", "")))
        nodes.append({
            "stixId": o["id"], "kind": t, "name": str(name or "")[:300],
            "techniqueId": o.get("technique_id") or "", "tacticId": o.get("tactic_id") or "",
            "description": o.get("description") or "",
            "confidence": o.get("confidence") if isinstance(o.get("confidence"), int) else None,
            "execStart": o.get("execution_start") or "", "execEnd": o.get("execution_end") or "",
            "operator": o.get("operator") or "", "isStart": o["id"] in starts,
        })
        for dst in (o.get("effect_refs") or []):
            edges.append((o["id"], dst, "effect"))
        for dst in (o.get("on_true_refs") or []):
            edges.append((o["id"], dst, "on_true"))
        for dst in (o.get("on_false_refs") or []):
            edges.append((o["id"], dst, "on_false"))
        for dst in (o.get("asset_refs") or []):
            edges.append((o["id"], dst, "asset"))

    ids = {n["stixId"] for n in nodes}
    edges = [e for e in edges if e[0] in ids and e[1] in ids]
    return {
        "stixId": flow["id"], "name": flow.get("name") or "Attack Flow", "scope": flow.get("scope") or "other",
        "description": flow.get("description") or "", "author": author,
        "confidence": flow.get("confidence") if isinstance(flow.get("confidence"), int) else None,
        "externalRefs": flow.get("external_references") or [],
        "created": flow.get("created") or "", "modified": flow.get("modified") or "",
        "nodes": nodes, "edges": edges,
    }


def _import(cur: sqlite3.Cursor, tenant: int, bundle: dict, source: str) -> dict:
    p = _parse(bundle)
    now = datetime.now(timezone.utc).isoformat()
    row = cur.execute("SELECT FlowID FROM ATTACKFLOW WHERE StixId=? AND TenantID IS ?", (p["stixId"], tenant)).fetchone()
    if row:
        fid = int(row[0])
        cur.execute("DELETE FROM ATTACKFLOWNODE WHERE FlowID=?", (fid,))
        cur.execute("DELETE FROM ATTACKFLOWEDGE WHERE FlowID=?", (fid,))
        cur.execute("UPDATE ATTACKFLOW SET Name=?, Scope=?, Description=?, Author=?, Confidence=?, ExternalRefs=?, "
                    "Source=?, Created=?, Modified=?, ImportedDate=? WHERE FlowID=?",
                    (p["name"], p["scope"], p["description"], p["author"], p["confidence"],
                     json.dumps(p["externalRefs"]), source, p["created"], p["modified"], now, fid))
        action = "refreshed"
    else:
        fid = _next_id(cur, "ATTACKFLOW", "FlowID")
        cur.execute("INSERT INTO ATTACKFLOW (FlowID, TenantID, StixId, Name, Scope, Description, Author, Confidence, "
                    "ExternalRefs, Source, Created, Modified, ImportedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fid, tenant, p["stixId"], p["name"], p["scope"], p["description"], p["author"], p["confidence"],
                     json.dumps(p["externalRefs"]), source, p["created"], p["modified"], now))
        action = "created"

    nid = _next_id(cur, "ATTACKFLOWNODE", "NodeID")
    for n in p["nodes"]:
        cur.execute("INSERT INTO ATTACKFLOWNODE (NodeID, FlowID, StixId, Kind, Name, TechniqueId, TacticId, "
                    "Description, Confidence, ExecStart, ExecEnd, Operator, IsStart) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (nid, fid, n["stixId"], n["kind"], n["name"], n["techniqueId"], n["tacticId"], n["description"],
                     n["confidence"], n["execStart"], n["execEnd"], n["operator"], 1 if n["isStart"] else 0))
        nid += 1
    eid = _next_id(cur, "ATTACKFLOWEDGE", "EdgeID")
    for src, dst, kind in p["edges"]:
        cur.execute("INSERT INTO ATTACKFLOWEDGE (EdgeID, FlowID, SrcStixId, DstStixId, Kind) VALUES (?,?,?,?,?)",
                    (eid, fid, src, dst, kind))
        eid += 1

    techs = {n["techniqueId"] for n in p["nodes"] if n["techniqueId"].startswith("T") and n["techniqueId"][1:2].isdigit()}
    actions = sum(1 for n in p["nodes"] if n["kind"] == "attack-action")
    return {"action": action, "id": fid, "name": p["name"], "actions": actions, "techniques": len(techs)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Import MITRE Attack Flow STIX bundles into XORCISM (XTHREAT).")
    ap.add_argument("--all", action="store_true", help="import the entire published corpus (~36 flows)")
    ap.add_argument("--name", action="append", default=[], help="corpus flow name (repeatable), e.g. SolarWinds")
    ap.add_argument("--url", action="append", default=[], help="https URL of a STIX bundle (repeatable)")
    ap.add_argument("--file", action="append", default=[], help="path to a local STIX bundle .json (repeatable)")
    ap.add_argument("--tenant", type=int, default=3, help="TenantID (default 3 = demo)")
    ap.add_argument("--db-dir", default=None, help="override DB directory")
    args = ap.parse_args()

    jobs: list[tuple[str, str]] = []   # (kind, ref)
    if args.all:
        jobs += [("corpus", n) for n in CORPUS]
    jobs += [("corpus", n) for n in args.name]
    jobs += [("url", u) for u in args.url]
    jobs += [("file", f) for f in args.file]
    if not jobs:
        ap.error("nothing to import - pass --all, --name, --url or --file")

    con = sqlite3.connect(_db("XTHREAT", args.db_dir))
    con.execute("PRAGMA busy_timeout=20000")
    cur = con.cursor()
    _ensure_tables(cur)

    ok = fail = 0
    for kind, ref in jobs:
        try:
            if kind == "corpus":
                url = CORPUS_BASE + urllib.parse.quote(ref) + ".json"
                bundle = _fetch(url)
                source = url
            elif kind == "url":
                if not ref.lower().startswith("https://"):
                    raise ValueError("url must be https")
                bundle = _fetch(ref)
                source = ref
            else:
                bundle = json.load(open(ref, encoding="utf-8"))
                source = os.path.abspath(ref)
            r = _import(cur, args.tenant, bundle, source)
            con.commit()
            print(f"[attack-flow] {r['action']} #{r['id']} '{r['name']}' - {r['actions']} actions, {r['techniques']} techniques")
            ok += 1
        except Exception as e:  # noqa: BLE001 - report and continue the batch
            print(f"[attack-flow] FAILED {kind} '{ref}': {e}")
            fail += 1

    con.close()
    print(f"[attack-flow] done: {ok} imported, {fail} failed (tenant {args.tenant}).")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
