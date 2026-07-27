"""import_gecc.py — import the Saudi NCA ECC (ECC-2:2024) into XORCISM.CONTROL.

Source: NCA "Guide to Essential Cybersecurity Controls (ECC) Implementation" (GECC 2:2024), the
official implementation guide for the Kingdom of Saudi Arabia's baseline cybersecurity framework
(TLP:CLEAR / Public). The updated ECC is organised as 4 main domains, 28 subdomains and 108 main
controls. This importer registers the full control catalogue as a CONTROL vocabulary so ECC-2:2024
shows in /frameworks, backs the ECC compliance journey, and can be cross-mapped and assessed in
/compliance-management — complementing the /nca-ecc implementation & evidence cockpit (server/ncaEcc.ts),
which additionally carries the GECC implementation guidelines and expected deliverables per control.

Writes a hierarchy of CONTROL rows (domains → subdomains → controls) under VOCABULARY
"Saudi NCA Essential Cybersecurity Controls (ECC-2:2024)":
  ControlName = "<ref> <title>", CIS = <ref>, Statement = the control text (© NCA),
  ControlDescription = "NCA ECC-2:2024 — Domain <n> <domain> · <subdomain>".
Idempotent by VocabularyID. Raw SQL; DB = XORCISM_DB_DIR. Data is bundled in data/gecc.json (mined
from the public NCA PDF); pass --file to point at another gecc.json.

    python xorcism_python/importers/import_gecc.py [--file data/gecc.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "Saudi NCA Essential Cybersecurity Controls (ECC-2:2024)"
_DATA = os.path.join(os.path.dirname(__file__), "data", "gecc.json")


def _db_path(db_dir: str | None) -> str:
    d = db_dir or os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, "XORCISM.db")


def _ensure_vocab(cur: sqlite3.Cursor, name: str) -> int:
    cols = {r[1] for r in cur.execute("PRAGMA table_info(VOCABULARY)").fetchall()}
    namecol = "VocabularyName" if "VocabularyName" in cols else ("Name" if "Name" in cols else None)
    if namecol:
        row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {namecol}=?", (name,)).fetchone()
        if row:
            return int(row[0])
    nid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    rec = {"VocabularyID": nid}
    if namecol:
        rec[namecol] = name
    if "VocabularyGUID" in cols:
        rec["VocabularyGUID"] = str(uuid.uuid4())
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
    return nid


def _key(ref: str) -> list[int]:
    return [int(x) for x in ref.split("-")]


def main() -> int:
    ap = argparse.ArgumentParser(description="Import the Saudi NCA ECC-2:2024 (GECC) into XORCISM.CONTROL")
    ap.add_argument("--file", default=_DATA, help="bundled gecc.json (default: data/gecc.json)")
    ap.add_argument("--db-dir", help="directory holding XORCISM.db (default: $XORCISM_DB_DIR)")
    a = ap.parse_args()

    doc = json.load(open(a.file, encoding="utf-8"))
    domains = {d["num"]: d["name"] for d in doc["domains"]}
    subnames = {s["code"]: s["name"] for s in doc["subdomains"]}
    subobj = {s["code"]: s.get("objective", "") for s in doc["subdomains"]}

    # Build a single ordered list of rows: domain headers, subdomain headers, then controls.
    rows: list[tuple[str, str, str, str]] = []  # (ref, title, statement, desc)
    for d in sorted(domains, key=int):
        rows.append((d, domains[d], f"NCA ECC-2:2024 main domain {d}.", f"NCA ECC-2:2024 — Domain {d} {domains[d]}"))
    for code in sorted(subnames, key=_key):
        dom = code.split("-")[0]
        rows.append((code, subnames[code], (subobj.get(code) or "").strip()[:2000],
                     f"NCA ECC-2:2024 — Domain {dom} {domains.get(dom, '')} · subdomain"))
    for c in sorted(doc["controls"], key=lambda x: _key(x["ref"])):
        dom = c["domain"]
        desc = f"NCA ECC-2:2024 — Domain {dom} {c.get('domainName', '')} · {c.get('subdomainName', '')}".strip()
        rows.append((c["ref"], c["text"][:120].rstrip() + ("…" if len(c["text"]) > 120 else ""), c["text"][:4000], desc))

    con = sqlite3.connect(_db_path(a.db_dir)); con.execute("PRAGMA busy_timeout=15000"); cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))  # idempotent refresh
    next_id = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1

    n_dom = n_sub = n_ctl = 0
    for ref, title, statement, desc in rows:
        depth = ref.count("-")
        rec = {
            "ControlID": next_id, "ControlGUID": f"gecc2-{ref}",
            "ControlName": f"{ref} {title}".strip()[:300],
            "ControlDescription": desc, "VocabularyID": vid, "CIS": ref,
            "Statement": statement or None, "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        next_id += 1
        if depth == 0: n_dom += 1
        elif depth == 1: n_sub += 1
        else: n_ctl += 1

    try:  # keep/register the ECC-2:2024 FRAMEWORK row's version if the table has one
        cur.execute("UPDATE FRAMEWORK SET FrameworkVersion=? WHERE FrameworkName LIKE '%ECC%' AND FrameworkName LIKE '%2024%'", ("2:2024",))
    except Exception:  # noqa: BLE001
        pass
    con.commit(); con.close()
    print(f"[gecc] VocabularyID={vid}: {n_dom + n_sub + n_ctl} rows "
          f"({n_dom} domains + {n_sub} subdomains + {n_ctl} controls) — NCA ECC-2:2024 (GECC).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
