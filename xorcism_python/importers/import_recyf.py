"""import_recyf.py - import the ANSSI Referentiel Cyber France (ReCyF) into XORCISM.CONTROL.

ReCyF (Referentiel Cyber France) is ANSSI's national reference framework operationalising the
NIS 2 cyber-risk-management measures for France. It is structured as 20 *security objectives*
(the mandatory "what" - obligations set by decree) each with *moyens acceptables de conformite*
(the recommended "how" - ANSSI measures). A proportionality principle applies: objectives 1-15
bind both Important (EI) and Essential (EE) entities; objectives 16-20 bind EE only. Each measure
is tagged EI/EE applicability via its code suffix (e.g. 2.B.2-EI/EE, 2.A.2-EE).

This importer registers the VOCABULARY "Referentiel Cyber France (ReCyF)" and writes CONTROL rows:
  * 20 objective rows   (CIS="OS-N", Statement=the obligation text, pillar + EI/EE scope in the
                         description) - the mandatory objectives, grouped by the ReCyF
                         Gouvernance / Protection / Defense / Resilience pillar model;
  * 153 measure rows    (CIS=the measure code, Statement=the measure text) - the acceptable means
                         of compliance.
It also writes CONTROLMAPPING rows (Framework="NIS2") mapping each objective to the relevant
NIS 2 article(s) (Directive (EU) 2022/2555, art. 20 / 21.2.a-j), per ReCyF's correspondence annex.

Two modes:
  * (no flag)  : load the bundled catalogue (recyf_v2.5.json, parsed from the official PDF) - works
                 offline and is the default.
  * --download : re-fetch and re-parse the official ANSSI ReCyF PDF (needs the optional `pypdf`
                 package); falls back to the bundled catalogue on any error.

Idempotent: re-running deletes the ReCyF controls + their NIS2 mappings and re-inserts. Raw SQL;
DB path = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_recyf.py            # bundled catalogue
    python xorcism_python/importers/import_recyf.py --download # re-parse the live ANSSI PDF
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "Référentiel Cyber France (ReCyF)"
PDF_URL = os.environ.get(
    "RECYF_PDF_URL",
    "https://messervicescyber-ressources.cellar-c2.services.clever-cloud.com/20260317_NIS_V2_ReCyF_v2.5.pdf",
)
BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recyf_v2.5.json")

# NIS 2 (Directive (EU) 2022/2555) article -> short title (for CONTROLMAPPING.ExternalName).
NIS2_TITLES = {
    "Art.20": "Gouvernance - approbation et supervision par les organes de direction",
    "Art.21.2": "Mesures de gestion des risques - approche tous risques",
    "Art.21.2.a": "Politiques d'analyse des risques et de securite des SI",
    "Art.21.2.b": "Gestion des incidents",
    "Art.21.2.c": "Continuite des activites et gestion des crises",
    "Art.21.2.d": "Securite de la chaine d'approvisionnement",
    "Art.21.2.e": "Securite de l'acquisition, du developpement et de la maintenance",
    "Art.21.2.f": "Evaluation de l'efficacite des mesures",
    "Art.21.2.g": "Cyberhygiene et formation a la cybersecurite",
    "Art.21.2.h": "Cryptographie et chiffrement",
    "Art.21.2.i": "Securite RH, controle d'acces et gestion des actifs",
    "Art.21.2.j": "Authentification multifacteur et communications securisees",
}

# Objective metadata for the --download re-parse path (the bundled JSON already carries these).
TITLES = {
    1: "Recensement des systemes d'information",
    2: "Mise en oeuvre d'un cadre de gouvernance de la securite numerique",
    3: "Maitrise de l'ecosysteme",
    4: "Integration de la securite numerique dans la gestion des ressources humaines",
    5: "Maitrise des systemes d'information",
    6: "Maitrise des acces physiques aux locaux",
    7: "Securisation de l'architecture des systemes d'information",
    8: "Securisation des acces distants aux systemes d'information",
    9: "Protection des systemes d'information contre les codes malveillants",
    10: "Gestion des identites et des acces des utilisateurs aux systemes d'information",
    11: "Maitrise de l'administration des systemes d'information",
    12: "Identification et reaction aux incidents de securite",
    13: "Continuite et reprise d'activite",
    14: "Reaction aux crises d'origine cyber",
    15: "Exercices, tests et entrainements",
    16: "Mise en oeuvre d'une approche par les risques",
    17: "Audit de la securite des systemes d'information",
    18: "Securisation de la configuration des ressources des systemes d'information",
    19: "Administration des systemes d'information depuis des ressources dediees",
    20: "Supervision de la securite des systemes d'information",
}
PILLAR = {**{n: "Gouvernance" for n in (1, 2, 3, 4, 5, 16, 17)},
          **{n: "Protection" for n in (6, 7, 8, 9, 10, 11, 18, 19)},
          **{n: "Defense" for n in (12, 20)},
          **{n: "Resilience" for n in (13, 14, 15)}}
NIS2 = {
    1: ["Art.21.2.i"], 2: ["Art.20", "Art.21.2.a", "Art.21.2.f", "Art.21.2.h", "Art.21.2.i"],
    3: ["Art.21.2.d", "Art.21.2.i"], 4: ["Art.21.2.g"], 5: ["Art.21.2.e", "Art.21.2.i"],
    6: ["Art.21.2"], 7: ["Art.21.2.e", "Art.21.2.h"], 8: ["Art.21.2.e", "Art.21.2.h", "Art.21.2.j"],
    9: ["Art.21.2.e"], 10: ["Art.21.2.e", "Art.21.2.i", "Art.21.2.j"], 11: ["Art.21.2.e", "Art.21.2.i"],
    12: ["Art.21.2.b"], 13: ["Art.21.2.c"], 14: ["Art.21.2.c", "Art.21.2.j"],
    15: ["Art.21.2.b", "Art.21.2.c", "Art.21.2.g"], 16: ["Art.21.2.a"], 17: ["Art.21.2.e", "Art.21.2.f"],
    18: ["Art.21.2.e"], 19: ["Art.21.2.e"], 20: ["Art.21.2.b"],
}


def _db_path() -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
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
    if "CreatedDate" in cols:
        rec["CreatedDate"] = datetime.now(timezone.utc).isoformat()
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
    return nid


def _load_bundle() -> dict:
    with open(BUNDLE, encoding="utf-8") as fh:
        return json.load(fh)


def _from_pdf() -> dict:
    """Re-fetch + parse the official ANSSI ReCyF PDF (requires pypdf). Mirrors the bundled catalogue."""
    import urllib.request

    import pypdf  # optional dependency

    req = urllib.request.Request(PDF_URL, headers={"User-Agent": "XORCISM-ReCyF-importer/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    tmp = os.path.join(os.path.dirname(BUNDLE), "_recyf_dl.pdf")
    with open(tmp, "wb") as fh:
        fh.write(raw)
    try:
        reader = pypdf.PdfReader(tmp)
        text = "\n".join((p.extract_text() or "") for p in reader.pages)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    code_re = re.compile(r"^\s*(\d{1,2})\.(?:([A-Z])\.)?(\d{1,2})-(EI/EE|EE|EI)\b\s*(.*)$")
    objh = re.compile(r"OBJECTIF\s+DE\s+S[ÉE]CURIT[ÉE]\s+(\d{1,2})\.", re.IGNORECASE)
    stop = re.compile(r"^\s*(OBJECTIF\s+DE\s+S|RAPPEL\s+DE\s+L|MOYENS\s+ACCEPTABLES|GOUVERNANCE\b|JUSTIFICATIONS|TABLEAUX)", re.IGNORECASE)
    rappel = re.compile(r"RAPPEL\s+DE\s+L", re.IGNORECASE)
    mac = re.compile(r"MOYENS\s+ACCEPTABLES", re.IGNORECASE)
    noise = re.compile(r"^(DOCUMENT DE TRAVAIL|RECYF\b|NIS 2\b|MESURES DE|VERSION|ATTENDU|D[’'`]UNE|\d+\s*$|\s*$)", re.IGNORECASE)

    def is_noise(s: str) -> bool:
        s = s.strip()
        if not s or noise.match(s):
            return True
        letters = [c for c in s if c.isalpha()]
        return bool(letters) and sum(1 for c in letters if c.isupper()) / len(letters) > 0.85 and len(s) < 90

    def clean(t: str) -> str:
        t = re.sub(r"\s+", " ", t).strip()
        t = re.sub(r"\s*(Oui|Non)\s+(Oui|Non)\s*$", "", t)
        return re.sub(r"\s*(Oui|Non)\s*$", "", t).strip()

    objstmt = {n: [] for n in TITLES}
    measures = []
    cur = None
    mode = None
    objnum = 0
    for raw_line in text.split("\n"):
        h = objh.search(raw_line)
        if h:
            objnum = int(h.group(1))
            mode = None
            if cur:
                measures.append(cur)
                cur = None
            continue
        m = code_re.match(raw_line)
        if m:
            if cur:
                measures.append(cur)
            num, sub, idx, appl, rest = m.groups()
            code = f"{num}.{sub + '.' if sub else ''}{idx}-{appl}"
            cur = {"obj": int(num), "code": code, "appl": appl, "text": rest.strip()}
            mode = "measure"
            continue
        if rappel.search(raw_line):
            mode = "rappel"
        if mac.search(raw_line):
            if mode == "rappel":
                mode = None
            if cur:
                measures.append(cur)
                cur = None
            continue
        if mode == "measure":
            if stop.match(raw_line):
                mode = None
            elif not is_noise(raw_line):
                cur["text"] += " " + raw_line.strip()
        elif mode == "rappel" and not is_noise(raw_line) and objnum in objstmt:
            objstmt[objnum].append(raw_line.strip())
    if cur:
        measures.append(cur)
    for mm in measures:
        mm["text"] = clean(mm["text"])
    objectives = [{"num": n, "title": TITLES[n], "pillar": PILLAR[n],
                   "scope": "EI/EE" if n <= 15 else "EE", "nis2": NIS2[n],
                   "statement": clean(" ".join(objstmt[n]))} for n in sorted(TITLES)]
    if len(measures) < 100:
        raise ValueError(f"parsed only {len(measures)} measures - looks wrong")
    return {"framework": VOCAB, "version": "2.5", "date": "2026-03-17",
            "objectives": objectives, "measures": measures}


def main() -> int:
    ap = argparse.ArgumentParser(description="Import ANSSI ReCyF into XORCISM.CONTROL")
    ap.add_argument("--download", action="store_true", help="re-fetch + parse the official ANSSI ReCyF PDF (needs pypdf)")
    a = ap.parse_args()

    cat = None
    if a.download:
        try:
            cat = _from_pdf()
            print(f"[recyf] re-parsed the live ANSSI PDF: {len(cat['objectives'])} objectives, {len(cat['measures'])} measures")
        except Exception as exc:  # noqa: BLE001
            print(f"[recyf] download/parse failed ({exc}); using bundled catalogue")
    if cat is None:
        cat = _load_bundle()
        print(f"[recyf] using bundled catalogue v{cat.get('version')}: {len(cat['objectives'])} objectives, {len(cat['measures'])} measures")

    con = sqlite3.connect(_db_path())
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()

    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    has_map = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone() is not None

    # idempotent: drop previous ReCyF controls + their NIS2 mappings
    old_ids = [r[0] for r in cur.execute("SELECT ControlID FROM CONTROL WHERE VocabularyID=?", (vid,)).fetchall()]
    if old_ids and has_map:
        cur.execute(f"DELETE FROM CONTROLMAPPING WHERE Framework='NIS2' AND ControlID IN ({','.join('?'*len(old_ids))})", old_ids)
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))

    next_cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    next_mid = 1
    if has_map:
        next_mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1

    def insert_control(rec: dict) -> int:
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        return rec["ControlID"]

    n_obj = n_meas = n_map = 0
    obj_title = {o["num"]: o["title"] for o in cat["objectives"]}
    obj_pillar = {o["num"]: o["pillar"] for o in cat["objectives"]}

    # 1) the 20 mandatory security objectives (the "what") + NIS2 crosswalk
    for o in cat["objectives"]:
        cid = next_cid
        next_cid += 1
        scope = o["scope"]
        nis2 = ", ".join(o["nis2"])
        insert_control({
            "ControlID": cid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"OS-{o['num']} {o['title']}"[:300],
            "ControlDescription": f"ReCyF objectif de securite {o['num']} - pilier {o['pillar']} - {scope} - NIS2 {nis2}",
            "VocabularyID": vid, "CIS": f"OS-{o['num']}",
            "Statement": o["statement"] or o["title"],
            "Guidance": f"Objectif obligatoire (le \"quoi\"). Applicabilite: {scope}. Pilier ReCyF: {o['pillar']}.",
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        })
        n_obj += 1
        if has_map:
            for art in o["nis2"]:
                cur.execute(
                    "INSERT INTO CONTROLMAPPING (MappingID, MappingGUID, ControlID, Framework, ExternalID, ExternalName, Relationship, Source, CreatedDate) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (next_mid, str(uuid.uuid4()), cid, "NIS2", art, NIS2_TITLES.get(art, art), "supports",
                     "ReCyF v2.5 (ANSSI) <-> NIS2 Directive (EU) 2022/2555 correspondence", now))
                next_mid += 1
                n_map += 1

    # 2) the acceptable means of compliance (the "how")
    for mm in cat["measures"]:
        cid = next_cid
        next_cid += 1
        title = obj_title.get(mm["obj"], "")
        pillar = obj_pillar.get(mm["obj"], "")
        insert_control({
            "ControlID": cid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{mm['code']} {mm['text']}"[:300],
            "ControlDescription": f"ReCyF - Objectif {mm['obj']}. {title} - pilier {pillar} - {mm['appl']}",
            "VocabularyID": vid, "CIS": mm["code"],
            "Statement": mm["text"],
            "Guidance": f"Moyen acceptable de conformite (le \"comment\"). Applicabilite: {mm['appl']}.",
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        })
        n_meas += 1

    con.commit()
    con.close()
    print(f"[recyf] VocabularyID={vid}: {n_obj} objectives + {n_meas} measures = {n_obj + n_meas} controls, {n_map} NIS2 mappings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
