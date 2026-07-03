#!/usr/bin/env python3
"""
MADIS (Soluris) → XORCISM GDPR/DPO cockpit connector.

Parses a MADIS export (madis.app, AGPLv3) and normalizes it into the payload the
XORCISM privacy module imports (POST /api/privacy/import):

    { "processing": [...], "processors": [...], "dsar": [...],
      "breaches": [...], "actions": [...], "source": "madis", "counts": {...} }

Accepts:
  * a JSON bundle already shaped like the payload above (pass-through), or a
    MADIS-shaped JSON object,
  * a single CSV register export (register auto-detected from headers, or given
    via the `register` parameter),
  * a directory of CSVs (routed by filename keyword).

Worker-safe, read-only, licence-safe: it only parses operator-produced exports.
No MADIS (AGPLv3) code is vendored; MADIS itself is run by the operator.
"""
import csv
import io
import json
import os
import sys
import unicodedata

TOOL_URL = "https://madis.app/"
MAX_BYTES = 25 * 1024 * 1024   # defensive cap on any single file read
MAX_ROWS = 20000               # defensive cap on rows per register

# ── CNIL / WP248 DPIA-trigger criteria: MADIS risk-indicator column → code ──────
DPIA_TRIGGER_MAP = [
    ("surveillance systematique", "monitoring"),
    ("systematic monitoring", "monitoring"),
    ("large echelle", "large-scale"),
    ("large scale", "large-scale"),
    ("personnes vulnerables", "vulnerable"),
    ("vulnerable", "vulnerable"),
    ("croisement", "matching"),
    ("matching", "matching"),
    ("evaluation ou notation", "scoring"),
    ("scoring", "scoring"),
    ("decisions automatisees", "auto-decision"),
    ("automated decision", "auto-decision"),
    ("exclusion automatique", "blocking"),
    ("usage innovant", "innovative"),
    ("innovative", "innovative"),
    ("donnees sensibles", "sensitive"),
    ("sensitive", "sensitive"),
]


def _norm(s):
    """lowercase + strip accents + collapse spaces — for tolerant header matching."""
    s = unicodedata.normalize("NFKD", str(s or "")).encode("ascii", "ignore").decode("ascii")
    return " ".join(s.lower().replace("_", " ").replace("-", " ").split())


def _truthy(v):
    return _norm(v) in ("oui", "yes", "true", "1", "vrai", "x", "o", "y")


def _get(row, *aliases):
    """Fetch a CSV cell by any of several header aliases (accent/case-insensitive)."""
    norm_row = {_norm(k): v for k, v in row.items() if k is not None}
    for a in aliases:
        na = _norm(a)
        if na in norm_row and str(norm_row[na]).strip():
            return str(norm_row[na]).strip()
        # substring fallback (handles "Finalités du traitement" ~ "finalite")
        for k, v in norm_row.items():
            if na and na in k and str(v).strip():
                return str(v).strip()
    return ""


def _triggers_from_row(row):
    codes = []
    for k, v in row.items():
        if not _truthy(v):
            continue
        nk = _norm(k)
        for needle, code in DPIA_TRIGGER_MAP:
            if needle in nk and code not in codes:
                codes.append(code)
    return codes


# ── Per-register row mappers ────────────────────────────────────────────────────
def map_processing(row):
    triggers = _triggers_from_row(row)
    special = _truthy(_get(row, "donnees sensibles", "categories particulieres", "special categories")) or "sensitive" in triggers
    return {
        "name": _get(row, "nom", "name", "traitement", "libelle"),
        "purpose": _get(row, "finalites", "finalite", "purpose"),
        "legalBasis": _get(row, "base legale", "fondement", "liceite", "legal basis"),
        "dataCategories": _get(row, "categories de donnees", "data categories", "donnees"),
        "dataSubjects": _get(row, "personnes concernees", "data subjects"),
        "recipients": _get(row, "destinataires", "categories de destinataires", "recipients"),
        "retention": _get(row, "delai de conservation", "duree de conservation", "retention"),
        "controller": _get(row, "responsable de traitement", "gestionnaire", "controller"),
        "specialCategories": special,
        "crossBorder": _truthy(_get(row, "transfert hors ue", "envoi des donnees hors ue", "cross border", "transfert")),
        "transferSafeguard": _get(row, "garantie", "safeguard", "encadrement du transfert"),
        "riskLevel": _get(row, "niveau de risque", "risk level") or ("High" if special or len(triggers) >= 2 else "Medium"),
        "dpiaTriggers": triggers,
    }


def map_processor(row):
    return {
        "name": _get(row, "nom du sous traitant", "nom", "name", "sous traitant"),
        "service": _get(row, "prestation", "service", "objet"),
        "referent": _get(row, "agent referent", "referent", "contact"),
        "clausesVerified": _truthy(_get(row, "clauses contractuelles verifiees", "clauses", "clauses verified")),
        "securityAdopted": _truthy(_get(row, "a adopte les elements de securite necessaires", "securite", "security adopted")),
        "maintainsRopa": _truthy(_get(row, "tient a jour un registre des traitements", "registre", "maintains ropa")),
        "transfersOutsideEU": _truthy(_get(row, "envoi des donnees hors ue", "transfert hors ue", "outside eu")),
        "dpoAppointed": _truthy(_get(row, "dpd designe", "dpo appointed", "dpo")),
        "location": _get(row, "localisation", "pays", "location"),
        "linkedProcessing": _get(row, "traitements associes", "traitement associe", "linked processing"),
        "status": _get(row, "statut", "status") or "Active",
    }


def map_dsar(row):
    return {
        "subjectName": _get(row, "demandeur", "personne concernee", "nom", "subject") or "Unknown subject",
        "requestType": _get(row, "objet de la demande", "type", "request type") or "Access",
        "receivedDate": _get(row, "date de la demande", "received date", "date"),
        "notes": _get(row, "motif", "reason", "notes"),
    }


def map_breach(row):
    desc = _get(row, "description de l'incident", "description", "nature")
    date = _get(row, "date de la violation", "detected date", "date")
    return {
        "title": _get(row, "titre", "title") or (desc[:80] if desc else ("Breach " + date if date else "Breach")),
        "description": desc,
        "detectedDate": date,
        "affectedSubjects": _get(row, "nombre de personnes affectees", "affected", "nombre de concernes"),
        "dataCategories": _get(row, "categories de donnees", "data categories"),
        "severity": _get(row, "gravite", "severity") or "Medium",
        "riskToSubjects": _get(row, "risque pour les personnes", "risk to subjects"),
    }


def map_action(row):
    prio_raw = _norm(_get(row, "priorite", "priority"))
    prio = 1 if ("haut" in prio_raw or "high" in prio_raw or prio_raw == "1") else 3 if ("bas" in prio_raw or "low" in prio_raw or prio_raw == "3") else 2
    return {
        "name": _get(row, "nom", "name", "action", "libelle"),
        "description": _get(row, "description"),
        "owner": _get(row, "responsable d'action", "responsable", "owner"),
        "priority": prio,
        "cost": _get(row, "cout", "cost"),
        "effort": _get(row, "charge", "effort"),
        "status": _get(row, "statut", "status") or "Planned",
        "dueDate": _get(row, "date previsionnelle", "scheduled date", "due date"),
        "linkKind": "processing" if _get(row, "traitement") else ("processor" if _get(row, "sous traitant") else ""),
        "linkRef": _get(row, "traitement associe", "traitement", "sous traitant", "linked"),
    }


REGISTERS = {
    "processing": (["traitement", "processing", "ropa", "rat"], map_processing),
    "processors": (["sous traitant", "processor", "subcontractor", "sous-traitant"], map_processor),
    "dsar": (["demande", "droit", "request", "dsar", "exercice"], map_dsar),
    "breaches": (["violation", "breach", "incident"], map_breach),
    "actions": (["action", "plan"], map_action),
}
# Header signatures used to auto-detect a register from a CSV's columns.
DETECT = {
    "processors": ["sous traitant", "clauses contractuelles", "dpd designe"],
    "breaches": ["violation", "personnes affectees", "notification cnil"],
    "dsar": ["objet de la demande", "demandeur", "exercice"],
    "actions": ["responsable d'action", "date previsionnelle", "priorite"],
    "processing": ["finalite", "base legale", "categories de donnees"],
}


def _read_text(path):
    with open(path, "rb") as fh:
        raw = fh.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("file too large")
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _sniff_csv(text):
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,\t|")
        delim = dialect.delimiter
    except Exception:
        delim = ";" if sample.count(";") >= sample.count(",") else ","
    rows = list(csv.DictReader(io.StringIO(text), delimiter=delim))
    return rows[:MAX_ROWS]


def _detect_register(rows, hint=""):
    if hint:
        hn = _norm(hint)
        for reg, (aliases, _) in REGISTERS.items():
            if any(a in hn for a in aliases):
                return reg
    if not rows:
        return None
    headers = " ".join(_norm(h) for h in rows[0].keys() if h)
    best, best_score = None, 0
    for reg, sigs in DETECT.items():
        score = sum(1 for s in sigs if s in headers)
        if score > best_score:
            best, best_score = reg, score
    return best if best_score else None


def _empty():
    return {"processing": [], "processors": [], "dsar": [], "breaches": [], "actions": []}


def _ingest_csv_text(out, text, hint):
    rows = _sniff_csv(text)
    reg = _detect_register(rows, hint)
    if not reg:
        return
    _, mapper = REGISTERS[reg]
    for r in rows:
        m = mapper(r)
        if str(m.get("name") or m.get("title") or m.get("subjectName") or "").strip():
            out[reg].append(m)


def run(params, workdir):
    out = _empty()
    path = (params or {}).get("file")
    hint = (params or {}).get("register", "")
    if not path or not os.path.exists(path):
        return {**out, "source": "madis", "counts": {k: 0 for k in out}, "error": "no input file"}

    if os.path.isdir(path):
        for fn in sorted(os.listdir(path)):
            fp = os.path.join(path, fn)
            if fn.lower().endswith(".csv") and os.path.isfile(fp):
                try:
                    _ingest_csv_text(out, _read_text(fp), fn)
                except Exception as e:  # noqa: BLE001 — one bad file must not sink the batch
                    sys.stderr.write(f"[madis] skip {fn}: {e}\n")
    else:
        text = _read_text(path)
        stripped = text.lstrip()
        if stripped[:1] in ("{", "["):
            try:
                data = json.loads(text)
            except Exception:
                data = None
            if isinstance(data, dict):
                # Map top-level register names (canonical or MADIS/French: "demandes",
                # "violations", "traitements", "sous-traitants"…) to our canonical keys.
                alias = {}
                for k, v in data.items():
                    nk = _norm(k)
                    for reg, (aliases, _) in REGISTERS.items():
                        if nk == reg or any(a in nk for a in aliases):
                            alias.setdefault(reg, v)
                            break
                for k in out:
                    v = alias.get(k)
                    if isinstance(v, list):
                        mapper = REGISTERS[k][1]
                        for item in v[:MAX_ROWS]:
                            if not isinstance(item, dict):
                                continue
                            # pass through if already normalized, else map French keys
                            out[k].append(item if ("name" in item or "title" in item or "subjectName" in item) else mapper(item))
            elif isinstance(data, list):
                _ingest_rows_list(out, data, hint)
        else:
            _ingest_csv_text(out, text, hint)

    counts = {k: len(v) for k, v in out.items()}
    return {**out, "source": "madis", "counts": counts, "tool": TOOL_URL}


def _ingest_rows_list(out, rows, hint):
    reg = _detect_register([r for r in rows if isinstance(r, dict)][:5], hint)
    if not reg:
        return
    mapper = REGISTERS[reg][1]
    for r in rows[:MAX_ROWS]:
        if isinstance(r, dict):
            out[reg].append(mapper(r))


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="MADIS (Soluris) GDPR export → XORCISM privacy import")
    ap.add_argument("--file", help="MADIS export (JSON bundle, CSV, or directory of CSVs)")
    ap.add_argument("--register", default="", help="traitements|sous-traitants|demandes|violations|actions")
    a = ap.parse_args()

    if not a.file:
        # Self-contained sample (one row per register) so the connector is demoable offline.
        sample = {
            "processing": [{"Nom": "Gestion de la relation citoyen", "Finalités": "Suivi des demandes",
                            "Base légale": "Mission d'intérêt public", "Catégories de données": "Identité, contact",
                            "Personnes concernées": "Administrés", "Délai de conservation": "5 ans",
                            "Surveillance systématique de personnes": "Non", "Collecte à large échelle": "Oui"}],
            "processors": [{"Nom du sous-traitant": "Hébergeur SaaS", "Agent référent": "DPO éditeur",
                            "Clauses contractuelles vérifiées": "Oui", "Envoi des données hors UE": "Non",
                            "DPD désigné": "Oui", "Localisation": "France"}],
            "demandes": [{"Objet de la demande": "Accès", "Date de la demande": "2026-06-01", "Demandeur": "Jean Dupont"}],
            "violations": [{"Date de la violation": "2026-05-20", "Description de l'incident": "E-mail mal adressé",
                            "Nombre de personnes affectées": "12", "Notification CNIL": "Non"}],
            "actions": [{"Nom": "Signer le contrat de sous-traitance", "Responsable d'action": "DPO",
                         "Priorité": "Haute", "Statut": "Non appliquée", "Date prévisionnelle": "2026-07-15"}],
        }
        fp = os.path.join(tempfile.mkdtemp(), "madis_export.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh, ensure_ascii=False)
        a.file = fp

    res = run({"file": a.file, "register": a.register}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    c = res["counts"]
    print(f"\n[madis] normalized: {c['processing']} processing · {c['processors']} processors · "
          f"{c['dsar']} DSAR · {c['breaches']} breaches · {c['actions']} actions "
          f"→ POST /api/privacy/import (tool: {TOOL_URL})", file=sys.stderr)
