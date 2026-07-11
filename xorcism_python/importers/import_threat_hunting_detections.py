"""
import_threat_hunting_detections.py — Integrate the dcrowder252/threat-hunting-detections
detection-engineering portfolio into XORCISM (XTHREAT.db).
Jerome Athias - XORCISM

Source: https://github.com/dcrowder252/threat-hunting-detections
A portfolio of vendor-agnostic Sigma rules + platform queries (Splunk SPL, Microsoft KQL,
CrowdStrike LogScale) + documented threat hunts + intel-driven hunts (the BumbleBee /
AdaptixC2 / Akira campaign, with DGA domains and C2 IPs).

What it imports (idempotent, additive — safe to re-run):
  • sigma/**/*.yml                 → XTHREAT.SIGMARULE  (idempotent by the Sigma rule id/GUID)
      – the full Sigma YAML, level/status/author/references, MITRE ATT&CK tags, and the matching
        platform queries from the parallel folders: Splunk SPL → SplQuery, Microsoft KQL → KqlQuery,
        CrowdStrike Falcon LogScale → CqlQuery. Feeds the Threat-Informed Defense 'detect' pillar
        and Purple-Team coverage via AttackTags.
  • hunts/**/*.md                  → XTHREAT.HUNT + HUNTATTACK
      – one hunt per documented investigation, ATT&CK-linked (techniques of its detections).
  • intel campaign IOCs            → XTHREAT.IOC + HUNTIOC
      – BumbleBee DGA domains + campaign IPs (with roles), STIX-patterned, linked to the intel hunt.

Target : XTHREAT.db. Self-sufficient — creates/ALTERs the tables it needs, so it runs against
any server version. Idempotent: existing rows are updated, new ones inserted.

Usage:
    python import_threat_hunting_detections.py                      # clones the repo, imports into $DB_DIR
    python import_threat_hunting_detections.py --repo path/to/clone
    python import_threat_hunting_detections.py --repo repo/ --db-dir C:\\Users\\me\\XORCISM_databases
"""
import argparse
import glob
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from uuid import uuid4

try:
    import yaml  # PyYAML (present in this repo's toolchain); a regex fallback covers its absence.
    _HAVE_YAML = True
except Exception:  # noqa: BLE001
    _HAVE_YAML = False

REPO_URL = "https://github.com/dcrowder252/threat-hunting-detections"
SOURCE = "dcrowder252/threat-hunting-detections"
_TCODE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_ATTACK_TAG_RE = re.compile(r"attack[._]t(\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_DOMAIN_RE = re.compile(r'QueryName\s*=\s*"([^"]+)"')
_IP_RE = re.compile(r'(?:dest_ip|src_ip)\s*=\s*"(\d{1,3}(?:\.\d{1,3}){3})"')
_IPREF_RE = re.compile(r"^[-*]\s*`?(\d{1,3}(?:\.\d{1,3}){3})`?\s*[—:-]+\s*(.+)$", re.MULTILINE)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _norm(s):
    return " ".join(re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).split())


def _code_block(md_text, lang):
    """First fenced code block for a language (```spl / ```kql / ```kusto …)."""
    for tag in ([lang] if isinstance(lang, str) else lang):
        m = re.search(r"```" + re.escape(tag) + r"\s*\n(.*?)```", md_text, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def _tcodes(text):
    return {m.group(0).upper() for m in _TCODE_RE.finditer(text or "")}


# ── table bootstrap (self-sufficient) ─────────────────────────────────────────────
_SIGMA_COLS = {
    "SigmaRuleID": "INTEGER PRIMARY KEY", "SigmaRuleGUID": "TEXT", "SigmaRuleName": "TEXT",
    "SigmaRuleDescription": "TEXT", "SigmaYaml": "TEXT", "LogSource": "TEXT", "Level": "TEXT",
    "Status": "TEXT", "Author": "TEXT", "SigmaReference": "TEXT", "AttackTags": "TEXT",
    "SplQuery": "TEXT", "KqlQuery": "TEXT", "EqlQuery": "TEXT", "CqlQuery": "TEXT",
    "CreatedDate": "DATE", "ValidFrom": "DATE", "ValidUntil": "DATE",
}


def _ensure(cur):
    cur.execute("CREATE TABLE IF NOT EXISTS SIGMARULE (%s)" % ", ".join(f"{n} {t}" for n, t in _SIGMA_COLS.items()))
    have = {r[1] for r in cur.execute("PRAGMA table_info(SIGMARULE)").fetchall()}
    for n, t in _SIGMA_COLS.items():
        if n not in have:
            cur.execute("ALTER TABLE SIGMARULE ADD COLUMN %s %s" % (n, t.replace(" PRIMARY KEY", "")))
    cur.execute("""CREATE TABLE IF NOT EXISTS HUNT (
        HuntID INTEGER PRIMARY KEY, HuntGUID TEXT, HuntName TEXT, HuntDescription TEXT, CreatedDate DATE,
        HuntReference TEXT, ValidFrom DATE, ValidUntil DATE, HuntStatus TEXT, HuntDate DATE, HuntTool TEXT,
        AttackTags TEXT, HuntFindings TEXT, HuntSource TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS HUNTATTACK (
        HuntAttackID INTEGER PRIMARY KEY, HuntID INTEGER, AttackID TEXT, AttackTechniqueID INTEGER,
        CreatedDate DATE, UNIQUE(HuntID, AttackID))""")
    cur.execute("""CREATE TABLE IF NOT EXISTS IOC (
        IOCID INTEGER PRIMARY KEY, IOCGUID TEXT, IOCName TEXT, IOCDescription TEXT, CreatedDate TEXT,
        IOCtype TEXT DEFAULT 'indicator', created_by_ref TEXT, ValidFrom DATE, ValidUntil DATE,
        StixID TEXT, SpecVersion TEXT DEFAULT '2.1', Pattern TEXT, PatternType TEXT DEFAULT 'stix',
        Labels TEXT, ExternalReferences TEXT, Confidence INTEGER, Revoked INTEGER DEFAULT 0)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS HUNTIOC (
        HuntIOCID INTEGER PRIMARY KEY, HuntID INTEGER, IOCID INTEGER, Relationship TEXT, CreatedDate DATE,
        UNIQUE(HuntID, IOCID))""")


def _next_id(cur, table, col):
    return (cur.execute(f"SELECT COALESCE(MAX({col}),0) AS m FROM {table}").fetchone()[0] or 0) + 1


# ── Sigma parsing ─────────────────────────────────────────────────────────────────
def _parse_sigma(text):
    if _HAVE_YAML:
        try:
            y = yaml.safe_load(text) or {}
        except Exception:  # noqa: BLE001
            y = {}
    else:
        y = {}
    def _g(key, default=""):
        v = y.get(key, default)
        return v if v is not None else default
    tags = y.get("tags") or []
    if not isinstance(tags, list):
        tags = [str(tags)]
    tcodes = sorted({("T" + m.group(1)).upper() for tg in tags for m in [_ATTACK_TAG_RE.search(str(tg))] if m}
                    | _tcodes(" ".join(str(t) for t in tags)))
    ls = y.get("logsource") or {}
    logsrc = "/".join(str(ls.get(k)) for k in ("product", "category", "service") if ls.get(k)) if isinstance(ls, dict) else str(ls)
    refs = y.get("references") or []
    if not isinstance(refs, list):
        refs = [str(refs)]
    # Regex fallback for title/id/level/status if YAML unavailable.
    def _rx(field):
        m = re.search(r"^%s:\s*(.+)$" % field, text, re.MULTILINE)
        return m.group(1).strip().strip("'\"") if m else ""
    return {
        "name": str(_g("title") or _rx("title"))[:300],
        "guid": str(_g("id") or _rx("id")) or None,
        "description": str(_g("description") or _rx("description"))[:8000],
        "level": str(_g("level") or _rx("level"))[:40],
        "status": str(_g("status") or _rx("status") or "experimental")[:40],
        "author": str(_g("author") or _rx("author") or SOURCE)[:200],
        "references": "\n".join(str(r) for r in refs)[:2000] or (_rx("references") or None),
        "logsource": logsrc[:200],
        "attack": ", ".join(tcodes) or ", ".join(sorted(_tcodes(text))),
        "yaml": text,
    }


def import_sigma(cur, repo):
    sigma_root = _find_dir(repo, "sigma")
    created = updated = 0
    cat_tcodes = {}  # category (rel dir) → set of T-codes (for hunt linking)
    for yml in sorted(glob.glob(os.path.join(sigma_root, "**", "*.yml"), recursive=True) +
                      glob.glob(os.path.join(sigma_root, "**", "*.yaml"), recursive=True)):
        if os.path.basename(yml).lower().startswith("readme"):
            continue
        text = _read(yml)
        s = _parse_sigma(text)
        if not s["name"]:
            continue
        rel = os.path.relpath(yml, sigma_root)
        cat = os.path.dirname(rel).replace("\\", "/")
        base = os.path.splitext(os.path.basename(yml))[0]
        cat_tcodes.setdefault(cat, set()).update(x.strip() for x in s["attack"].split(",") if x.strip())
        # enrich with the parallel platform queries (same category/base under those folders):
        #   Splunk SPL → SplQuery · Microsoft KQL → KqlQuery · CrowdStrike Falcon LogScale → CqlQuery
        spl = _platform_query(repo, ["splunk"], cat, base, ["spl", "splunk"])
        kql = _platform_query(repo, ["kql (defender)", "kql"], cat, base, ["kql", "kusto"])
        cql = _platform_query(repo, ["crowdstrike"], cat, base, ["kusto", "logscale", "cql", "csql"])
        guid = s["guid"] or ("thd:" + rel.replace("\\", "/"))
        common = (s["name"], s["description"], s["yaml"], s["logsource"], s["level"], s["status"],
                  s["author"], s["references"], s["attack"], spl, kql, cql)
        row = cur.execute("SELECT SigmaRuleID FROM SIGMARULE WHERE SigmaRuleGUID=?", (guid,)).fetchone()
        if row:
            cur.execute("""UPDATE SIGMARULE SET SigmaRuleName=?, SigmaRuleDescription=?, SigmaYaml=?,
                LogSource=?, Level=?, Status=?, Author=?, SigmaReference=?, AttackTags=?, SplQuery=?, KqlQuery=?, CqlQuery=?
                WHERE SigmaRuleID=?""", (*common, row[0]))
            updated += 1
        else:
            cur.execute("""INSERT INTO SIGMARULE (SigmaRuleName, SigmaRuleDescription, SigmaYaml, LogSource,
                Level, Status, Author, SigmaReference, AttackTags, SplQuery, KqlQuery, CqlQuery, SigmaRuleGUID,
                CreatedDate, ValidFrom) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*common, guid, _now(), _today()))
            created += 1
    return created, updated, cat_tcodes


def _platform_query(repo, folder_names, cat, base, langs):
    want = _norm(base).replace(" ", "").rstrip("s")  # tolerate case/underscore/singular-plural drift
    for fn in folder_names:
        root = _find_dir(repo, fn, required=False)
        if not root:
            continue
        catdir = os.path.join(root, cat)
        if not os.path.isdir(catdir):
            continue
        cands = [os.path.join(catdir, base + ".md")]  # exact first
        cands += [os.path.join(catdir, f) for f in sorted(os.listdir(catdir))
                  if f.lower().endswith(".md") and _norm(os.path.splitext(f)[0]).replace(" ", "").rstrip("s") == want]
        for md in cands:
            if os.path.exists(md):
                q = _code_block(_read(md), langs)
                if q:
                    return q[:8000]
    return None


# ── Hunt parsing ──────────────────────────────────────────────────────────────────
def import_hunts(cur, repo, cat_tcodes):
    hunts_root = _find_dir(repo, "hunts")
    created = updated = links = 0
    hunt_ids = {}  # base → HuntID (for IOC linking)
    for md in sorted(glob.glob(os.path.join(hunts_root, "**", "*.md"), recursive=True)):
        if os.path.basename(md).lower().startswith("readme"):
            continue
        text = _read(md)
        m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        name = (m.group(1).strip() if m else os.path.splitext(os.path.basename(md))[0])[:300]
        base = re.sub(r"_hunt$", "", os.path.splitext(os.path.basename(md))[0])
        # techniques: literal T-codes in the doc ∪ the best-matching sigma category's T-codes
        doc_tokens = set(_norm(base).split())
        best_cat, best_j = None, 0.0
        for cat in cat_tcodes:
            ctoks = set(_norm(cat.split("/")[-1]).split())
            inter = len(doc_tokens & ctoks)
            j = inter / max(1, len(doc_tokens | ctoks))
            if inter and j > best_j:
                best_cat, best_j = cat, j
        tcodes = set(_tcodes(text)) | (cat_tcodes.get(best_cat, set()) if best_cat else set())
        tcodes = sorted(t for t in tcodes if re.fullmatch(r"T\d{4}(\.\d{3})?", t))
        ref = None
        rm = re.search(r"https?://\S+", text)
        if "intel" in md.lower() and rm:
            ref = rm.group(0).rstrip(").,")
        desc = text[:8000]
        row = cur.execute("SELECT HuntID FROM HUNT WHERE HuntName=? AND HuntSource=?", (name, SOURCE)).fetchone()
        if row:
            hid = row[0]
            cur.execute("UPDATE HUNT SET HuntDescription=?, AttackTags=?, HuntReference=?, HuntStatus=? WHERE HuntID=?",
                        (desc, ", ".join(tcodes), ref, "Documented", hid))
            updated += 1
        else:
            hid = _next_id(cur, "HUNT", "HuntID")
            cur.execute("""INSERT INTO HUNT (HuntID, HuntGUID, HuntName, HuntDescription, CreatedDate,
                HuntReference, HuntStatus, HuntTool, AttackTags, HuntFindings, HuntSource)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (hid, str(uuid4()), name, desc, _now(), ref, "Documented",
                 "Sigma · Splunk · KQL · CrowdStrike", ", ".join(tcodes), "", SOURCE))
            created += 1
        hunt_ids[base] = hid
        for aid in tcodes:
            nid = _next_id(cur, "HUNTATTACK", "HuntAttackID")
            if cur.execute("INSERT OR IGNORE INTO HUNTATTACK (HuntAttackID, HuntID, AttackID, CreatedDate) VALUES (?,?,?,?)",
                           (nid, hid, aid, _now())).rowcount:
                links += 1
    return created, updated, links, hunt_ids


# ── Intel IOC parsing (BumbleBee / AdaptixC2 / Akira campaign) ─────────────────────
def import_iocs(cur, repo, hunt_ids):
    created = updated = linked = 0
    # find the intel IOC files (any platform folder carries the same indicators; splunk has roles)
    campaign_hid = None
    for base, hid in hunt_ids.items():
        if "bumblebee" in base or "adaptix" in base or "akira" in base:
            campaign_hid = hid
            break
    for md in sorted(glob.glob(os.path.join(repo, "**", "intel_*.md"), recursive=True)):
        low = md.lower().replace("\\", "/")
        if "/splunk/" not in low:  # de-dup: read the Splunk variant (has the IP-role reference)
            continue
        text = _read(md)
        ref_m = re.search(r"Intel Source:\**\s*(https?://\S+)", text) or re.search(r"https?://\S+", text)
        ref = ref_m.group(1 if ref_m and ref_m.re.groups else 0).rstrip(").,") if ref_m else None
        atk_m = re.search(r"MITRE ATT&CK:\**\s*([T0-9., ]+)", text)
        labels = ", ".join(sorted(_tcodes(atk_m.group(1)))) if atk_m else ""
        roles = {ip: role.strip() for ip, role in _IPREF_RE.findall(text)}
        indicators = []  # (value, type, stix_type, desc)
        for d in dict.fromkeys(_DOMAIN_RE.findall(text)):
            indicators.append((d, "domain-name", "BumbleBee DGA domain"))
        for ip in dict.fromkeys(_IP_RE.findall(text)):
            indicators.append((ip, "ipv4-addr", roles.get(ip, "Campaign infrastructure")))
        for value, stype, role in indicators:
            desc = f"{role} — BumbleBee/AdaptixC2/Akira campaign"
            pattern = f"[{stype}:value = '{value}']"
            row = cur.execute("SELECT IOCID FROM IOC WHERE IOCName=? AND COALESCE(IOCtype,'indicator')='indicator'", (value,)).fetchone()
            if row:
                iid = row[0]
                cur.execute("UPDATE IOC SET IOCDescription=?, Pattern=?, PatternType='stix', Labels=?, ExternalReferences=?, Confidence=?, created_by_ref=? WHERE IOCID=?",
                            (desc, pattern, labels or "malicious-activity", ref, 60, SOURCE, iid))
                updated += 1
            else:
                iid = _next_id(cur, "IOC", "IOCID")
                cur.execute("""INSERT INTO IOC (IOCID, IOCGUID, IOCName, IOCDescription, CreatedDate, IOCtype,
                    created_by_ref, ValidFrom, StixID, Pattern, PatternType, Labels, ExternalReferences, Confidence)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (iid, str(uuid4()), value, desc, _now(), "indicator", SOURCE, _today(),
                     "indicator--" + str(uuid4()), pattern, "stix", labels or "malicious-activity", ref, 60))
                created += 1
            if campaign_hid:
                nid = _next_id(cur, "HUNTIOC", "HuntIOCID")
                if cur.execute("INSERT OR IGNORE INTO HUNTIOC (HuntIOCID, HuntID, IOCID, Relationship, CreatedDate) VALUES (?,?,?,?,?)",
                               (nid, campaign_hid, iid, "indicates", _now())).rowcount:
                    linked += 1
    return created, updated, linked


# ── repo location helpers ─────────────────────────────────────────────────────────
def _find_dir(repo, name, required=True):
    p = os.path.join(repo, name)
    if os.path.isdir(p):
        return p
    hits = [d for d in glob.glob(os.path.join(repo, "**", name), recursive=True) if os.path.isdir(d)]
    if hits:
        return sorted(hits, key=len)[0]
    if required:
        raise SystemExit(f"[thd] '{name}/' folder not found under {repo}")
    return None


def _clone(dest):
    print(f"[thd] cloning {REPO_URL} …")
    subprocess.check_call(["git", "clone", "--depth", "1", REPO_URL, dest])
    return dest


def main():
    ap = argparse.ArgumentParser(description="Integrate dcrowder252/threat-hunting-detections into XTHREAT")
    ap.add_argument("--repo", help="path to a local clone of the repo (default: git-clone the canonical URL)")
    ap.add_argument("--db-dir", default=os.getenv("DB_DIR", os.getenv("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")),
                    help="directory holding XTHREAT.db (default: $DB_DIR)")
    a = ap.parse_args()

    tmp = None
    repo = a.repo
    if not repo:
        tmp = tempfile.mkdtemp(prefix="thd-")
        repo = _clone(os.path.join(tmp, "repo"))
    elif not os.path.isdir(repo):
        raise SystemExit(f"[thd] --repo not found: {repo}")

    dbpath = os.path.join(a.db_dir, "XTHREAT.db")
    if not os.path.isdir(a.db_dir):
        raise SystemExit(f"[thd] db-dir not found: {a.db_dir}")
    con = sqlite3.connect(dbpath, timeout=20)
    con.execute("PRAGMA busy_timeout=20000")
    cur = con.cursor()
    try:
        _ensure(cur)
        sc, su, cat_tcodes = import_sigma(cur, repo)
        hc, hu, hlinks, hunt_ids = import_hunts(cur, repo, cat_tcodes)
        ic, iu, ilinks = import_iocs(cur, repo, hunt_ids)
        con.commit()
    finally:
        con.close()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    print(f"[thd] SIGMARULE : {sc} inserted, {su} updated")
    print(f"[thd] HUNT      : {hc} inserted, {hu} updated ({hlinks} ATT&CK links)")
    print(f"[thd] IOC       : {ic} inserted, {iu} updated ({ilinks} hunt links)")
    print(f"[thd] done -> {dbpath}")


if __name__ == "__main__":
    main()
