"""
import_oval.py — Python port of Import_oval/Program.cs (C# .NET)
Jerome Athias - XORCISM

Imports OVAL definitions, tests, objects, states and variables into the
XOVAL.db / XORCISM.db databases (and XVULNERABILITY.db for CVE links).

⚠ WARNING: This can take hours! (Importing the full CIS OVALRepo means parsing
tens of thousands of XML files; plan accordingly.)

TWO SUPPORTED SOURCES:

1) "Split" CIS OVALRepo repository (NEW, recommended) — one XML file per
   element, laid out as a tree:
       repository/definitions/**/<oval-id>.xml
       repository/tests/**/<oval-id>.xml
       repository/objects/**/<oval-id>.xml
       repository/states/**/<oval-id>.xml
       repository/variables/**/<oval-id>.xml
   GitHub: https://github.com/CISecurity/OVALRepo
       python import_oval.py --repo /path/to/OVALRepo
       python import_oval.py --download                 # git clone --depth 1

2) Single consolidated oval.xml file (OLD format):
       python import_oval.py --xml oval.xml

Supported schema: OVAL definitions 5.x
  definitions namespace: http://oval.mitre.org/XMLSchema/oval-definitions-5
"""

import argparse
import os
import re
import sys
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional, Iterator

import requests
from sqlalchemy import event, text, Integer, BigInteger, SmallInteger
from sqlalchemy.orm import Mapper

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope, get_engine
from xorcism_python.utils import log

MODULE = "ImportOVAL"
OVAL_REPO_GIT = "https://github.com/CISecurity/OVALRepo.git"
OVAL_VERSION = "5.11.2"

# OVAL namespaces
NS_DEF = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
NS_COMMON = "http://oval.mitre.org/XMLSchema/oval-common-5"

# OVALRepo repository sub-directories, in import order
REPO_SUBDIRS = ["definitions", "tests", "objects", "states", "variables"]

# Validation regexes (cf. C#)
RE_CVE = re.compile(r"CVE-(?:19|20)\d{2}-(?:0\d{3}|[1-9]\d{3,})")
RE_TST = re.compile(r"oval:.*?:tst:\d+")

# Namespace-URI-suffix → short OVAL name mapping (cf. C#)
NS_SUFFIX_MAP = {
    "#aix": "aix-def", "#apache": "apache-def", "#catos": "catos-def",
    "#esx": "esx-def", "#freebsd": "freebsd-def", "#hpux": "hpux-def",
    "#independent": "ind-def", "#ios": "ios-def", "#linux": "linux-def",
    "#macos": "macos-def", "#pixos": "pixos-def", "#sharepoint": "sp-def",
    "#solaris": "sol-def", "#unix": "unix-def", "#windows": "win-def",
}


# ─── Integer primary-key auto-increment ──────────────────────────────────────
# The tables were created with "<Id> INTEGER NOT NULL" WITHOUT a PRIMARY KEY:
# SQLite does not auto-increment them. This listener assigns MAX(<col>)+1 to any
# single-column integer PK left empty, just before INSERT. The "value already
# set" guard makes the listener idempotent even if another importer has already
# registered the same handler.

_pk_counters: dict = {}
_INT_TYPES = (Integer, BigInteger, SmallInteger)


def _auto_pk(mapper, connection, target) -> None:
    pk_cols = mapper.primary_key
    if len(pk_cols) != 1:
        return
    col = pk_cols[0]
    if not isinstance(col.type, _INT_TYPES):
        return  # textual PK (e.g. CWEID, CCEID): supplied explicitly
    attr = mapper.get_property_by_column(col).key
    if getattr(target, attr, None) is not None:
        return
    tbl = mapper.local_table.name
    key = (str(connection.engine.url), tbl)
    db_max = connection.execute(
        text(f'SELECT COALESCE(MAX("{col.name}"), 0) FROM "{tbl}"')
    ).scalar()
    nxt = max(_pk_counters.get(key, 0), int(db_max or 0)) + 1
    _pk_counters[key] = nxt
    setattr(target, attr, nxt)


event.listen(Mapper, "before_insert", _auto_pk)


# ─── XML helpers ──────────────────────────────────────────────────────────────

def _local(tag: str) -> str:
    """Local name of an ElementTree tag (namespace stripped)."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _ns_short(tag: str) -> str:
    """Short OVAL name (win-def, linux-def…) derived from the tag namespace."""
    uri = tag[1:tag.index("}")] if tag.startswith("{") else ""
    for suffix, short in NS_SUFFIX_MAP.items():
        if suffix in uri:
            return short
    return ""


def _qd(name: str) -> str:
    """Tag qualified in the oval-definitions-5 namespace."""
    return f"{{{NS_DEF}}}{name}"


def _text(el: Optional[ET.Element]) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def _trunc(s: Optional[str], n: int) -> Optional[str]:
    if not s:
        return None
    return s[:n]


def _int(s: Optional[str], default: int = 0) -> int:
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def _now() -> datetime:
    # UTC timezone-aware then made naive: keeps exactly the stored format (no
    # offset) while avoiding datetime.utcnow() (deprecated).
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─── Repository / file retrieval ──────────────────────────────────────────────

def download_oval_repo(dest: str) -> str:
    """Shallow clone of the CIS OVALRepo repository (git). Returns the local path."""
    if os.path.isdir(os.path.join(dest, "repository")):
        log(MODULE, f"Repository already present: {dest}")
        return dest
    if shutil.which("git") is None:
        raise RuntimeError(
            "git not found. Install git, or clone "
            f"{OVAL_REPO_GIT} manually and use --repo <path>."
        )
    log(MODULE, f"Shallow-cloning {OVAL_REPO_GIT} → {dest}")
    subprocess.run(
        ["git", "clone", "--depth", "1", OVAL_REPO_GIT, dest],
        check=True,
    )
    log(MODULE, "Clone finished.")
    return dest


def _repository_root(repo_path: str) -> str:
    """Return the 'repository' folder from a repo path or a direct path."""
    cand = os.path.join(repo_path, "repository")
    if os.path.isdir(cand):
        return cand
    return repo_path  # the user may have pointed directly at repository/


def _iter_xml_files(base: str) -> Iterator[str]:
    """Recursively list the .xml files of a directory."""
    if not os.path.isdir(base):
        return
    for root, _dirs, files in os.walk(base):
        for f in files:
            if f.endswith(".xml"):
                yield os.path.join(root, f)


# ─── Enumerations & lookups (get_or_create) ───────────────────────────────────

# In-memory cache of "get-or-create" lookups: (kind, value) → id.
# Avoids thousands of redundant SELECT/flush calls on the small tables.
_lookup_cache: dict = {}


def _gc(cache_kind, session, model_cls, filter_col: str, value, id_attr: str,
        create_kwargs: dict):
    """Generic get-or-create with in-memory cache. Returns the id."""
    ck = (cache_kind, value)
    hit = _lookup_cache.get(ck)
    if hit is not None:
        return hit
    row = session.query(model_cls).filter_by(**{filter_col: value}).first()
    if row is None:
        row = model_cls(**{filter_col: value, **create_kwargs})
        session.add(row)
        session.flush()
    rid = getattr(row, id_attr)
    _lookup_cache[ck] = rid
    return rid


def _class_enum(s, value: str, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OVALCLASSENUMERATION
    return _gc("class", s, OVALCLASSENUMERATION, "ClassValue", value,
               "OVALClassEnumerationID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _operator_enum(s, value: str, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OPERATORENUMERATION
    return _gc("op", s, OPERATORENUMERATION, "OperatorValue", value,
               "OperatorEnumerationID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _namespace(s, name: str, vocab_id: int) -> Optional[int]:
    if not name:
        return None
    from xorcism_python.models.xoval import OVALNAMESPACE
    return _gc("ns", s, OVALNAMESPACE, "OVALNamespaceName", name,
               "OVALNamespaceID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _test_datatype(s, name: str, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OVALTESTDATATYPE
    return _gc("tdt", s, OVALTESTDATATYPE, "OVALTestDataTypeName", name,
               "OVALTestDataTypeID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _object_datatype(s, name: str, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OVALOBJECTDATATYPE
    return _gc("odt", s, OVALOBJECTDATATYPE, "OVALObjectDataTypeName", name,
               "OVALObjectDataTypeID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _state_type(s, name: str, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OVALSTATETYPE
    return _gc("stt", s, OVALSTATETYPE, "OVALStateTypeName", name,
               "OVALStateTypeID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _variable_datatype(s, name: str, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OVALVARIABLEDATATYPE
    return _gc("vdt", s, OVALVARIABLEDATATYPE, "OVALVariableDataTypeName", name,
               "OVALVariableDataTypeID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _variable_type(s, name: str, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OVALVARIABLETYPE
    return _gc("vt", s, OVALVARIABLETYPE, "OVALVariableTypeName", name,
               "OVALVariableTypeID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _existence_enum(xs, value: str, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import EXISTENCEENUMERATION
    return _gc("exist", xs, EXISTENCEENUMERATION, "ExistenceValue", value,
               "ExistenceEnumerationID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _check_enum(xs, value: str, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import CHECKENUMERATION
    return _gc("check", xs, CHECKENUMERATION, "EnumerationValue", value,
               "CheckEnumerationID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


# ─── Lookups in XORCISM / XVULNERABILITY ──────────────────────────────────────

def _osfamily(xs, name: str, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import OSFAMILY
    return _gc("osfam", xs, OSFAMILY, "FamilyName", _trunc(name, 255),
               "OSFamilyID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _platform(xs, name: str, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import PLATFORM
    return _gc("plat", xs, PLATFORM, "PlatformName", _trunc(name, 255),
               "PlatformID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _product(xs, name: str, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import PRODUCT
    return _gc("prod", xs, PRODUCT, "ProductName", _trunc(name, 255),
               "ProductID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _cpe(xs, cpe_name: str, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import CPE
    return _gc("cpe", xs, CPE, "CPEName", _trunc(cpe_name, 255),
               "CPEID", {"VocabularyID": vocab_id, "CreatedDate": _now()})


def _reference(xs, ref_id: str, source: str, url: str, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import REFERENCE
    ck = ("ref", source, ref_id)
    hit = _lookup_cache.get(ck)
    if hit is not None:
        return hit
    row = xs.query(REFERENCE).filter_by(Source=source, ReferenceTitle=ref_id).first()
    if row is None:
        row = REFERENCE(
            Source=_trunc(source, 100),
            ReferenceTitle=_trunc(ref_id, 255),
            ReferenceURL=_trunc(url, 1000),
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        xs.add(row); xs.flush()
    _lookup_cache[ck] = row.ReferenceID
    return row.ReferenceID


def _cce(xs, cce_id: str, vocab_id: int) -> str:
    """CCE has a textual PK (CCEID); we use it as the identifier."""
    from xorcism_python.models.xorcism import CCE
    ck = ("cce", cce_id)
    if ck in _lookup_cache:
        return _lookup_cache[ck]
    row = xs.query(CCE).filter_by(CCEID=cce_id).first()
    if row is None:
        row = CCE(CCEID=cce_id, cce_id=cce_id, VocabularyID=vocab_id, CreatedDate=_now())
        xs.add(row); xs.flush()
    _lookup_cache[ck] = row.CCEID
    return row.CCEID


def _vulnerability(vs, cve_id: str, vocab_id: int) -> int:
    from xorcism_python.models.xvulnerability import VULNERABILITY
    return _gc("vuln", vs, VULNERABILITY, "VULReferentialID", _trunc(cve_id, 50),
               "VulnerabilityID", {"VULReferential": "CVE", "VocabularyID": vocab_id,
                                   "CreatedDate": _now()})


# ─── Stubs (forward references) ───────────────────────────────────────────────

def _ensure_test_stub(s, pattern: str, comment: str, negate: bool, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OVALTEST
    row = s.query(OVALTEST).filter_by(OVALTestIDPattern=pattern).first()
    if row is None:
        row = OVALTEST(
            OVALTestIDPattern=pattern,
            OVALTestVersion=0,                    # NOT NULL — enriched by the tests
            comment=_trunc(comment, 1000) or "",  # NOT NULL
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        s.add(row); s.flush()
    return row.OVALTestID


def _ensure_definition_stub(s, pattern: str, vocab_id: int) -> int:
    from xorcism_python.models.xoval import OVALDEFINITION
    row = s.query(OVALDEFINITION).filter_by(OVALDefinitionIDPattern=pattern).first()
    if row is None:
        row = OVALDEFINITION(
            OVALDefinitionIDPattern=pattern,
            OVALDefinitionVersion=0,              # NOT NULL
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        s.add(row); s.flush()
    return row.OVALDefinitionID


# ─── Database optimisations (PRAGMA + indexes) ───────────────────────────────

_INDEX_SQL = {
    "XOVAL": [
        'CREATE INDEX IF NOT EXISTS ix_ovaldef_pat ON OVALDEFINITION(OVALDefinitionIDPattern)',
        'CREATE INDEX IF NOT EXISTS ix_ovaltest_pat ON OVALTEST(OVALTestIDPattern)',
        'CREATE INDEX IF NOT EXISTS ix_ovalobj_pat ON OVALOBJECT(OVALObjectIDPattern)',
        'CREATE INDEX IF NOT EXISTS ix_ovalstate_pat ON OVALSTATE(OVALStateIDPattern)',
        'CREATE INDEX IF NOT EXISTS ix_ovalvar_pat ON OVALVARIABLE(OVALVariableIDPattern)',
        'CREATE INDEX IF NOT EXISTS ix_ovalns_name ON OVALNAMESPACE(OVALNamespaceName)',
        'CREATE INDEX IF NOT EXISTS ix_ovalcc_crit ON OVALCRITERIACRITERION(OVALCriteriaID, OVALTestID)',
        'CREATE INDEX IF NOT EXISTS ix_ovalced_crit ON OVALCRITERIAEXTENDDEFINITION(OVALCriteriaID, OVALDefinitionID)',
        'CREATE INDEX IF NOT EXISTS ix_ovalobjfortest ON OVALOBJECTFOROVALTEST(OVALTestID, OVALObjectID)',
        'CREATE INDEX IF NOT EXISTS ix_ovalstatefortest ON OVALSTATEFOROVALTEST(OVALTestID, OVALStateID)',
        'CREATE INDEX IF NOT EXISTS ix_ovaldeffam ON OVALDEFINITIONFAMILY(OVALDefinitionID)',
        'CREATE INDEX IF NOT EXISTS ix_ovaldefplat ON OVALDEFINITIONPLATFORM(OVALDefinitionID)',
        'CREATE INDEX IF NOT EXISTS ix_ovaldefprod ON OVALDEFINITIONPRODUCT(OVALDefinitionID)',
        'CREATE INDEX IF NOT EXISTS ix_ovaldefvuln ON OVALDEFINITIONVULNERABILITY(OVALDefinitionID)',
        'CREATE INDEX IF NOT EXISTS ix_ovaldefcpe ON OVALDEFINITIONCPE(OVALDefinitionID)',
        'CREATE INDEX IF NOT EXISTS ix_ovaldefcce ON OVALDEFINITIONCCE(OVALDefinitionID)',
        'CREATE INDEX IF NOT EXISTS ix_ovaldefref ON OVALDEFINITIONREFERENCE(OVALDefinitionID)',
    ],
    "XORCISM": [
        'CREATE INDEX IF NOT EXISTS ix_osfam_name ON OSFAMILY(FamilyName)',
        'CREATE INDEX IF NOT EXISTS ix_plat_name ON PLATFORM(PlatformName)',
        'CREATE INDEX IF NOT EXISTS ix_prod_name ON PRODUCT(ProductName)',
        'CREATE INDEX IF NOT EXISTS ix_cpe_name ON CPE(CPEName)',
        'CREATE INDEX IF NOT EXISTS ix_ref_src ON REFERENCE(Source, ReferenceTitle)',
        'CREATE INDEX IF NOT EXISTS ix_exist_val ON EXISTENCEENUMERATION(ExistenceValue)',
        'CREATE INDEX IF NOT EXISTS ix_check_val ON CHECKENUMERATION(EnumerationValue)',
    ],
    "XVULNERABILITY": [
        'CREATE INDEX IF NOT EXISTS ix_vuln_refid ON VULNERABILITY(VULReferentialID)',
    ],
}

_tuned_engines: set = set()


def _tune_engine(dbname: str) -> None:
    """Apply speed-up PRAGMAs to every new connection of the engine."""
    if dbname in _tuned_engines:
        return
    eng = get_engine(dbname)

    @event.listens_for(eng, "connect")
    def _set_pragmas(dbapi_con, _rec):  # noqa: ANN001
        cur = dbapi_con.cursor()
        # Connection-level PRAGMAs (no exclusive lock required) → compatible
        # with the web server which keeps the databases open (WAL).
        # NB: we do NOT change journal_mode (that would require exclusive access).
        cur.execute("PRAGMA busy_timeout=30000")  # wait rather than fail
        cur.execute("PRAGMA synchronous=OFF")     # import is re-runnable/idempotent
        cur.execute("PRAGMA temp_store=MEMORY")
        cur.execute("PRAGMA cache_size=-200000")  # ~200 MB of page cache
        cur.close()

    _tuned_engines.add(dbname)


def _create_indexes(session, dbname: str) -> None:
    """Create the indexes that speed up the idempotency lookups (once)."""
    for sql in _INDEX_SQL.get(dbname, []):
        try:
            session.execute(text(sql))
        except Exception as e:  # table may be absent
            log(MODULE, f"  index skipped ({dbname}): {e}")
    session.commit()


def _reset_caches() -> None:
    _lookup_cache.clear()
    _pk_counters.clear()


# ─── VOCABULARY ───────────────────────────────────────────────────────────────

def _setup_vocabulary(xs) -> int:
    from xorcism_python.models.xorcism import VOCABULARY
    vocab = xs.query(VOCABULARY).filter_by(
        VocabularyName="OVAL", VocabularyVersion=OVAL_VERSION
    ).first()
    if vocab is None:
        vocab = VOCABULARY(
            VocabularyName="OVAL",
            VocabularyVersion=OVAL_VERSION,
            CreatedDate=_now(),
        )
        xs.add(vocab); xs.flush()
        log(MODULE, f"VOCABULARY OVAL created (ID={vocab.VocabularyID})")
    return vocab.VocabularyID


# ─── Import of ONE element ────────────────────────────────────────────────────

def _import_one_definition(dnode, s, xs, vs, vocab_id: int) -> None:
    from xorcism_python.models.xoval import (
        OVALDEFINITION,
        OVALDEFINITIONFAMILY, OVALDEFINITIONPLATFORM, OVALDEFINITIONPRODUCT,
        OVALDEFINITIONVULNERABILITY, OVALDEFINITIONCPE, OVALDEFINITIONCCE,
        OVALDEFINITIONREFERENCE,
    )

    pattern = dnode.get("id", "")
    version = _int(dnode.get("version"))
    cls = dnode.get("class", "")
    deprecated = dnode.get("deprecated", "").lower() == "true"

    class_enum_id = _class_enum(s, cls, vocab_id) if cls else None

    defn = s.query(OVALDEFINITION).filter_by(
        OVALDefinitionIDPattern=pattern, OVALDefinitionVersion=version
    ).first()
    if defn is None:
        # may exist as a stub (version 0) created by an extend_definition
        defn = s.query(OVALDEFINITION).filter_by(
            OVALDefinitionIDPattern=pattern
        ).first()
    if defn is None:
        defn = OVALDEFINITION(
            OVALDefinitionIDPattern=pattern,
            OVALDefinitionVersion=version,
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        s.add(defn)
    defn.OVALDefinitionVersion = version
    defn.OVALClassEnumerationID = class_enum_id
    defn.deprecated = deprecated
    defn.VocabularyID = vocab_id
    # Store the raw definition XML in the BLOB so the app reads it from the DB (not local files).
    try:
        defn.BLOB = ET.tostring(dnode, encoding="unicode")
    except Exception:  # noqa: BLE001 — serialization is best-effort; metadata import still proceeds
        pass
    s.flush()
    def_id = defn.OVALDefinitionID

    # — metadata —
    meta = dnode.find(_qd("metadata"))
    if meta is not None:
        title = _text(meta.find(_qd("title")))
        if title:
            defn.OVALDefinitionTitle = _trunc(title, 1000)
        desc = _text(meta.find(_qd("description")))
        if desc:
            defn.OVALDefinitionDescription = _trunc(desc, 4000)

        # affected → family / platform / product
        for affected in meta.findall(_qd("affected")):
            family = affected.get("family", "")
            if family:
                fam_id = _osfamily(xs, family, vocab_id)
                if s.query(OVALDEFINITIONFAMILY).filter_by(
                    OVALDefinitionID=def_id, OSFamilyID=fam_id
                ).first() is None:
                    s.add(OVALDEFINITIONFAMILY(
                        OVALDefinitionID=def_id, OSFamilyID=fam_id,
                        VocabularyID=vocab_id, CreatedDate=_now(),
                    ))
            for plat in affected.findall(_qd("platform")):
                pname = _text(plat)
                if not pname:
                    continue
                plat_id = _platform(xs, pname, vocab_id)
                if s.query(OVALDEFINITIONPLATFORM).filter_by(
                    OVALDefinitionID=def_id, PlatformID=plat_id
                ).first() is None:
                    s.add(OVALDEFINITIONPLATFORM(
                        OVALDefinitionID=def_id, PlatformID=plat_id,
                        VocabularyID=vocab_id, CreatedDate=_now(),
                    ))
            for prod in affected.findall(_qd("product")):
                prname = _text(prod)
                if not prname:
                    continue
                prod_id = _product(xs, prname, vocab_id)
                if s.query(OVALDEFINITIONPRODUCT).filter_by(
                    OVALDefinitionID=def_id, ProductID=prod_id
                ).first() is None:
                    s.add(OVALDEFINITIONPRODUCT(
                        OVALDefinitionID=def_id, ProductID=prod_id,
                        VocabularyID=vocab_id, CreatedDate=_now(),
                    ))

        # reference → CVE / CPE / CCE / other
        for ref in meta.findall(_qd("reference")):
            source = ref.get("source", "")
            ref_id = ref.get("ref_id", "")
            ref_url = ref.get("ref_url", "")
            if not ref_id:
                continue
            src_up = source.upper()
            if src_up == "CVE":
                vuln_id = _vulnerability(vs, ref_id, vocab_id)
                if s.query(OVALDEFINITIONVULNERABILITY).filter_by(
                    OVALDefinitionID=def_id, VulnerabilityID=vuln_id
                ).first() is None:
                    s.add(OVALDEFINITIONVULNERABILITY(
                        OVALDefinitionID=def_id, VulnerabilityID=vuln_id,
                        OVALDefinitionVulnerabilityRelationship="affected",
                        VocabularyID=vocab_id, CreatedDate=_now(),
                    ))
            elif src_up == "CPE":
                cpe_id = _cpe(xs, ref_id, vocab_id)
                if s.query(OVALDEFINITIONCPE).filter_by(
                    OVALDefinitionID=def_id, CPEID=cpe_id
                ).first() is None:
                    s.add(OVALDEFINITIONCPE(
                        OVALDefinitionID=def_id, CPEID=cpe_id,
                        OVALDefinitionCPERelationship="affected",
                        VocabularyID=vocab_id, CreatedDate=_now(),
                    ))
            elif src_up == "CCE":
                cce_id = _cce(xs, ref_id, vocab_id)
                if s.query(OVALDEFINITIONCCE).filter_by(
                    OVALDefinitionID=def_id, CCEID=cce_id
                ).first() is None:
                    s.add(OVALDEFINITIONCCE(
                        OVALDefinitionID=def_id, CCEID=cce_id,
                        VocabularyID=vocab_id, CreatedDate=_now(),
                    ))
            else:
                rid = _reference(xs, ref_id, source, ref_url, vocab_id)
                if s.query(OVALDEFINITIONREFERENCE).filter_by(
                    OVALDefinitionID=def_id, ReferenceID=rid
                ).first() is None:
                    s.add(OVALDEFINITIONREFERENCE(
                        OVALDefinitionID=def_id, ReferenceID=rid,
                        VocabularyID=vocab_id, CreatedDate=_now(),
                    ))

        # oval_repository → status
        repo = meta.find(_qd("oval_repository"))
        if repo is not None:
            status = _text(repo.find(_qd("status")))
            if status:
                defn.StatusName = _trunc(status, 50)

    # — criteria (main tree) —
    crit = dnode.find(_qd("criteria"))
    if crit is not None:
        criteria_id = _build_criteria(s, crit, vocab_id)
        defn.OVALCriteriaID = criteria_id

    s.flush()


def _build_criteria(s, crit_node, vocab_id: int) -> int:
    """Create an OVALCRITERIA and its content (criterion / extend_definition /
    recursive sub-criteria). Returns the OVALCriteriaID."""
    from xorcism_python.models.xoval import (
        OVALCRITERIA, OVALCRITERIACRITERION, OVALCRITERIAEXTENDDEFINITION,
        OVALCRITERIAFOROVALCRITERIA,
    )

    operator = crit_node.get("operator", "AND")
    op_id = _operator_enum(s, operator, vocab_id)
    negate = crit_node.get("negate", "").lower() == "true"
    comment = crit_node.get("comment", "")

    criteria = OVALCRITERIA(
        OperatorEnumerationID=op_id,
        negate=negate,
        comment=_trunc(comment, 1000),
        VocabularyID=vocab_id,
        CreatedDate=_now(),
    )
    s.add(criteria); s.flush()
    criteria_id = criteria.OVALCriteriaID

    rank = 0
    for child in list(crit_node):
        name = _local(child.tag)
        if name == "criteria":
            rank += 1
            sub_id = _build_criteria(s, child, vocab_id)
            s.add(OVALCRITERIAFOROVALCRITERIA(
                OVALCriteriaRefID=criteria_id,
                OVALCriteriaSubjectID=sub_id,
                CriteriaRank=rank,
                RelationshipName="HasMember",
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))
        elif name == "criterion":
            test_ref = child.get("test_ref", "")
            if not RE_TST.match(test_ref or ""):
                continue
            cneg = child.get("negate", "").lower() == "true"
            ccomment = child.get("comment", "")
            test_id = _ensure_test_stub(s, test_ref, ccomment, cneg, vocab_id)
            if s.query(OVALCRITERIACRITERION).filter_by(
                OVALCriteriaID=criteria_id, OVALTestID=test_id
            ).first() is None:
                s.add(OVALCRITERIACRITERION(
                    OVALCriteriaID=criteria_id,
                    OVALTestID=test_id,
                    negate=cneg,
                    comment=_trunc(ccomment, 1000),
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                ))
        elif name == "extend_definition":
            def_ref = child.get("definition_ref", "")
            if not def_ref:
                continue
            cneg = child.get("negate", "").lower() == "true"
            ccomment = child.get("comment", "")
            ext_def_id = _ensure_definition_stub(s, def_ref, vocab_id)
            if s.query(OVALCRITERIAEXTENDDEFINITION).filter_by(
                OVALCriteriaID=criteria_id, OVALDefinitionID=ext_def_id
            ).first() is None:
                s.add(OVALCRITERIAEXTENDDEFINITION(
                    OVALCriteriaID=criteria_id,
                    OVALDefinitionID=ext_def_id,
                    negate=cneg,
                    comment=_trunc(ccomment, 1000),
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                ))

    s.flush()
    return criteria_id


def _import_one_test(tnode, s, xs, vocab_id: int) -> None:
    from xorcism_python.models.xoval import (
        OVALTEST, OVALOBJECT, OVALSTATE, OVALOBJECTFOROVALTEST, OVALSTATEFOROVALTEST,
    )

    pattern = tnode.get("id", "")
    version = _int(tnode.get("version"))
    datatype_name = _local(tnode.tag)  # registry_test, file_test…
    ns_short = _ns_short(tnode.tag)

    test = s.query(OVALTEST).filter_by(
        OVALTestIDPattern=pattern, OVALTestVersion=version
    ).first()
    if test is None:
        # stub (version 0) possibly created by the criteria
        test = s.query(OVALTEST).filter_by(OVALTestIDPattern=pattern).first()
    if test is None:
        test = OVALTEST(
            OVALTestIDPattern=pattern, OVALTestVersion=version,
            VocabularyID=vocab_id, CreatedDate=_now(),
        )
        s.add(test)

    test.OVALTestVersion = version
    test.OVALTestDataTypeID = _test_datatype(s, datatype_name, vocab_id)
    test.OVALNamespaceID = _namespace(s, ns_short, vocab_id)
    test.comment = _trunc(tnode.get("comment", ""), 1000) or ""
    test.deprecated = tnode.get("deprecated", "").lower() == "true"

    existence = tnode.get("check_existence", "at_least_one_exists")
    test.ExistenceEnumerationID = _existence_enum(xs, existence, vocab_id)
    check = tnode.get("check", "at_least_one_exists")
    test.CheckEnumerationID = _check_enum(xs, check, vocab_id)
    state_op = tnode.get("state_operator")
    if state_op:
        test.OperatorEnumerationID = _operator_enum(s, state_op, vocab_id)
    test.VocabularyID = vocab_id
    s.flush()
    test_id = test.OVALTestID

    # object_ref / state_ref (children of the test)
    for child in list(tnode):
        cname = _local(child.tag)
        if cname == "object":
            obj_ref = child.get("object_ref", "")
            if not obj_ref:
                continue
            obj = s.query(OVALOBJECT).filter_by(OVALObjectIDPattern=obj_ref).first()
            if obj is None:
                obj = OVALOBJECT(OVALObjectIDPattern=obj_ref, OVALObjectVersion=0,
                                 comment="", VocabularyID=vocab_id, CreatedDate=_now())
                s.add(obj); s.flush()
            if s.query(OVALOBJECTFOROVALTEST).filter_by(
                OVALTestID=test_id, OVALObjectID=obj.OVALObjectID
            ).first() is None:
                s.add(OVALOBJECTFOROVALTEST(
                    OVALTestID=test_id, OVALObjectID=obj.OVALObjectID,
                    VocabularyID=vocab_id, CreatedDate=_now(),
                ))
        elif cname == "state":
            st_ref = child.get("state_ref", "")
            if not st_ref:
                continue
            st = s.query(OVALSTATE).filter_by(OVALStateIDPattern=st_ref).first()
            if st is None:
                st = OVALSTATE(OVALStateIDPattern=st_ref, comment="",
                               VocabularyID=vocab_id, CreatedDate=_now())
                s.add(st); s.flush()
            if s.query(OVALSTATEFOROVALTEST).filter_by(
                OVALTestID=test_id, OVALStateID=st.OVALStateID
            ).first() is None:
                s.add(OVALSTATEFOROVALTEST(
                    OVALTestID=test_id, OVALStateID=st.OVALStateID,
                    VocabularyID=vocab_id, CreatedDate=_now(),
                ))


def _import_one_object(onode, s, vocab_id: int) -> None:
    from xorcism_python.models.xoval import OVALOBJECT

    pattern = onode.get("id", "")
    version = _int(onode.get("version"))
    datatype_name = _local(onode.tag)
    ns_short = _ns_short(onode.tag)

    obj = s.query(OVALOBJECT).filter_by(OVALObjectIDPattern=pattern).first()
    if obj is None:
        obj = OVALOBJECT(OVALObjectIDPattern=pattern, OVALObjectVersion=0,
                         comment="", VocabularyID=vocab_id, CreatedDate=_now())
        s.add(obj)
    obj.OVALObjectVersion = version
    obj.OVALObjectDataTypeID = _object_datatype(s, datatype_name, vocab_id)
    obj.OVALNamespaceID = _namespace(s, ns_short, vocab_id)
    obj.comment = _trunc(onode.get("comment", ""), 1000) or ""
    obj.deprecated = onode.get("deprecated", "").lower() == "true"
    obj.VocabularyID = vocab_id
    s.flush()


def _import_one_state(snode, s, vocab_id: int) -> None:
    from xorcism_python.models.xoval import OVALSTATE

    pattern = snode.get("id", "")
    version = _int(snode.get("version"))
    type_name = _local(snode.tag)
    ns_short = _ns_short(snode.tag)

    st = s.query(OVALSTATE).filter_by(
        OVALStateIDPattern=pattern, OVALStateVersion=version
    ).first()
    if st is None:
        st = s.query(OVALSTATE).filter_by(OVALStateIDPattern=pattern).first()
    if st is None:
        st = OVALSTATE(OVALStateIDPattern=pattern, comment="",
                       VocabularyID=vocab_id, CreatedDate=_now())
        s.add(st)
    st.OVALStateVersion = version
    st.OVALStateTypeID = _state_type(s, type_name, vocab_id)
    st.OVALNamespaceID = _namespace(s, ns_short, vocab_id)
    st.comment = _trunc(snode.get("comment", ""), 1000) or ""
    st.deprecated = snode.get("deprecated", "").lower() == "true"
    operator = snode.get("operator")
    if operator:
        st.OperatorEnumerationID = _operator_enum(s, operator, vocab_id)
    st.VocabularyID = vocab_id
    s.flush()


def _import_one_variable(vnode, s, vocab_id: int) -> None:
    from xorcism_python.models.xoval import OVALVARIABLE

    pattern = vnode.get("id", "")
    version = _int(vnode.get("version"))
    var_type_name = _local(vnode.tag)  # local_variable, external_variable…
    datatype_name = vnode.get("datatype", "string")
    ns_short = _ns_short(vnode.tag)

    var = s.query(OVALVARIABLE).filter_by(OVALVariableIDPattern=pattern).first()
    if var is None:
        var = OVALVARIABLE(OVALVariableIDPattern=pattern, OVALVariableVersion=0,
                           comment="", VocabularyID=vocab_id, CreatedDate=_now())
        s.add(var)
    var.OVALVariableVersion = version
    var.OVALVariableDataTypeID = _variable_datatype(s, datatype_name, vocab_id)
    var.OVALVariableTypeID = _variable_type(s, var_type_name, vocab_id)
    var.OVALNamespaceID = _namespace(s, ns_short, vocab_id)
    var.comment = _trunc(vnode.get("comment", ""), 1000) or ""
    var.deprecated = vnode.get("deprecated", "").lower() == "true"
    var.VocabularyID = vocab_id
    s.flush()


# ─── Mode 1: OVALRepo repository (individual files) ───────────────────────────

# Expected root local-name per element type
_ROOT_LOCAL = {
    "definitions": ("definition",),
    "tests": None,       # any *_test
    "objects": None,     # any *_object
    "states": None,      # any *_state
    "variables": None,   # *_variable
}


def _valid_root(subdir: str, local_name: str) -> bool:
    if subdir == "definitions":
        return local_name == "definition"
    if subdir == "tests":
        return local_name.endswith("_test")
    if subdir == "objects":
        return local_name.endswith("_object")
    if subdir == "states":
        return local_name.endswith("_state")
    if subdir == "variables":
        return local_name.endswith("_variable") or local_name in (
            "local_variable", "external_variable", "constant_variable",
        )
    return False


def parse_oval_repo(repo_path: str) -> None:
    """Import from the CIS OVALRepo repository tree (separate files)."""
    repository = _repository_root(repo_path)
    log(MODULE, "WARNING: This can take hours!")
    log(MODULE, f"Importing from repository: {repository}")

    # Optimisations: speed-up PRAGMAs + in-memory caches
    _reset_caches()
    for _db in ("XOVAL", "XORCISM", "XVULNERABILITY"):
        _tune_engine(_db)

    with session_scope("XORCISM") as xs:
        vocab_id = _setup_vocabulary(xs)
        xs.commit()

    with session_scope("XOVAL") as s, \
         session_scope("XORCISM") as xs, \
         session_scope("XVULNERABILITY") as vs:

        # Indexes speeding up the idempotency lookups (created once)
        _create_indexes(s, "XOVAL")
        _create_indexes(xs, "XORCISM")
        _create_indexes(vs, "XVULNERABILITY")

        for subdir in REPO_SUBDIRS:
            base = os.path.join(repository, subdir)
            if not os.path.isdir(base):
                log(MODULE, f"  (missing) {base}")
                continue
            log(MODULE, f"Importing {subdir}…")
            count = 0
            errors = 0
            for path in _iter_xml_files(base):
                try:
                    node = ET.parse(path).getroot()
                except ET.ParseError as e:
                    errors += 1
                    log(MODULE, f"  invalid XML skipped: {path} ({e})")
                    continue

                local = _local(node.tag)
                if not _valid_root(subdir, local):
                    continue

                if subdir == "definitions":
                    _import_one_definition(node, s, xs, vs, vocab_id)
                elif subdir == "tests":
                    _import_one_test(node, s, xs, vocab_id)
                elif subdir == "objects":
                    _import_one_object(node, s, vocab_id)
                elif subdir == "states":
                    _import_one_state(node, s, vocab_id)
                elif subdir == "variables":
                    _import_one_variable(node, s, vocab_id)

                count += 1
                if count % 200 == 0:
                    s.commit(); xs.commit(); vs.commit()
                    log(MODULE, f"  {subdir}: {count} files…")

            s.commit(); xs.commit(); vs.commit()
            log(MODULE, f"{subdir}: {count} imported ({errors} XML errors).")

    log(MODULE, "OVAL import (repository) finished.")


# ─── Mode 2: consolidated oval.xml file (old format) ──────────────────────────

def parse_oval_xml(xml_path: str) -> None:
    log(MODULE, "WARNING: This can take hours!")
    log(MODULE, f"Parsing {xml_path}")
    root = ET.parse(xml_path).getroot()

    _reset_caches()
    for _db in ("XOVAL", "XORCISM", "XVULNERABILITY"):
        _tune_engine(_db)

    with session_scope("XORCISM") as xs:
        vocab_id = _setup_vocabulary(xs)
        xs.commit()

    with session_scope("XOVAL") as s, \
         session_scope("XORCISM") as xs, \
         session_scope("XVULNERABILITY") as vs:

        _create_indexes(s, "XOVAL")
        _create_indexes(xs, "XORCISM")
        _create_indexes(vs, "XVULNERABILITY")

        # definitions
        cont = root.find(_qd("definitions"))
        defs = cont.findall(_qd("definition")) if cont is not None else []
        log(MODULE, f"Definitions found: {len(defs)}")
        for i, d in enumerate(defs):
            _import_one_definition(d, s, xs, vs, vocab_id)
            if (i + 1) % 50 == 0:
                s.commit(); xs.commit(); vs.commit()
        s.commit(); xs.commit(); vs.commit()
        log(MODULE, "Definitions imported.")

        # tests
        cont = root.find(_qd("tests"))
        tests = list(cont) if cont is not None else []
        log(MODULE, f"Tests found: {len(tests)}")
        for i, t in enumerate(tests):
            _import_one_test(t, s, xs, vocab_id)
            if (i + 1) % 100 == 0:
                s.commit(); xs.commit()
        s.commit(); xs.commit()
        log(MODULE, "Tests imported.")

        # objects
        cont = root.find(_qd("objects"))
        objs = list(cont) if cont is not None else []
        log(MODULE, f"Objects found: {len(objs)}")
        for i, o in enumerate(objs):
            _import_one_object(o, s, vocab_id)
            if (i + 1) % 200 == 0:
                s.commit()
        s.commit()
        log(MODULE, "Objects imported.")

        # states
        cont = root.find(_qd("states"))
        states = list(cont) if cont is not None else []
        log(MODULE, f"States found: {len(states)}")
        for i, st in enumerate(states):
            _import_one_state(st, s, vocab_id)
            if (i + 1) % 200 == 0:
                s.commit()
        s.commit()
        log(MODULE, "States imported.")

        # variables
        cont = root.find(_qd("variables"))
        variables = list(cont) if cont is not None else []
        log(MODULE, f"Variables found: {len(variables)}")
        for i, v in enumerate(variables):
            _import_one_variable(v, s, vocab_id)
            if (i + 1) % 200 == 0:
                s.commit()
        s.commit()
        log(MODULE, "Variables imported.")

    log(MODULE, "OVAL import (file) finished.")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import OVAL into XOVAL.db (CIS OVALRepo repository or single file)"
    )
    parser.add_argument(
        "--repo",
        help="Path to a local clone of CISecurity/OVALRepo "
             "(folder containing repository/).",
    )
    parser.add_argument(
        "--download", action="store_true",
        help="Clone (git, --depth 1) the OVALRepo repository then import it.",
    )
    parser.add_argument(
        "--dest", default="OVALRepo",
        help="Destination folder of the clone (default: ./OVALRepo).",
    )
    parser.add_argument(
        "--xml",
        help="Old format: path to a consolidated oval.xml file.",
    )
    args = parser.parse_args()

    # Heads-up: a full OVAL import processes tens of thousands of records.
    log(MODULE, "WARNING: This can take hours!")

    if args.xml:
        parse_oval_xml(args.xml)
        return

    repo_path = args.repo
    if args.download or not repo_path:
        repo_path = download_oval_repo(args.dest)

    parse_oval_repo(repo_path)


if __name__ == "__main__":
    main()
