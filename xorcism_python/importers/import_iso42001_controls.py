"""
import_iso42001_controls.py — Imports the Annex A controls of ISO/IEC 42001:2023
(Artificial intelligence management system, AIMS) into XORCISM.CONTROL, linked to a
VOCABULARY named "ISO42001".

Annex A:2023 has 38 controls in 9 control objectives (categories):
  A.2 Policies related to AI (3) · A.3 Internal organization (2) ·
  A.4 Resources for AI systems (5) · A.5 Assessing impacts of AI systems (4) ·
  A.6 AI system life cycle (9) · A.7 Data for AI systems (5) ·
  A.8 Information for interested parties of AI systems (4) ·
  A.9 Use of AI systems (3) · A.10 Third-party and customer relationships (3)

Only the clause REFERENCE and the short factual TITLE are imported — the normative
ISO text is protected and is NOT reproduced.

Mapping (mirrors import_iso27001.py):
  ControlName        = "<ref> <title>"   (e.g. "A.2.2 AI policy")
  ISO                = "<ref>"            (e.g. "A.2.2")
  ControlDescription = category           (e.g. "Policies related to AI")
  VocabularyID       = id of the "ISO42001" VOCABULARY (get-or-created)

Idempotent: the VOCABULARY is get-or-created by name; each control is get-or-updated
by (ISO == ref AND VocabularyID == <ISO42001 vocab>).

Usage:
    python import_iso42001_controls.py
"""

import os
import sys
from datetime import datetime, timezone

from sqlalchemy import event, text, Integer, BigInteger, SmallInteger
from sqlalchemy.orm import Mapper

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportISO42001"
VOCAB_NAME = "ISO42001"
VOCAB_VERSION = "2023"
VOCAB_REFERENCE = "ISO/IEC 42001:2023"
VOCAB_DESCRIPTION = "Artificial intelligence management system (AIMS) — Annex A reference controls"

# (reference, title) by category — ISO/IEC 42001:2023 Annex A
POLICIES = [
    ("A.2.2", "AI policy"),
    ("A.2.3", "Alignment with other organizational policies"),
    ("A.2.4", "Review of the AI policy"),
]
INTERNAL_ORG = [
    ("A.3.2", "AI roles and responsibilities"),
    ("A.3.3", "Reporting of concerns"),
]
RESOURCES = [
    ("A.4.2", "Resource documentation"),
    ("A.4.3", "Data resources"),
    ("A.4.4", "Tooling resources"),
    ("A.4.5", "System and computing resources"),
    ("A.4.6", "Human resources"),
]
IMPACTS = [
    ("A.5.2", "AI system impact assessment process"),
    ("A.5.3", "Documentation of AI system impact assessments"),
    ("A.5.4", "Assessing AI system impact on individuals or groups of individuals"),
    ("A.5.5", "Assessing societal impacts of AI systems"),
]
LIFECYCLE = [
    ("A.6.1.2", "Objectives for responsible development of AI system"),
    ("A.6.1.3", "Processes for responsible AI system design and development"),
    ("A.6.2.2", "AI system requirements and specification"),
    ("A.6.2.3", "Documentation of AI system design and development"),
    ("A.6.2.4", "AI system verification and validation"),
    ("A.6.2.5", "AI system deployment"),
    ("A.6.2.6", "AI system operation and monitoring"),
    ("A.6.2.7", "AI system technical documentation"),
    ("A.6.2.8", "AI system recording of event logs"),
]
DATA = [
    ("A.7.2", "Data for development and enhancement of AI system"),
    ("A.7.3", "Acquisition of data"),
    ("A.7.4", "Quality of data for AI systems"),
    ("A.7.5", "Data provenance"),
    ("A.7.6", "Data preparation"),
]
INFORMATION = [
    ("A.8.2", "System documentation and information for users"),
    ("A.8.3", "External reporting"),
    ("A.8.4", "Communication of incidents"),
    ("A.8.5", "Information for interested parties"),
]
USE = [
    ("A.9.2", "Processes for responsible use of AI systems"),
    ("A.9.3", "Objectives for responsible use of AI system"),
    ("A.9.4", "Intended use of the AI system"),
]
THIRD_PARTY = [
    ("A.10.2", "Allocating responsibilities"),
    ("A.10.3", "Suppliers"),
    ("A.10.4", "Customers"),
]

CATEGORIES = [
    ("Policies related to AI", POLICIES),
    ("Internal organization", INTERNAL_ORG),
    ("Resources for AI systems", RESOURCES),
    ("Assessing impacts of AI systems", IMPACTS),
    ("AI system life cycle", LIFECYCLE),
    ("Data for AI systems", DATA),
    ("Information for interested parties of AI systems", INFORMATION),
    ("Use of AI systems", USE),
    ("Third-party and customer relationships", THIRD_PARTY),
]


# ─── Auto-increment of integer primary keys (cf. import_iso27001.py) ─────
_pk_counters: dict = {}
_INT_TYPES = (Integer, BigInteger, SmallInteger)


def _auto_pk(mapper, connection, target) -> None:
    pk_cols = mapper.primary_key
    if len(pk_cols) != 1:
        return
    col = pk_cols[0]
    if not isinstance(col.type, _INT_TYPES):
        return
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


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def run() -> None:
    from xorcism_python.models.xorcism import CONTROL, VOCABULARY
    created = updated = 0
    with session_scope("XORCISM") as session:
        # 1) get-or-create the "ISO42001" vocabulary
        vocab = session.query(VOCABULARY).filter_by(VocabularyName=VOCAB_NAME).first()
        if vocab is None:
            vocab = VOCABULARY(
                VocabularyName=VOCAB_NAME,
                VocabularyVersion=VOCAB_VERSION,
                VocabularyReference=VOCAB_REFERENCE,
                VocabularyDescription=VOCAB_DESCRIPTION,
                CreatedDate=_now().isoformat(),
                DateModified=_now().isoformat(),
            )
            session.add(vocab)
            session.flush()
            log(MODULE, f"VOCABULARY '{VOCAB_NAME}' created (VocabularyID={vocab.VocabularyID}).")
        vocab_id = vocab.VocabularyID

        # 2) import the Annex A controls
        for category, items in CATEGORIES:
            for ref, title in items:
                name = f"{ref} {title}"
                ctrl = session.query(CONTROL).filter_by(ISO=ref, VocabularyID=vocab_id).first()
                if ctrl is None:
                    ctrl = CONTROL(CreatedDate=_now())
                    session.add(ctrl)
                    created += 1
                else:
                    updated += 1
                ctrl.ControlName = name
                ctrl.ISO = ref
                ctrl.ControlDescription = category
                ctrl.VocabularyID = vocab_id
                session.flush()
        session.commit()
    total = sum(len(i) for _, i in CATEGORIES)
    log(MODULE, f"ISO/IEC 42001:2023 Annex A: {total} controls — {created} created, {updated} updated (VocabularyID={vocab_id}).")


if __name__ == "__main__":
    run()
