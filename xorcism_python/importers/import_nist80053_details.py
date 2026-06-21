"""
import_nist80053_details.py - Enriches the NIST SP 800-53 Rev 5 controls already in
XORCISM.CONTROL (VocabularyID = 7) with their full text from the OSCAL catalog:
  Statement        - the control statement (lettered/numbered items flattened to readable text)
  Guidance         - the discussion / supplemental guidance
  Params           - the organization-defined parameters (ODPs), one per line
  RelatedControls  - comma-separated related-control refs (from OSCAL "related" links)

Source: the local OSCAL catalog already used by import_nist800-53.py
  resources/NIST_SP-800-53_rev5_catalog.json
(no network needed). Idempotent: every run overwrites the four CONTROL columns for VocabularyID=7,
matching on CONTROL.NIST (e.g. "AC-2(1)"). The columns are created if missing.

Usage:
    python import_nist80053_details.py [--json path.json]
"""

import argparse
import json
import os
import sys

from sqlalchemy import inspect, text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportNIST80053Details"
VOCAB_ID = 7
DEFAULT_JSON = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "resources", "NIST_SP-800-53_rev5_catalog.json",
)
DETAIL_COLS = ("Statement", "Guidance", "Params", "RelatedControls")


def to_nist_ref(oscal_id: str) -> str:
    """ 'ac-1' -> 'AC-1'; 'ac-2.1' -> 'AC-2(1)' (NIST notation). """
    fam, _, rest = oscal_id.partition("-")
    fam = fam.upper()
    if "." in rest:
        base, enh = rest.split(".", 1)
        return f"{fam}-{base}({enh})"
    return f"{fam}-{rest}"


def _iter_controls(controls):
    for c in controls or []:
        yield c
        yield from _iter_controls(c.get("controls"))


def _part_label(part) -> str:
    for prop in part.get("props", []) or []:
        if prop.get("name") == "label":
            return str(prop.get("value", "")).strip()
    return ""


def _render(parts, depth, out) -> None:
    """Flatten a tree of OSCAL parts into indented, labelled lines."""
    for p in parts or []:
        prose = (p.get("prose") or "").strip()
        if prose:
            label = _part_label(p)
            out.append(("  " * depth) + (f"{label} " if label else "") + prose)
        _render(p.get("parts"), depth + 1, out)


def _statement(ctrl) -> str:
    for part in ctrl.get("parts", []) or []:
        if part.get("name") == "statement":
            lines = []
            if part.get("prose"):
                lines.append(part["prose"].strip())
            _render(part.get("parts"), 0, lines)
            return "\n".join(lines).strip()
    return ""


def _guidance(ctrl) -> str:
    chunks = []
    for part in ctrl.get("parts", []) or []:
        if part.get("name") in ("guidance", "supplemental_guidance"):
            lines = []
            if part.get("prose"):
                lines.append(part["prose"].strip())
            _render(part.get("parts"), 0, lines)
            chunks.append("\n".join(lines).strip())
    return "\n\n".join(c for c in chunks if c).strip()


def _params(ctrl) -> str:
    out = []
    for prm in ctrl.get("params", []) or []:
        pid = prm.get("id", "")
        label = prm.get("label")
        if not label and prm.get("select"):
            how = prm["select"].get("how-many", "one")
            choices = "; ".join(prm["select"].get("choice", []) or [])
            label = f"[{how}] {choices}" if choices else "(selection)"
        if not label and prm.get("values"):
            label = "; ".join(str(v) for v in prm["values"])
        out.append(f"{pid}: {label or '(organization-defined)'}")
    return "\n".join(out).strip()


def _related(ctrl) -> str:
    refs = []
    for ln in ctrl.get("links", []) or []:
        if ln.get("rel") == "related" and ln.get("href", "").startswith("#"):
            refs.append(to_nist_ref(ln["href"][1:]))
    # de-dup, keep order
    seen, ordered = set(), []
    for r in refs:
        if r not in seen:
            seen.add(r)
            ordered.append(r)
    return ", ".join(ordered)


def _ensure_columns(session) -> None:
    engine = session.get_bind()
    have = {c["name"] for c in inspect(engine).get_columns("CONTROL")}
    for col in DETAIL_COLS:
        if col not in have:
            session.execute(text(f'ALTER TABLE "CONTROL" ADD COLUMN "{col}" TEXT'))
            log(MODULE, f"Added CONTROL.{col}")


def run(json_path: str) -> None:
    log(MODULE, f"Reading OSCAL catalog: {json_path}")
    with open(json_path, "r", encoding="utf-8") as fh:
        catalog = json.load(fh)["catalog"]

    rows = []  # (ref, statement, guidance, params, related)
    for group in catalog.get("groups", []):
        for ctrl in _iter_controls(group.get("controls")):
            cid = ctrl.get("id")
            if not cid:
                continue
            rows.append((
                to_nist_ref(cid), _statement(ctrl), _guidance(ctrl), _params(ctrl), _related(ctrl),
            ))
    log(MODULE, f"{len(rows)} controls parsed")

    updated = 0
    with session_scope("XORCISM") as session:
        _ensure_columns(session)
        for ref, stmt, gdn, prm, rel in rows:
            res = session.execute(
                text('UPDATE "CONTROL" SET "Statement" = :s, "Guidance" = :g, "Params" = :p, '
                     '"RelatedControls" = :r WHERE "VocabularyID" = :v AND "NIST" = :ref'),
                {"s": stmt or None, "g": gdn or None, "p": prm or None, "r": rel or None, "v": VOCAB_ID, "ref": ref},
            )
            updated += res.rowcount or 0
        session.commit()
    log(MODULE, f"Done. Enriched {updated} controls with statement/guidance/params/related.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Enrich XORCISM.CONTROL 800-53 rows with OSCAL statement/guidance/params/related")
    ap.add_argument("--json", default=DEFAULT_JSON, help="Path to the OSCAL catalog JSON")
    args = ap.parse_args()
    if not os.path.exists(args.json):
        raise SystemExit(f"Catalog not found: {args.json} (run import_nist800-53.py first)")
    run(args.json)


if __name__ == "__main__":
    main()
