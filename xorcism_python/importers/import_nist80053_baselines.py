"""
import_nist80053_baselines.py - Tags the NIST SP 800-53 Rev 5 controls already in
XORCISM.CONTROL (VocabularyID = 7) with their security-control baseline membership:
Low / Moderate / High (SP 800-53B) and the Privacy baseline.

Source: official NIST OSCAL baseline *profiles* (public domain, US government work):
  .../SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline_profile.json
  .../SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json
  .../SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json
  .../SP800-53/rev5/json/NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json
Each profile enumerates the control IDs (incl. enhancements) it selects. We download them into
resources/ (unless already present or --dir is given) and set the matching CONTROL.Baseline* flag.

Mapping: CONTROL.BaselineLow / BaselineModerate / BaselineHigh / BaselinePrivacy = 1 for members,
0 otherwise (the columns are created if missing). Match is on CONTROL.NIST (e.g. "AC-2(1)") for the
800-53 vocabulary. Idempotent: every run resets the four columns for VocabularyID=7 then re-tags.

Usage:
    python import_nist80053_baselines.py            # download profiles into resources/ if needed
    python import_nist80053_baselines.py --dir DIR  # use baseline profile JSONs already in DIR
    python import_nist80053_baselines.py --no-download   # fail if a profile is missing locally
"""

import argparse
import json
import os
import sys
import urllib.request

from sqlalchemy import inspect, text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportNIST80053Baselines"
VOCAB_ID = 7  # "NIST 800-53"

BASE_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/"
)
RES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "resources")

# column on CONTROL  ->  (profile file name)
BASELINES = {
    "BaselineLow": "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
    "BaselineModerate": "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
    "BaselineHigh": "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
    "BaselinePrivacy": "NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json",
}


def to_nist_ref(oscal_id: str) -> str:
    """ 'ac-1' -> 'AC-1'; 'ac-2.1' -> 'AC-2(1)' (NIST notation). """
    fam, _, rest = oscal_id.partition("-")
    fam = fam.upper()
    if "." in rest:
        base, enh = rest.split(".", 1)
        return f"{fam}-{base}({enh})"
    return f"{fam}-{rest}"


def _resolve(fname: str, src_dir: str, download: bool) -> str:
    """Return a path to the profile JSON, downloading into resources/ when allowed."""
    local = os.path.join(src_dir, fname)
    if os.path.exists(local):
        return local
    if not download:
        raise SystemExit(f"Missing baseline profile: {local} (run without --no-download to fetch it)")
    os.makedirs(RES_DIR, exist_ok=True)
    dest = os.path.join(RES_DIR, fname)
    if not os.path.exists(dest):
        url = BASE_URL + fname
        log(MODULE, f"Downloading {url}")
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (fixed gov URL)
            data = resp.read()
        with open(dest, "wb") as fh:
            fh.write(data)
    return dest


def _profile_control_ids(json_path: str) -> set:
    """Collect every selected control id from an OSCAL profile (imports[].include-controls[].with-ids[])."""
    with open(json_path, "r", encoding="utf-8") as fh:
        prof = json.load(fh).get("profile", {})
    ids = set()
    for imp in prof.get("imports", []):
        for inc in imp.get("include-controls", []):
            for cid in inc.get("with-ids", []):
                if cid:
                    ids.add(to_nist_ref(str(cid)))
    return ids


def _ensure_columns(session) -> None:
    """Add the four Baseline* columns to CONTROL if they don't exist yet (SQLite/Postgres/MySQL)."""
    engine = session.get_bind()
    have = {c["name"] for c in inspect(engine).get_columns("CONTROL")}
    for col in BASELINES:
        if col not in have:
            session.execute(text(f'ALTER TABLE "CONTROL" ADD COLUMN "{col}" INTEGER'))
            log(MODULE, f"Added CONTROL.{col}")


def run(src_dir: str, download: bool) -> None:
    # Parse the four profiles first (so a bad download aborts before we touch the DB).
    members = {}
    for col, fname in BASELINES.items():
        path = _resolve(fname, src_dir, download)
        members[col] = _profile_control_ids(path)
        log(MODULE, f"{col}: {len(members[col])} controls")

    with session_scope("XORCISM") as session:
        _ensure_columns(session)
        # Reset, then tag — idempotent.
        cols = ", ".join(f'"{c}" = 0' for c in BASELINES)
        session.execute(text(f'UPDATE "CONTROL" SET {cols} WHERE "VocabularyID" = :v'), {"v": VOCAB_ID})
        tagged = {}
        for col, refs in members.items():
            n = 0
            for ref in refs:
                res = session.execute(
                    text(f'UPDATE "CONTROL" SET "{col}" = 1 WHERE "VocabularyID" = :v AND "NIST" = :r'),
                    {"v": VOCAB_ID, "r": ref},
                )
                n += res.rowcount or 0
            tagged[col] = n
        session.commit()

    summary = " | ".join(f"{c.replace('Baseline','')}={tagged[c]}" for c in BASELINES)
    log(MODULE, f"Done. Tagged controls -> {summary}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Tag XORCISM.CONTROL with NIST SP 800-53 Low/Moderate/High/Privacy baselines")
    ap.add_argument("--dir", default=RES_DIR, help="Directory holding the baseline profile JSONs (default: resources/)")
    ap.add_argument("--no-download", action="store_true", help="Do not fetch missing profiles from NIST")
    args = ap.parse_args()
    run(args.dir, download=not args.no_download)


if __name__ == "__main__":
    main()
