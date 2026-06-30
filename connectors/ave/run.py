"""AVE connector — parse the AVE catalogue (github.com/bawbel/ave, Apache-2.0) and emit its
records for import into XORCISM.AVERECORD (the runner's import_ave_records path).

AVE (Agentic Vulnerability Enumeration) is the behavioral-classification standard for agentic-AI
components — stable AVE-2026-##### ids + AIVSS scores + mappings to OWASP Agentic/MCP Top 10,
MITRE ATLAS and NIST AI RMF. Worker-safe & read-only: parses exported JSON only (no scanning).

Accepts: a records.json / {records:[]} / array export, a single AVE-####.json, or (via `dir`) a
directory of AVE-####.json files. Defaults to the bundled sample.json.
"""
from __future__ import annotations

import glob
import json
import os
from typing import Any, Dict, List


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _records_from(doc: Any) -> List[Dict[str, Any]]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for k in ("records", "ave_records", "data"):
            if isinstance(doc.get(k), list):
                return [r for r in doc[k] if isinstance(r, dict)]
        if doc.get("ave_id"):  # a single record file
            return [doc]
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    here = os.path.dirname(os.path.abspath(__file__))
    records: List[Dict[str, Any]] = []

    d = params.get("dir")
    if d and os.path.isdir(d):
        for fp in sorted(glob.glob(os.path.join(d, "AVE-*.json"))):
            try:
                records.extend(_records_from(_load(fp)))
            except (json.JSONDecodeError, ValueError, OSError):
                continue
    else:
        path = params.get("file") or os.path.join(here, "sample.json")
        if not os.path.isabs(path) and not os.path.exists(path):
            cand = os.path.join(workdir or here, path)
            if os.path.exists(cand):
                path = cand
        try:
            records = _records_from(_load(path))
        except FileNotFoundError:
            return {"ave_records": [], "error": "file not found: %s" % path}
        except (json.JSONDecodeError, ValueError) as exc:
            return {"ave_records": [], "error": "not valid JSON: %s" % exc}

    return {"ave_records": records, "source": str(params.get("source") or "AVE"), "count": len(records)}


if __name__ == "__main__":  # python run.py [file.json]
    import sys
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    res = run(p, os.getcwd())
    print(json.dumps({k: (v if k != "ave_records" else "[%d records]" % len(v)) for k, v in res.items()}, indent=2))
