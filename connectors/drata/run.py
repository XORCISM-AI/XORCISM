"""Drata connector — sync policies + evidence into XCOMPLIANCE.DOCUMENT.

Offline: a JSON export via the `file` param. Live: DRATA_API_KEY (Bearer) + optional DRATA_API_BASE.
Returns {"documents": [...], "source": "Drata"} for runner.import_documents.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402


def run(params, workdir):
    items = g.from_file(params)
    if items is not None:
        return {"documents": g.norm(items), "source": "Drata"}

    key = os.getenv("DRATA_API_KEY") or os.getenv("DRATA_TOKEN")
    base = (params.get("base") or os.getenv("DRATA_API_BASE") or "https://public-api.drata.com").rstrip("/")
    if not key:
        raise RuntimeError("Drata: provide a `file` param (offline export) or set DRATA_API_KEY in the worker env.")
    hdr = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    cap = int(params.get("max_items") or 2000)
    docs = []
    for path, dtype in (("/public/policies", "Policy"), ("/public/documents", "Document"), ("/public/evidence", "Evidence")):
        try:
            docs += g.norm(g.rows(g.http_json(base + path, hdr)), dtype)
        except Exception:  # noqa: BLE001
            continue
    return {"documents": docs[:cap], "source": "Drata"}
