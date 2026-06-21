"""OneTrust connector — sync policies + documents into XCOMPLIANCE.DOCUMENT.

Offline: a JSON export via the `file` param. Live: ONETRUST_BASE + ONETRUST_API_TOKEN (Bearer).
Returns {"documents": [...], "source": "OneTrust"} for runner.import_documents.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402


def run(params, workdir):
    items = g.from_file(params)
    if items is not None:
        return {"documents": g.norm(items), "source": "OneTrust"}

    token = os.getenv("ONETRUST_API_TOKEN") or os.getenv("ONETRUST_TOKEN")
    base = (params.get("base") or os.getenv("ONETRUST_BASE") or "").rstrip("/")
    if not base or not token:
        raise RuntimeError("OneTrust: provide a `file` param or set ONETRUST_BASE + ONETRUST_API_TOKEN.")
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    cap = int(params.get("max_items") or 2000)
    docs = []
    for path, dtype in (("/api/policy/v2/policies", "Policy"), ("/api/documents/v1/documents", "Document")):
        try:
            docs += g.norm(g.rows(g.http_json(base + path, hdr)), dtype)
        except Exception:  # noqa: BLE001
            continue
    return {"documents": docs[:cap], "source": "OneTrust"}
