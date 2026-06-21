"""Vanta connector — sync policies + evidence/documents into XCOMPLIANCE.DOCUMENT.

Offline: a JSON export via the `file` param. Live: VANTA_API_TOKEN (Bearer) + optional VANTA_API_BASE.
Returns {"documents": [...], "source": "Vanta"} for runner.import_documents.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402


def run(params, workdir):
    items = g.from_file(params)
    if items is not None:
        return {"documents": g.norm(items), "source": "Vanta"}

    token = os.getenv("VANTA_API_TOKEN") or os.getenv("VANTA_TOKEN")
    base = (params.get("base") or os.getenv("VANTA_API_BASE") or "https://api.vanta.com").rstrip("/")
    if not token:
        raise RuntimeError("Vanta: provide a `file` param (offline export) or set VANTA_API_TOKEN in the worker env.")
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    cap = int(params.get("max_items") or 2000)
    docs = []
    for path, dtype in (("/v1/policies", "Policy"), ("/v1/documents", "Document"), ("/v1/evidence", "Evidence")):
        try:
            docs += g.norm(g.rows(g.http_json(base + path, hdr)), dtype)
        except Exception:  # noqa: BLE001 — endpoint may not exist on this Vanta plan
            continue
    return {"documents": docs[:cap], "source": "Vanta"}
