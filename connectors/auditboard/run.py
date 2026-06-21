"""AuditBoard connector — sync policies + evidence into XCOMPLIANCE.DOCUMENT.

Offline: a JSON export via the `file` param. Live: AUDITBOARD_BASE + AUDITBOARD_API_TOKEN (Bearer).
Returns {"documents": [...], "source": "AuditBoard"} for runner.import_documents.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402


def run(params, workdir):
    items = g.from_file(params)
    if items is not None:
        return {"documents": g.norm(items), "source": "AuditBoard"}

    token = os.getenv("AUDITBOARD_API_TOKEN") or os.getenv("AUDITBOARD_TOKEN")
    base = (params.get("base") or os.getenv("AUDITBOARD_BASE") or "").rstrip("/")
    if not base or not token:
        raise RuntimeError("AuditBoard: provide a `file` param or set AUDITBOARD_BASE + AUDITBOARD_API_TOKEN.")
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    cap = int(params.get("max_items") or 2000)
    docs = []
    for path, dtype in (("/api/v1/policies", "Policy"), ("/api/v1/evidence", "Evidence"), ("/api/v1/documents", "Document")):
        try:
            docs += g.norm(g.rows(g.http_json(base + path, hdr)), dtype)
        except Exception:  # noqa: BLE001
            continue
    return {"documents": docs[:cap], "source": "AuditBoard"}
