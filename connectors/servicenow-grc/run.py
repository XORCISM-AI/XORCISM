"""ServiceNow GRC connector — sync GRC policies + documents into XCOMPLIANCE.DOCUMENT.

Offline: a JSON export via the `file` param. Live: SERVICENOW_INSTANCE + SERVICENOW_USER +
SERVICENOW_PASSWORD (Basic auth) against the Table API. Returns {"documents": [...], "source":
"ServiceNow GRC"} for runner.import_documents.
"""
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402


def run(params, workdir):
    items = g.from_file(params)
    if items is not None:
        return {"documents": g.norm(items), "source": "ServiceNow GRC"}

    base = params.get("base") or os.getenv("SERVICENOW_INSTANCE") or ""
    if base and "://" not in base:
        base = f"https://{base}.service-now.com"
    base = base.rstrip("/")
    user, pwd = os.getenv("SERVICENOW_USER"), os.getenv("SERVICENOW_PASSWORD")
    if not base or not user or not pwd:
        raise RuntimeError("ServiceNow GRC: provide a `file` param or set SERVICENOW_INSTANCE + SERVICENOW_USER + SERVICENOW_PASSWORD.")
    hdr = {"Authorization": g.basic_auth(user, pwd), "Accept": "application/json"}
    cap = int(params.get("max_items") or 2000)
    tables = [t.strip() for t in (params.get("tables") or "sn_grc_policy,sn_grc_document").split(",") if t.strip()]
    docs = []
    for table in tables:
        dtype = "Policy" if "policy" in table else "Document"
        q = urllib.parse.urlencode({"sysparm_limit": cap, "sysparm_exclude_reference_link": "true"})
        try:
            docs += g.norm(g.rows(g.http_json(f"{base}/api/now/table/{table}?{q}", hdr)), dtype, framework="")
        except Exception:  # noqa: BLE001
            continue
    return {"documents": docs, "source": "ServiceNow GRC"}
