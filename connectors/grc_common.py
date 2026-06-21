"""
grc_common.py — shared helpers for the GRC document connectors (Vanta, Drata, ServiceNow GRC,
OneTrust, AuditBoard). Each connector pulls evidence + policy documents and normalizes them to the
shape consumed by runner.import_documents:
    {"documents": [{external_id, name, description, type, framework, url, author, date, status,
                    category, classification, version, language}], "source": "<Platform>"}
Connectors run offline from a JSON export (the `file` param — the verifiable path) or live against the
platform API using credentials supplied via the worker environment (never the UI).
"""
import base64
import json
import os
import urllib.request


def http_json(url, headers=None, timeout=40, data=None, method=None):
    req = urllib.request.Request(url, headers=headers or {}, data=data, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (operator-supplied GRC base URL)
        body = r.read().decode("utf-8", "replace")
    return json.loads(body) if body.strip() else {}


def basic_auth(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def rows(data):
    """Extract a list of records from the common API envelope shapes."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("results", "data", "items", "records", "value", "policies", "evidence", "documents", "result"):
            v = data.get(k)
            if isinstance(v, list):
                return v
    return []


def from_file(params):
    """Offline: load a JSON export and return a flat list of raw doc dicts (or None if no file)."""
    f = params.get("file")
    if not f or not os.path.exists(f):
        return None
    with open(f, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and isinstance(data.get("documents"), list):
        return data["documents"]
    if isinstance(data, list):
        return data
    out = []
    for key, dtype in (("policies", "Policy"), ("evidence", "Evidence"), ("reports", "Report")):
        for x in (data.get(key, []) if isinstance(data, dict) else []):
            if isinstance(x, dict):
                x.setdefault("type", dtype)
                out.append(x)
    return out


def norm(items, default_type="Evidence", framework=None):
    """Normalize raw platform records to DOCUMENT items. Keeps only those with an external id."""
    docs = []
    for x in items or []:
        if not isinstance(x, dict):
            continue
        ext = x.get("external_id") or x.get("id") or x.get("uuid") or x.get("sys_id") or x.get("name")
        if not ext:
            continue
        docs.append({
            "external_id": str(ext),
            "name": x.get("name") or x.get("title") or x.get("displayName") or x.get("short_description") or "Document",
            "description": x.get("description") or x.get("summary") or x.get("body") or "",
            "type": x.get("type") or x.get("documentType") or default_type,
            "framework": x.get("framework") or x.get("standard") or x.get("frameworkName") or framework or "",
            "url": x.get("url") or x.get("link") or x.get("documentUrl") or x.get("fileUrl") or "",
            "author": x.get("author") or x.get("owner") or x.get("createdBy") or x.get("ownerName") or "",
            "date": x.get("date") or x.get("updatedAt") or x.get("createdAt") or x.get("sys_updated_on") or "",
            "status": x.get("status") or x.get("state") or "Active",
            "category": x.get("category") or x.get("controlCategory") or "",
            "classification": x.get("classification") or "",
            "version": str(x.get("version") or x.get("versionNumber") or ""),
            "language": x.get("language") or "en",
        })
    return docs
