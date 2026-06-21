"""run.py — XORCISM connector: Microsoft 365 / Entra ID (Azure AD) → identities + assets.

Collects and synchronizes the Entra directory into XORCISM via the Microsoft Graph API:
  • users            → human identities      (IDENTITY, type=human, class=user)
  • servicePrincipals→ non-human identities  (IDENTITY, type=non-human, class=servicePrincipal)
  • devices          → assets                (ASSET, via the findings path)

Auth is app-only (OAuth2 client-credentials). Secrets come from the WORKER ENVIRONMENT, never
the XORCISM UI:
    ENTRA_TENANT_ID      tenant GUID or primary domain (or the `tenant` param)
    ENTRA_CLIENT_ID      app registration (client) id
    ENTRA_CLIENT_SECRET  client secret
The app registration needs the application permissions User.Read.All, Application.Read.All and
Device.Read.All (admin-consented).

Offline / test mode: params["file"] = a saved Graph JSON export — either
{"users":[...], "servicePrincipals":[...], "devices":[...]} or raw Graph {"value":[...]} arrays.

Python stdlib only (urllib) — NO database access here, so the connector also runs on a remote
worker. The runner maps "identities" → IDENTITY and "assets" → ASSET.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

SOURCE = "Microsoft Entra ID"
_GRAPH = "https://graph.microsoft.com/v1.0"
_LOGIN = "https://login.microsoftonline.com"
_TRUE = {"y", "yes", "true", "1", "on", "enabled"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    include = {s.strip().lower() for s in str(params.get("include") or "users,serviceprincipals,devices").replace(" ", "").split(",") if s.strip()}
    max_items = int(params.get("max_items") or 1000)

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        users, sps, devices = _from_export(data)
    else:
        token = _token(params)
        users = _graph_list(token, "/users?$select=id,displayName,userPrincipalName,accountEnabled,mail,jobTitle,createdDateTime", max_items) if "users" in include else []
        sps = _graph_list(token, "/servicePrincipals?$select=id,displayName,appId,accountEnabled,servicePrincipalType", max_items) if "serviceprincipals" in include else []
        devices = _graph_list(token, "/devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,accountEnabled,approximateLastSignInDateTime,isCompliant", max_items) if "devices" in include else []

    identities: List[Dict[str, Any]] = [_map_user(u) for u in users] + [_map_sp(s) for s in sps]
    assets: List[Dict[str, Any]] = [_map_device(d) for d in devices]
    assets = [a for a in assets if a.get("hostname")]
    return {"assets": assets, "services": [], "cpes": [], "identities": identities, "source": SOURCE}


# ── auth + Graph paging (stdlib) ──────────────────────────────────────────────────
def _token(params: Dict[str, Any]) -> str:
    tenant = str(params.get("tenant") or os.getenv("ENTRA_TENANT_ID") or "").strip()
    cid = os.getenv("ENTRA_CLIENT_ID") or ""
    secret = os.getenv("ENTRA_CLIENT_SECRET") or ""
    if not (tenant and cid and secret):
        raise RuntimeError(
            "Entra live mode needs ENTRA_TENANT_ID (or the tenant param), ENTRA_CLIENT_ID and "
            "ENTRA_CLIENT_SECRET in the worker environment — or pass an offline export via file=.")
    body = urllib.parse.urlencode({
        "client_id": cid, "client_secret": secret,
        "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default",
    }).encode()
    req = urllib.request.Request(f"{_LOGIN}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token", data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (fixed Microsoft endpoint)
        tok = json.loads(r.read().decode("utf-8", "replace"))
    if not tok.get("access_token"):
        raise RuntimeError(f"Entra token request failed: {tok.get('error_description') or tok}")
    return tok["access_token"]


def _graph_list(token: str, path: str, max_items: int) -> List[Dict[str, Any]]:
    url: Optional[str] = _GRAPH + path
    out: List[Dict[str, Any]] = []
    while url and len(out) < max_items:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310 (Graph endpoint)
            page = json.loads(r.read().decode("utf-8", "replace"))
        out.extend(page.get("value") or [])
        url = page.get("@odata.nextLink")
    return out[:max_items]


def _from_export(data: Any) -> tuple:
    """Accept {users,servicePrincipals,devices} or a raw Graph {value:[...]} (type inferred)."""
    if isinstance(data, dict) and any(k in data for k in ("users", "servicePrincipals", "devices")):
        return (data.get("users") or [], data.get("servicePrincipals") or [], data.get("devices") or [])
    rows = data.get("value") if isinstance(data, dict) else (data if isinstance(data, list) else [])
    users, sps, devices = [], [], []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        if "servicePrincipalType" in r or "appId" in r:
            sps.append(r)
        elif "operatingSystem" in r or "deviceId" in r:
            devices.append(r)
        else:
            users.append(r)
    return users, sps, devices


# ── mappers (Graph object → normalized XORCISM item) ──────────────────────────────
def _status(enabled: Any) -> str:
    if enabled is None:
        return ""
    return "enabled" if (enabled is True or str(enabled).lower() in _TRUE) else "disabled"


def _map_user(u: Dict[str, Any]) -> Dict[str, Any]:
    sign_in = (u.get("signInActivity") or {}).get("lastSignInDateTime") if isinstance(u.get("signInActivity"), dict) else None
    return {
        "name": u.get("userPrincipalName") or u.get("displayName") or u.get("id"),
        "type": "human", "class": "user",
        "description": u.get("jobTitle") or (u.get("mail") or ""),
        "status": _status(u.get("accountEnabled")),
        "provider": SOURCE, "external_id": u.get("id"),
        "environment": "Cloud", "credential_type": "password",
        "last_used": sign_in,
        "risk": (u.get("riskLevel") if isinstance(u.get("riskLevel"), str) else None),
    }


def _map_sp(s: Dict[str, Any]) -> Dict[str, Any]:
    spt = (s.get("servicePrincipalType") or "").lower()
    klass = "managedIdentity" if "managed" in spt else "servicePrincipal"
    return {
        "name": s.get("displayName") or s.get("appId") or s.get("id"),
        "type": "non-human", "class": klass,
        "description": (f"appId={s.get('appId')}" if s.get("appId") else "") + (f" ({s.get('servicePrincipalType')})" if s.get("servicePrincipalType") else ""),
        "status": _status(s.get("accountEnabled")),
        "provider": SOURCE, "external_id": s.get("id"),
        "environment": "Cloud", "credential_type": "client-credential",
    }


def _map_device(d: Dict[str, Any]) -> Dict[str, Any]:
    name = d.get("displayName") or d.get("deviceId") or d.get("id") or ""
    os_str = " ".join(x for x in (d.get("operatingSystem"), d.get("operatingSystemVersion")) if x)
    return {"hostname": name, "key": d.get("deviceId") or d.get("id") or name, "os": os_str}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Microsoft Entra ID → identities + assets (dry run)")
    ap.add_argument("--file", help="offline Graph JSON export")
    ap.add_argument("--tenant", default="")
    ap.add_argument("--include", default="users,servicePrincipals,devices")
    ap.add_argument("--max-items", type=int, default=1000)
    a = ap.parse_args()
    res = run({"file": a.file, "tenant": a.tenant, "include": a.include, "max_items": a.max_items}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[entra-id] {len(res['identities'])} identit(y/ies), {len(res['assets'])} asset(s)", flush=True)
