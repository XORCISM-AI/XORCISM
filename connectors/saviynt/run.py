"""run.py — Import Saviynt EIC identities/accounts into XORCISM (XORCISM.IDENTITY).

Saviynt Enterprise Identity Cloud (EIC, saviynt.com) is a cloud-native IGA + PAM platform. This connector
imports its users and accounts into the XORCISM identity registry (idempotent by Provider+ExternalID via
runner.import_identities), feeding the identity inventory (/identities), certification (/identity-governance)
and the Saviynt-style Access Governance cockpit (/access-governance).

Read-only & worker-safe. Two modes:
  * live:    SAVIYNT_BASE_URL + SAVIYNT_USERNAME + SAVIYNT_PASSWORD (token login → fetch users/accounts)
  * offline: params["file"] = a Saviynt user/account export JSON  (or the bundled sample)

Mapping → identity item: users → human "user"; accounts → non-human "account" (NHI). Privileged/admin
markers, status, employee type, last-login and risk are carried where present.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

TOOL_NAME = "Saviynt"
SOURCE = "Saviynt"
_PRIV_RX = ("admin", "privilege", "root", "superuser", "sudo", "domain admin", "global admin")


def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def _is_priv(*vals: Any) -> str:
    hay = " ".join(str(v or "") for v in vals).lower()
    return "privileged" if any(tok in hay for tok in _PRIV_RX) else "standard"


def _user_to_identity(u: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = _first(u, "username", "userName", "systemUserName", "email", "name")
    if not name:
        return None
    ext = _first(u, "userkey", "userKey", "id", "employeeid", "employeeId") or name
    status_raw = str(_first(u, "statuskey", "status", "statusKey") or "1")
    status = "inactive" if status_raw in ("0", "inactive", "disabled", "terminated") else "active"
    emptype = str(_first(u, "employeeType", "customproperty1", "userType") or "").lower()
    klass = "Non-Human" if any(t in emptype for t in ("service", "system", "bot", "machine")) else "Human"
    return {
        "name": str(name)[:200], "type": "service-account" if klass == "Non-Human" else "user", "class": klass,
        "description": str(_first(u, "displayname", "displayName", "title") or "")[:500],
        "status": status, "provider": SOURCE, "external_id": str(ext),
        "privilege": _is_priv(name, _first(u, "title", "roles", "customproperty1")),
        "environment": str(_first(u, "location", "department") or ""),
        "last_used": _first(u, "lastlogindate", "lastLoginDate", "statusUpdateDate"),
        "risk": "High" if status == "active" and _is_priv(name, _first(u, "title")) == "privileged" else None,
    }


def _account_to_identity(a: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = _first(a, "name", "accountID", "accountId", "displayName")
    if not name:
        return None
    ext = _first(a, "accountKey", "accountkey", "id") or name
    status = str(_first(a, "status", "statuskey") or "1")
    priv = _is_priv(name, _first(a, "accountType", "endpoint", "description"))
    uncorrelated = not _first(a, "userKey", "userkey", "owner")
    return {
        "name": str(name)[:200], "type": "privileged-account" if priv == "privileged" else "account", "class": "Non-Human",
        "description": str(_first(a, "description", "endpoint", "securitySystem") or "")[:500],
        "status": "inactive" if status in ("0", "inactive", "suspended") else "active",
        "provider": SOURCE, "external_id": str(ext), "privilege": priv,
        "environment": str(_first(a, "endpoint", "securitySystem") or ""),
        "credential_type": "service-account",
        "last_used": _first(a, "lastlogondate", "lastLogonDate"),
        "risk": "High" if uncorrelated else None,  # orphaned/uncorrelated accounts are higher risk
    }


def _collect(data: Any, *keys: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if isinstance(v, list):
                out += [x for x in v if isinstance(x, dict)]
    return out


def _http_json(url: str, method: str, headers: Dict[str, str], body: Any = None, timeout: int = 60) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", "Accept": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", "replace") or "null")


def _live(base: str, user: str, pwd: str, include: str, limit: int) -> List[Dict[str, Any]]:
    """Best-effort live pull from Saviynt EIC. Any failure → []."""
    out: List[Dict[str, Any]] = []
    try:
        base = base.rstrip("/")
        tok = _http_json(f"{base}/ECM/api/login", "POST", {}, {"username": user, "password": pwd})
        access = (tok or {}).get("access_token") or (tok or {}).get("accessToken")
        if not access:
            return []
        auth = {"Authorization": f"Bearer {access}"}
        if "users" in include:
            d = _http_json(f"{base}/ECM/api/v5/getUser", "POST", auth, {"max": limit, "offset": 0})
            for u in _collect(d, "userdetails", "users", "Userlist", "results"):
                it = _user_to_identity(u)
                if it:
                    out.append(it)
        if "accounts" in include:
            d = _http_json(f"{base}/ECM/api/v5/getAccounts", "POST", auth, {"max": limit, "offset": 0})
            for a in _collect(d, "accountdetails", "accounts", "Accountlist", "results"):
                it = _account_to_identity(a)
                if it:
                    out.append(it)
    except Exception:
        return []
    return out


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = max(1, min(int(params.get("limit") or 500), 5000))
    include = str(params.get("include") or "users,accounts").lower()
    base = (os.environ.get("SAVIYNT_BASE_URL") or "").strip()
    user = (os.environ.get("SAVIYNT_USERNAME") or "").strip()
    pwd = (os.environ.get("SAVIYNT_PASSWORD") or "").strip()

    identities: List[Dict[str, Any]] = []
    if base and user and pwd and not params.get("file"):
        identities = _live(base, user, pwd, include, limit)
    if not identities:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        users = _collect(data, "users", "userdetails", "Userlist") if "users" in include else []
        accts = _collect(data, "accounts", "accountdetails", "Accountlist") if "accounts" in include else []
        if not users and not accts and isinstance(data, list):
            users = [x for x in data if isinstance(x, dict)]
        for u in users:
            it = _user_to_identity(u)
            if it:
                identities.append(it)
        for a in accts:
            it = _account_to_identity(a)
            if it:
                identities.append(it)

    return {"source": SOURCE, "identities": identities[:limit]}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Saviynt connector (offline dry run)")
    ap.add_argument("--file"); ap.add_argument("--include", default="users,accounts")
    a = ap.parse_args()
    if not a.file:
        sample = {
            "users": [
                {"username": "alice.finance", "userkey": "1001", "status": "1", "displayname": "Alice Finance", "title": "AP Clerk", "department": "Finance", "lastlogindate": "2026-06-28"},
                {"username": "svc-batch", "userkey": "1002", "status": "1", "employeeType": "service", "displayname": "Batch Service"},
                {"username": "dave.admin", "userkey": "1003", "status": "1", "title": "Domain Admin", "department": "IT"},
            ],
            "accounts": [
                {"name": "ORA_APPS_ADMIN", "accountKey": "5001", "status": "1", "endpoint": "Oracle EBS", "accountType": "privileged"},
                {"name": "win-local-svc", "accountKey": "5002", "status": "1", "endpoint": "Windows", "userKey": None},
            ],
        }
        fp = os.path.join(tempfile.mkdtemp(), "saviynt.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file, "include": a.include}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[Saviynt] {len(res['identities'])} identity/account(s) -> XORCISM.IDENTITY (tool: saviynt.com)", flush=True)
