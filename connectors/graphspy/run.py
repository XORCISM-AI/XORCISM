"""run.py - XORCISM connector: GraphSpy (Entra ID / M365) engagement export -> assets + identity-attack findings.

GraphSpy (github.com/RedByte1337/GraphSpy) is a browser-based initial-access & post-exploitation tool for
Entra ID / Microsoft 365: device-code phishing, access/refresh/PRT token abuse, OneDrive/SharePoint/Outlook/
Teams exfiltration and MFA-method persistence. This connector ingests a GraphSpy session export (JSON) and
maps it to the XORCISM model. No live attack and no DB access (worker-safe): it returns normalized
{assets, vulns} that the runner imports.

Mapping:
  tenant / users / devices                  -> ASSET (tags: m365 / entra / identity / user / device)
  captured access/refresh token             -> VULN  GRAPHSPY-TOKEN-<n>   (T1528 Steal App Access Token; PRT -> T1550, critical)
  successful device-code phish              -> VULN  GRAPHSPY-DEVICECODE-<n> (T1528 / T1078)
  over-privileged user w/ weak or no MFA    -> VULN  GRAPHSPY-MFA-<n>     (T1078 Valid Accounts)
  explicit GraphSpy findings[]              -> VULN  GRAPHSPY-<n>         (severity + attck from the finding)

Export schema (all sections optional):
  {
    "tenant": "contoso.onmicrosoft.com",
    "users":   [ { "upn": "alice@contoso.com", "roles": ["Global Administrator"], "mfa": ["authenticator"], "enabled": true } ],
    "devices": [ { "name": "DESKTOP-1", "trust": "AzureAD", "compliant": false } ],
    "tokens":  [ { "user": "alice@contoso.com", "type": "refresh", "scope": ".default", "source": "device_code", "prt": true } ],
    "device_codes": [ { "user": "bob@contoso.com", "status": "authenticated" } ],
    "findings":[ { "title": "...", "severity": "high", "user": "...", "attck": "T1114", "detail": "..." } ]
  }
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SOURCE = "GraphSpy"
PRIV = ("global administrator", "privileged role", "application administrator", "admin", "owner",
        "global reader", "privileged authentication")
_SEV = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low", "info": "info"}


def _sev(v: Any, default: str = "high") -> str:
    return _SEV.get(str(v or "").strip().lower(), default)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("graphspy: provide a 'file' (a GraphSpy engagement export .json)")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    tenant = str(params.get("target") or data.get("tenant") or os.path.basename(str(path))).strip() or "m365-tenant"

    assets: List[Dict[str, Any]] = [{"name": tenant, "tags": ["m365", "entra", "tenant", "cloud"]}]
    vulns: List[Dict[str, Any]] = []
    n = 0

    users = data.get("users") or []
    for u in users:
        upn = str(u.get("upn") or u.get("user") or u.get("userPrincipalName") or "").strip()
        if not upn:
            continue
        assets.append({"name": upn, "tags": ["m365", "entra", "identity", "user"]})
        roles = [str(r).lower() for r in (u.get("roles") or [])]
        mfa = u.get("mfa")
        weak_mfa = (mfa in (None, [], "", False)) or (isinstance(mfa, (list, tuple)) and len(mfa) == 0) \
            or any(str(m).lower() in ("sms", "voice", "phone", "none") for m in (mfa or []))
        if any(any(p in r for p in PRIV) for r in roles) and weak_mfa:
            n += 1
            vulns.append({"asset": upn, "ref": "GRAPHSPY-MFA-%d" % n,
                          "name": "Privileged Entra user with weak/no MFA: %s" % upn,
                          "severity": "high", "description": "%s holds a privileged role (%s) with weak or no MFA — phishable to tenant takeover. ATT&CK T1078." % (upn, ", ".join(roles) or "?")})

    for d in (data.get("devices") or []):
        dn = str(d.get("name") or d.get("id") or "").strip()
        if dn:
            assets.append({"name": dn, "tags": ["m365", "entra", "device"]})

    for t in (data.get("tokens") or []):
        user = str(t.get("user") or t.get("upn") or tenant)
        prt = bool(t.get("prt"))
        ttype = str(t.get("type") or "access")
        src = str(t.get("source") or "")
        n += 1
        vulns.append({"asset": user, "ref": "GRAPHSPY-TOKEN-%d" % n,
                      "name": "%s%s token captured for %s" % ("PRT " if prt else "", ttype, user),
                      "severity": "critical" if prt else "high",
                      "description": "GraphSpy captured a %s%s token (scope=%s%s) — replayable for Graph access / SSO. ATT&CK %s." % (
                          "Primary Refresh " if prt else "", ttype, t.get("scope") or "?",
                          (" via %s" % src) if src else "", "T1550" if prt else "T1528")})

    for dc in (data.get("device_codes") or []):
        if str(dc.get("status") or "").lower() in ("authenticated", "success", "ok", "captured"):
            user = str(dc.get("user") or tenant)
            n += 1
            vulns.append({"asset": user, "ref": "GRAPHSPY-DEVICECODE-%d" % n,
                          "name": "Device-code phishing succeeded: %s" % user,
                          "severity": "high",
                          "description": "A GraphSpy device-code authentication succeeded for %s — initial access without a password. ATT&CK T1528 / T1078." % user})

    for f in (data.get("findings") or []):
        title = str(f.get("title") or f.get("name") or "GraphSpy finding")[:200]
        user = str(f.get("user") or f.get("asset") or tenant)
        attck = str(f.get("attck") or f.get("attack") or "")
        n += 1
        vulns.append({"asset": user, "ref": "GRAPHSPY-%d" % n, "name": title, "severity": _sev(f.get("severity")),
                      "description": ("%s%s" % (f.get("detail") or f.get("description") or title, (" ATT&CK %s." % attck) if attck else ""))[:1600]})

    # de-dup assets by name
    seen = set(); uniq = []
    for a in assets:
        if a["name"] not in seen:
            seen.add(a["name"]); uniq.append(a)
    return {"source": SOURCE, "project": "GraphSpy", "assets": uniq, "vulns": vulns}


if __name__ == "__main__":
    import sys
    r = run({"file": sys.argv[1]}, ".")
    print("GraphSpy: %d assets, %d findings" % (len(r["assets"]), len(r["vulns"])))
    for v in r["vulns"][:10]:
        print("  %-9s %-22s %s" % (v["severity"], v["ref"], v["name"][:60]))
