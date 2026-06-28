"""run.py - XORCISM connector: CyberArkHound OpenGraph export -> CyberArk entities + PAM attack-path findings.

CyberArkHound (github.com/jazofra/CyberArkHound) is "BloodHound for CyberArk": it exports CyberArk PVWA /
Privilege Cloud data (users, groups, safes, accounts, platforms, PSM servers, CCP AppIDs and the safe
membership/permission matrix) into a BloodHound-compatible OpenGraph JSON of privilege-escalation and
credential-access paths. This connector ingests that JSON and maps it to the XORCISM model (no live access,
no DB access - worker-safe). It returns normalized {assets, vulns} that the runner imports.

Mapping:
  each graph node (safe / account / user / group / AppID / PSM server) -> ASSET (tags cyberark/pam/identity)
  each privilege-escalation / credential-access edge                   -> VULN on the target entity:
     CanGrantAccessTo  -> high (T1098)  | CanHijackViaReconcile -> high (T1187)
     CanRetrieveViaCCP -> high (T1528, critical when unrestricted) | HasAccessTo -> medium (T1555)
     CanApprove        -> medium (T1098)| LinkedTo -> low (T1555)  | UsedAccount -> skipped (activity)
  misconfigurations on nodes (unrestricted CCP, safe without CPM, wildcard AllowedSafes, PSM w/o
     session monitoring) and any top-level findings[] -> VULN.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SOURCE = "CyberArkHound"
# edge kind (lowercased, "cyberark_" stripped) -> (severity, attck, human description)
EDGE_MAP = {
    "hasaccessto": ("medium", "T1555", "direct credential access (use/retrieve accounts on the safe)"),
    "cangrantaccessto": ("high", "T1098", "safe privilege escalation (manageSafe/manageSafeMembers -> self-grant access)"),
    "canretrieveviaccp": ("high", "T1528", "credential retrieval via CCP/AIMWebService AppID"),
    "canhijackviareconcile": ("high", "T1187", "reconcile-account hijack (coerce the CPM to reset the target password)"),
    "canapprove": ("medium", "T1098", "dual-control / self-approval bypass"),
    "linkedto": ("low", "T1555", "linked credential chain (logon/reconcile/enable dependency)"),
}
SKIP_EDGES = {"usedaccount", "memberof", "contains", "hasrole"}
PRIV = ("admin", "domain admin", "enterprise admin", "root", "reconcile", "privileged", "krbtgt")


def _truthy(v: Any) -> bool:
    return v is True or v == 1 or str(v).strip().lower() in ("true", "yes", "1")


def _endpoint(v: Any) -> str:
    if isinstance(v, dict):
        for k in ("value", "id", "objectid", "ObjectId", "name", "Name"):
            if v.get(k):
                return str(v[k])
        return ""
    return str(v) if v is not None else ""


def _node_id(n: Dict[str, Any]) -> str:
    for k in ("id", "objectid", "ObjectId", "Id", "ID"):
        if n.get(k):
            return str(n[k])
    return ""


def _node_name(props: Dict[str, Any], nid: str) -> str:
    for k in ("name", "Name", "displayname", "DisplayName", "samaccountname", "safeName", "username", "accountName"):
        if props.get(k):
            return str(props[k])
    return nid


def _kinds(n: Dict[str, Any]) -> List[str]:
    for k in ("kinds", "labels", "Kinds", "Labels"):
        if isinstance(n.get(k), (list, tuple)):
            return [str(x) for x in n[k]]
    for k in ("kind", "type", "category", "label"):
        if n.get(k):
            return [str(n[k])]
    return []


def _kind_tag(kinds: List[str]) -> str:
    blob = " ".join(kinds).lower()
    for word in ("safe", "account", "appid", "application", "psm", "platform", "group", "user"):
        if word in blob:
            return "appid" if word == "application" else word
    return "entity"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("cyberarkhound: provide a 'file' (a CyberArkHound OpenGraph JSON export)")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    g = data.get("graph") if isinstance(data.get("graph"), dict) else data
    nodes = g.get("nodes") or data.get("nodes") or []
    edges = g.get("edges") or g.get("relationships") or data.get("edges") or []
    vault = str(params.get("target") or (data.get("metadata") or {}).get("source") or os.path.basename(str(path))).strip() or "cyberark-vault"

    # index nodes
    by_id: Dict[str, Dict[str, Any]] = {}
    assets: List[Dict[str, Any]] = [{"name": vault, "tags": ["cyberark", "pam", "vault"]}]
    vulns: List[Dict[str, Any]] = []
    n = 0

    for nd in nodes:
        nid = _node_id(nd)
        if not nid:
            continue
        props = nd.get("properties") if isinstance(nd.get("properties"), dict) else nd
        kinds = _kinds(nd)
        tag = _kind_tag(kinds)
        name = _node_name(props, nid)
        by_id[nid] = {"name": name, "tag": tag, "props": props}
        assets.append({"name": name[:200], "tags": ["cyberark", "pam", "identity", tag]})

        # node-level misconfigurations
        blob = json.dumps(props).lower()
        if tag == "appid" and (_truthy(props.get("isUnrestricted")) or '"isunrestricted":true' in blob):
            n += 1
            vulns.append({"asset": name[:200], "ref": "CYBERARKHOUND-MISCFG-%d" % n, "severity": "critical",
                          "name": "Unrestricted CCP application: %s" % name,
                          "description": "CCP/AIMWebService AppID '%s' has no authentication restrictions - the AppID alone retrieves credentials. ATT&CK T1528." % name})
        elif tag == "appid" and "aimwebservice" in name.lower():
            n += 1
            vulns.append({"asset": name[:200], "ref": "CYBERARKHOUND-MISCFG-%d" % n, "severity": "high",
                          "name": "Default AIMWebService application: %s" % name,
                          "description": "Default AIMWebService AppID typically has broad safe access. ATT&CK T1528."})
        if tag == "platform" and ("*" in str(props.get("AllowedSafes") or props.get("allowedSafes") or "")):
            n += 1
            vulns.append({"asset": name[:200], "ref": "CYBERARKHOUND-MISCFG-%d" % n, "severity": "medium",
                          "name": "Platform with wildcard AllowedSafes: %s" % name,
                          "description": "Platform '%s' allows privileged accounts on any safe (AllowedSafes=*), removing guardrails." % name})
        if tag == "safe":
            cpm = props.get("managingCPM") or props.get("ManagingCPM") or props.get("cpm") or props.get("CPM")
            if cpm in (None, "", "None", "null") or _truthy(props.get("noCPM")):
                n += 1
                vulns.append({"asset": name[:200], "ref": "CYBERARKHOUND-MISCFG-%d" % n, "severity": "medium",
                              "name": "Safe without CPM rotation: %s" % name,
                              "description": "Safe '%s' has no CPM - credentials are unrotated / long-lived. ATT&CK T1555." % name})
        if tag == "psm" and (("monitor" in blob and '"false"' in blob) or props.get("recordSession") is False):
            n += 1
            vulns.append({"asset": name[:200], "ref": "CYBERARKHOUND-MISCFG-%d" % n, "severity": "medium",
                          "name": "PSM account without session monitoring: %s" % name,
                          "description": "PSM account '%s' has no session monitoring - potential breakout exposure." % name})

    # edges -> attack-path findings (severity raised toward privileged targets / unrestricted CCP)
    for ed in edges:
        kind = str(ed.get("kind") or ed.get("type") or ed.get("edgeType") or ed.get("label") or "").strip()
        norm = kind.lower().replace("cyberark_", "").replace("cyberark", "")
        if not norm or norm in SKIP_EDGES:
            continue
        sev, attck, desc = EDGE_MAP.get(norm, ("medium", "T1078", "privileged access path"))
        s_id = _endpoint(ed.get("start") or ed.get("source") or ed.get("from"))
        e_id = _endpoint(ed.get("end") or ed.get("target") or ed.get("to"))
        s = by_id.get(s_id, {}).get("name") or s_id
        e = by_id.get(e_id, {}).get("name") or e_id
        if not s or not e:
            continue
        eprops = ed.get("properties") if isinstance(ed.get("properties"), dict) else {}
        if norm == "canretrieveviaccp" and (_truthy(eprops.get("isUnrestricted")) or _truthy((by_id.get(s_id, {}).get("props") or {}).get("isUnrestricted"))):
            sev = "critical"
        elif sev == "medium" and any(p in (s + " " + e).lower() for p in PRIV):
            sev = "high"
        n += 1
        vulns.append({"asset": e[:200], "ref": "CYBERARKHOUND-%d" % n,
                      "name": ("CyberArk path: %s -[%s]-> %s" % (s, kind or norm, e))[:240],
                      "severity": sev,
                      "description": "%s %s can reach %s via %s. ATT&CK %s." % (by_id.get(s_id, {}).get("tag", "principal"), s, e, desc, attck)})

    # any explicit top-level findings/summary
    for f in (data.get("findings") or (data.get("metadata") or {}).get("findings") or []):
        if not isinstance(f, dict):
            continue
        n += 1
        vulns.append({"asset": str(f.get("asset") or f.get("entity") or vault)[:200], "ref": "CYBERARKHOUND-FIND-%d" % n,
                      "name": str(f.get("title") or f.get("name") or "CyberArk finding")[:240],
                      "severity": str(f.get("severity") or "medium").lower(),
                      "description": str(f.get("description") or f.get("detail") or "")[:1600]})

    # de-dup assets by name
    seen = set(); uniq = []
    for a in assets:
        if a["name"] and a["name"] not in seen:
            seen.add(a["name"]); uniq.append(a)
    return {"source": SOURCE, "project": "CyberArkHound", "assets": uniq, "vulns": vulns}


if __name__ == "__main__":
    import sys
    r = run({"file": sys.argv[1]}, ".")
    print("CyberArkHound: %d assets, %d findings" % (len(r["assets"]), len(r["vulns"])))
    for v in r["vulns"][:12]:
        print("  %-9s %-22s %s" % (v["severity"], v["ref"], v["name"][:62]))
