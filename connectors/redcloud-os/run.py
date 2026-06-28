"""run.py - XORCISM connector: RedCloud-OS cloud red-team engagement -> cloud assets + cloud-attack findings.

RedCloud-OS (github.com/RedCloudOS) is a "Cloud Adversary Simulation Operating System for Red Teams"
that bundles the leading cloud attack tools across AWS / Azure / GCP / Kubernetes and organises them by
kill-chain phase. This connector ingests the engagement output and maps it to the XORCISM model
(no live cloud access, no DB access - worker-safe). It returns normalized {assets, vulns} that the runner
imports.

It accepts the 'file' in any of these shapes and auto-detects which:
  1. RedCloud-OS engagement bundle:  {engagement, csp, assets:[...], findings:[...]}
  2. ScoutSuite results            :  scoutsuite_results JS/JSON (services.<svc>.findings.<id>)
  3. Prowler                       :  OCSF JSON or v3 JSON (list of findings)
  4. BloodHound / AzureHound / PMapper / cloudfox graph: {nodes:[...], edges:[...]}

Mapping:
  cloud resource / identity (account, role, user, bucket, VM, function, cluster, node) -> ASSET
       (tags redcloud / <csp> / cloud / <kind>)
  misconfiguration / exposure / privilege-escalation edge                              -> VULN
       severity-ranked, ATT&CK-tagged (T1078/T1098/T1190/T1530/T1552/T1556/T1562/T1580).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Tuple

SOURCE = "RedCloud-OS"

# Normalize a free-form severity/level to the XORCISM scale.
_SEV = {
    "critical": "critical", "crit": "critical",
    "high": "high", "danger": "high", "error": "high", "fail": "high", "failed": "high",
    "medium": "medium", "med": "medium", "warning": "medium", "warn": "medium", "moderate": "medium",
    "low": "low", "minor": "low",
    "info": "info", "informational": "info", "notice": "info", "pass": "info", "passed": "info",
}

# Kill-chain phase -> representative ATT&CK technique (cloud).
_PHASE_ATTCK = {
    "enumeration": "T1580", "discovery": "T1580", "recon": "T1580", "reconnaissance": "T1580",
    "initial access": "T1078", "initial-access": "T1078", "access": "T1078",
    "credential access": "T1552", "credential-access": "T1552", "credentials": "T1552",
    "privilege escalation": "T1098", "privilege-escalation": "T1098", "privesc": "T1098",
    "persistence": "T1098",
    "defense evasion": "T1562", "defense-evasion": "T1562", "evasion": "T1562",
    "lateral movement": "T1078", "lateral-movement": "T1078",
    "exfiltration": "T1530", "exfil": "T1530", "collection": "T1530",
    "impact": "T1485",
}

# Keyword -> ATT&CK (cloud) when no phase/attck is supplied by the source.
_KW_ATTCK = [
    (("public", "anonymous", "0.0.0.0/0", "world-readable", "exposed", "internet"), "T1530"),
    (("bucket", "blob", "storage", "s3", "object"), "T1530"),
    (("mfa", "multi-factor", "multifactor"), "T1556"),
    (("cloudtrail", "logging", "log file", "flow log", "audit log", "config recorder", "guardduty", "monitor"), "T1562"),
    (("passrole", "assumerole", "privilege", "escalat", "admin", "*:*", "administratoraccess", "wildcard"), "T1098"),
    (("password", "secret", "credential", "access key", "api key", "token", "gitleaks", "unsecured"), "T1552"),
    (("public-facing", "unauthenticated", "exploit", "rce", "cve-"), "T1190"),
]

_CSP_KW = {
    "aws": ("aws", "amazon", "iam", "s3", "ec2", "lambda", "cloudtrail", "arn:", "eks"),
    "azure": ("azure", "entra", "office365", "o365", "m365", "microsoft.graph", "storage account", "roadtools"),
    "gcp": ("gcp", "google cloud", "gcs", "gke", "gcloud", "projects/"),
    "k8s": ("kubernetes", "k8s", "kubelet", "kube-system", "cluster", "peirates", "pod", "namespace"),
}

PRIV = ("admin", "owner", "domain admin", "root", "*:*", "administratoraccess", "privileged")


def _sev(v: Any, default: str = "medium") -> str:
    return _SEV.get(str(v or "").strip().lower(), default)


def _detect_csp(text: str, override: str) -> str:
    if override:
        return "k8s" if override in ("k8s", "kubernetes") else override
    t = text.lower()
    for csp, kws in _CSP_KW.items():
        if any(k in t for k in kws):
            return csp
    return "cloud"


def _attck(phase: str, text: str) -> str:
    p = (phase or "").strip().lower()
    if p in _PHASE_ATTCK:
        return _PHASE_ATTCK[p]
    t = text.lower()
    for kws, tech in _KW_ATTCK:
        if any(k in t for k in kws):
            return tech
    return "T1078"


def _bump(sev: str, blob: str) -> str:
    if sev in ("medium", "low") and any(p in blob.lower() for p in PRIV):
        return "high"
    return sev


def _short(s: Any, n: int) -> str:
    return str(s if s is not None else "")[:n]


# ── format detection ──────────────────────────────────────────────────────────────
def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    # ScoutSuite results files are JS: `scoutsuite_results = {...};`
    m = re.match(r"\s*(?:var\s+)?scoutsuite_results\s*=\s*", raw)
    if m:
        raw = raw[m.end():].rstrip().rstrip(";")
    return json.loads(raw)


# ── parsers (each returns (assets, vulns), n is a running finding counter) ──────────
def _parse_bundle(data: Dict[str, Any], label: str, csp_over: str) -> Tuple[List[dict], List[dict]]:
    assets: List[dict] = [{"name": label, "tags": ["redcloud", "cloud", "engagement"]}]
    vulns: List[dict] = []
    for a in (data.get("assets") or []):
        if isinstance(a, str):
            nm, kind, csp = a, "resource", csp_over
        elif isinstance(a, dict):
            nm = a.get("name") or a.get("id") or a.get("arn") or a.get("resource") or ""
            kind = (a.get("kind") or a.get("type") or "resource").lower()
            csp = _detect_csp(json.dumps(a), a.get("csp") or csp_over)
        else:
            continue
        if nm:
            assets.append({"name": _short(nm, 200), "tags": ["redcloud", csp, "cloud", kind]})
    n = 0
    for f in (data.get("findings") or data.get("vulns") or []):
        if not isinstance(f, dict):
            continue
        n += 1
        text = json.dumps(f)
        csp = _detect_csp(text, f.get("csp") or csp_over)
        phase = f.get("phase") or f.get("tactic") or ""
        attck = str(f.get("attck") or f.get("attack") or f.get("technique") or _attck(phase, text))
        tool = f.get("tool") or f.get("module") or ""
        asset = f.get("asset") or f.get("resource") or f.get("entity") or label
        sev = _bump(_sev(f.get("severity") or f.get("level"), "medium"), text)
        title = f.get("title") or f.get("name") or f.get("check") or "Cloud finding"
        desc = f.get("description") or f.get("detail") or f.get("message") or ""
        tail = " ".join(x for x in [("[%s/%s]" % (csp.upper(), phase) if phase else "[%s]" % csp.upper()),
                                    ("via %s." % tool if tool else ""), "ATT&CK %s." % attck] if x)
        vulns.append({"asset": _short(asset, 200), "ref": "REDCLOUD-%d" % n, "severity": sev,
                      "name": _short(title, 240),
                      "description": _short((desc + " " if desc else "") + tail, 1600)})
    return assets, vulns


def _parse_scoutsuite(data: Dict[str, Any], label: str, csp_over: str) -> Tuple[List[dict], List[dict]]:
    prov = str((data.get("provider_code") or data.get("provider_name") or csp_over or "")).lower()
    csp0 = _detect_csp(prov or "scoutsuite", csp_over)
    acct = data.get("account_id") or (data.get("last_run") or {}).get("ruleset_name") or label
    assets: List[dict] = [{"name": _short(acct, 200), "tags": ["redcloud", csp0, "cloud", "account"]}]
    vulns: List[dict] = []
    n = 0
    for svc_name, svc in (data.get("services") or {}).items():
        if not isinstance(svc, dict):
            continue
        for fid, f in (svc.get("findings") or {}).items():
            if not isinstance(f, dict):
                continue
            level = f.get("level")
            sev = _sev(level, "medium")
            if sev == "info" and not f.get("flagged_items"):
                continue
            desc = f.get("description") or fid
            attck = _attck("", "%s %s %s" % (svc_name, fid, desc))
            items = f.get("items") or []
            flagged = f.get("flagged_items") or (len(items) if items else 0)
            if not items:
                n += 1
                vulns.append({"asset": _short(acct, 200), "ref": "REDCLOUD-SS-%d" % n,
                              "severity": _bump(sev, "%s %s" % (fid, desc)),
                              "name": _short("ScoutSuite: %s" % desc, 240),
                              "description": _short("[%s/%s] %s (flagged: %s). ATT&CK %s." % (csp0.upper(), svc_name, desc, flagged, attck), 1600)})
                continue
            for path in items[:60]:
                res = str(path).split(".")[-1] if path else acct
                assets.append({"name": _short(res, 200), "tags": ["redcloud", csp0, "cloud", svc_name]})
                n += 1
                vulns.append({"asset": _short(res, 200), "ref": "REDCLOUD-SS-%d" % n,
                              "severity": _bump(sev, "%s %s" % (path, desc)),
                              "name": _short("ScoutSuite: %s" % desc, 240),
                              "description": _short("[%s/%s] %s on %s. ATT&CK %s." % (csp0.upper(), svc_name, desc, path, attck), 1600)})
    return assets, vulns


def _parse_prowler(rows: List[dict], label: str, csp_over: str) -> Tuple[List[dict], List[dict]]:
    assets: List[dict] = []
    vulns: List[dict] = []
    seen_acct = set()
    n = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        status = str(r.get("status_code") or r.get("Status") or r.get("status") or "").upper()
        if status in ("PASS", "PASSED", "MANUAL"):
            continue
        # OCSF vs v3 field names
        title = (r.get("CheckTitle") or r.get("check_title") or (r.get("finding_info") or {}).get("title")
                 or r.get("message") or "Prowler finding")
        sev = _sev(r.get("Severity") or r.get("severity") or (r.get("severity_id")), "medium")
        svc = r.get("ServiceName") or r.get("service_name") or (r.get("resources") or [{}])[0].get("type") or ""
        prov = r.get("Provider") or r.get("provider") or (r.get("cloud") or {}).get("provider") or ""
        acct = (r.get("AccountId") or r.get("account_id") or (r.get("cloud") or {}).get("account", {}).get("uid") or label)
        res = (r.get("ResourceId") or r.get("resource_id") or (r.get("resources") or [{}])[0].get("uid") or acct)
        text = "%s %s %s" % (title, svc, json.dumps(r.get("Risk") or r.get("risk") or ""))
        csp = _detect_csp("%s %s" % (prov, text), csp_over)
        if acct not in seen_acct:
            seen_acct.add(acct)
            assets.append({"name": _short(acct, 200), "tags": ["redcloud", csp, "cloud", "account"]})
        assets.append({"name": _short(res, 200), "tags": ["redcloud", csp, "cloud", str(svc).lower() or "resource"]})
        attck = _attck("", text)
        n += 1
        vulns.append({"asset": _short(res, 200), "ref": "REDCLOUD-PRW-%d" % n,
                      "severity": _bump(sev, text),
                      "name": _short("Prowler: %s" % title, 240),
                      "description": _short("[%s/%s] %s on %s. ATT&CK %s." % (csp.upper(), svc or "cloud", title, res, attck), 1600)})
    return assets, vulns


def _ep(v: Any) -> str:
    if isinstance(v, dict):
        for k in ("value", "id", "objectid", "ObjectId", "name", "Name"):
            if v.get(k):
                return str(v[k])
        return ""
    return str(v) if v is not None else ""


def _parse_graph(data: Dict[str, Any], label: str, csp_over: str) -> Tuple[List[dict], List[dict]]:
    g = data.get("graph") if isinstance(data.get("graph"), dict) else data
    nodes = g.get("nodes") or data.get("nodes") or []
    edges = g.get("edges") or g.get("relationships") or data.get("edges") or []
    by_id: Dict[str, str] = {}
    assets: List[dict] = []
    vulns: List[dict] = []
    csp0 = _detect_csp(json.dumps(data)[:4000], csp_over)
    for nd in nodes:
        if not isinstance(nd, dict):
            continue
        nid = str(nd.get("id") or nd.get("objectid") or nd.get("ObjectId") or "")
        props = nd.get("properties") if isinstance(nd.get("properties"), dict) else nd
        name = str(props.get("name") or props.get("Name") or props.get("displayname") or nid)
        kinds = nd.get("kinds") or nd.get("labels") or ([nd.get("kind")] if nd.get("kind") else [])
        kind = str((kinds[0] if kinds else "node")).lower()
        if nid:
            by_id[nid] = name
        if name:
            assets.append({"name": _short(name, 200), "tags": ["redcloud", csp0, "cloud", kind]})
    n = 0
    for ed in edges:
        if not isinstance(ed, dict):
            continue
        kind = str(ed.get("kind") or ed.get("type") or ed.get("label") or "CanReach")
        s = by_id.get(_ep(ed.get("start") or ed.get("source") or ed.get("from")), "") or _ep(ed.get("start") or ed.get("source") or ed.get("from"))
        e = by_id.get(_ep(ed.get("end") or ed.get("target") or ed.get("to")), "") or _ep(ed.get("end") or ed.get("target") or ed.get("to"))
        if not s or not e:
            continue
        attck = _attck("privilege escalation", kind)
        n += 1
        sev = _bump("medium", "%s %s %s" % (s, kind, e))
        vulns.append({"asset": _short(e, 200), "ref": "REDCLOUD-GR-%d" % n, "severity": sev,
                      "name": _short("Cloud path: %s -[%s]-> %s" % (s, kind, e), 240),
                      "description": _short("[%s] %s can reach %s via %s. ATT&CK %s." % (csp0.upper(), s, e, kind, attck), 1600)})
    return assets, vulns


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("redcloud-os: provide a 'file' (a RedCloud-OS engagement bundle or a ScoutSuite / Prowler / graph export)")
    data = _load(str(path))
    csp_over = str(params.get("csp") or "").strip().lower()
    if csp_over == "kubernetes":
        csp_over = "k8s"
    label = (str(params.get("target") or "").strip()
             or (data.get("engagement") if isinstance(data, dict) else "")
             or (data.get("metadata") or {}).get("engagement", "") if isinstance(data, dict) else ""
             or os.path.basename(str(path))).strip() or "redcloud-engagement"

    if isinstance(data, list):
        assets, vulns = _parse_prowler(data, label, csp_over)
    elif isinstance(data, dict) and (data.get("findings") is not None or data.get("vulns") is not None) and data.get("services") is None:
        assets, vulns = _parse_bundle(data, label, csp_over)
    elif isinstance(data, dict) and data.get("services") is not None:
        assets, vulns = _parse_scoutsuite(data, label, csp_over)
    elif isinstance(data, dict) and (data.get("nodes") is not None or (data.get("graph") or {}).get("nodes") is not None):
        assets, vulns = _parse_graph(data, label, csp_over)
    elif isinstance(data, dict):
        # bare list of prowler-style findings under a key, else treat as a bundle
        for k in ("findings", "results", "data"):
            if isinstance(data.get(k), list):
                assets, vulns = _parse_prowler(data[k], label, csp_over)
                break
        else:
            assets, vulns = _parse_bundle(data, label, csp_over)
    else:
        raise RuntimeError("redcloud-os: unrecognized export format")

    # de-dup assets by name
    seen = set()
    uniq: List[dict] = []
    for a in assets:
        nm = a.get("name")
        if nm and nm not in seen:
            seen.add(nm)
            uniq.append(a)
    return {"source": SOURCE, "project": "RedCloud-OS", "assets": uniq, "vulns": vulns}


if __name__ == "__main__":
    import sys
    r = run({"file": sys.argv[1], "target": (sys.argv[2] if len(sys.argv) > 2 else None)}, ".")
    print("RedCloud-OS: %d assets, %d findings" % (len(r["assets"]), len(r["vulns"])))
    for v in r["vulns"][:12]:
        print("  %-9s %-16s %s" % (v["severity"], v["ref"], v["name"][:64]))
