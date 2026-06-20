"""run.py — XORCISM connector: OpenSCAP (oscap) output → assets + cpes + vulns.

Imports an OpenSCAP report produced by `oscap`, mapping it to the XORCISM model.
Handles the three common oscap outputs (namespaces stripped, so ARF — which bundles
both — works too):

  • OVAL results   (`oscap oval eval --results res.xml`)  — <definition definition_id result class>
  • XCCDF results  (`oscap xccdf eval --results …`)        — <rule-result idref><result>
  • ARF            (`oscap xccdf eval --results-arf …`)    — both of the above + the source content

Mapping:
  scanned host                              -> ASSET (param `target`, else the report's host name)
  OVAL vulnerability-class `true`           -> VULN  (ref = referenced CVE, else OVAL-<def id>)
  OVAL inventory-class `true` (+ CPE ref)   -> CPE   (installed software)
  XCCDF rule-result `fail`/`error`          -> VULN  (ref = XCCDF-<rule id>, severity from the rule)

No DB access (worker-safe): returns {assets, services, cpes, vulns}. The XOR agent's
live OVAL scan uses the same model via /api/agent/oval; this connector is the file path.
"""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_TRUE = {"true", "pass"}
_FAIL = {"false", "fail", "error"}


def _ln(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("openscap: provide a 'file' (an oscap OVAL/XCCDF results or ARF report)")
    root = ET.parse(path).getroot()
    project = str(params.get("target") or "").strip() or _host(root) or os.path.basename(str(path))
    return _map(root, project)


def _host(root: ET.Element) -> str:
    for el in root.iter():
        t = _ln(el.tag)
        if t in ("primary_host_name", "host_name", "fqdn") and (el.text or "").strip():
            return el.text.strip()
    return ""


def _map(root: ET.Element, project: str) -> Dict[str, Any]:
    assets = {project.lower(): {"hostname": project, "key": project.lower()}}
    cpes: set = set()
    vulns: List[Dict[str, Any]] = []
    seen: set = set()

    # 1) OVAL definition source content (present in ARF / a definitions file): id -> meta
    meta: Dict[str, Dict[str, Any]] = {}
    for el in root.iter():
        if _ln(el.tag) == "definition" and el.get("id"):
            title = ""; cves: List[str] = []; cpe_refs: List[str] = []
            for sub in el.iter():
                st = _ln(sub.tag)
                if st == "title" and not title:
                    title = (sub.text or "").strip()
                elif st == "reference":
                    src = (sub.get("source") or "").upper(); rid = sub.get("ref_id") or ""
                    if src == "CVE" and rid:
                        cves.append(rid)
                    elif src == "CPE" and rid:
                        cpe_refs.append(rid)
            meta[el.get("id")] = {"class": el.get("class", ""), "title": title, "cves": cves, "cpes": cpe_refs}

    # 2) OVAL results: <definition definition_id result class>
    for el in root.iter():
        if _ln(el.tag) == "definition" and el.get("definition_id"):
            did = el.get("definition_id"); result = (el.get("result") or "").lower()
            m = meta.get(did, {})
            cls = (m.get("class") or el.get("class") or "").lower()
            if cls == "vulnerability" and result in _TRUE:
                refs = m.get("cves") or _CVE.findall(did) or [f"OVAL-{did.split(':')[-1]}"]
                for ref in refs:
                    r = ref.upper() if ref.upper().startswith("CVE") else ref
                    if r in seen:
                        continue
                    seen.add(r)
                    vulns.append({"asset": project, "ref": r[:120], "name": (m.get("title") or did)[:200], "severity": "unknown"})
            elif cls == "inventory" and result in _TRUE:
                for c in (m.get("cpes") or []):
                    if c.startswith("cpe:"):
                        cpes.add(c)

    # 3) XCCDF rule-results: <rule-result idref><result>fail</result>
    rules: Dict[str, Dict[str, str]] = {}
    for el in root.iter():
        if _ln(el.tag) == "Rule" and el.get("id"):
            title = ""; sev = el.get("severity", "")
            for sub in el:
                if _ln(sub.tag) == "title":
                    title = (sub.text or "").strip(); break
            rules[el.get("id")] = {"title": title, "severity": sev}
    for el in root.iter():
        if _ln(el.tag) == "rule-result" and el.get("idref"):
            rid = el.get("idref"); result = ""
            for sub in el:
                if _ln(sub.tag) == "result":
                    result = (sub.text or "").strip().lower(); break
            if result in _FAIL:
                ref = "XCCDF-" + (rid.split("_rule_")[-1] if "_rule_" in rid else rid.split(":")[-1])
                if ref in seen:
                    continue
                seen.add(ref)
                ru = rules.get(rid, {})
                vulns.append({"asset": project, "ref": ref[:120], "name": (ru.get("title") or rid)[:200], "severity": (ru.get("severity") or "medium").lower()})

    return {"assets": list(assets.values()), "services": [], "cpes": sorted(cpes), "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import json
    import tempfile

    ap = argparse.ArgumentParser(description="OpenSCAP import (dry run)")
    ap.add_argument("file", help="an oscap OVAL/XCCDF results or ARF report")
    ap.add_argument("--target", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "target": a.target}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[openscap] {len(res['assets'])} asset(s), {len(res['cpes'])} CPE(s), {len(res['vulns'])} finding(s)", flush=True)
