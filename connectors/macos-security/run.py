"""run.py -- XORCISM connector for the NIST macOS Security Compliance Project (mSCP).

The mSCP (pages.nist.gov/macos_security, github.com/usnistgov/macos_security) generates hardening
baselines for Apple platforms; each baseline ships a compliance script that audits a Mac and writes
results. This connector ingests those results (it does not run the scan) and records them as a
Compliance AUDIT with one finding per failed rule -> XORCISM.XCOMPLIANCE (via
runner.import_compliance). Each mSCP rule carries its NIST SP 800-53 references.

Accepted inputs (`file`, else bundled sample.json):
  * mSCP results JSON:
      {"baseline":"800-53r5_high","os":"macOS 14","host":"mac01",
       "results":[{"rule_id":"os_sip_enable","title":"Enable System Integrity Protection",
                   "result":"fail","severity":"high","references":{"800-53r5":["AC-3","SC-7"]},
                   "discussion":"..."}, ...]}
  * the mSCP audit **plist** org.<baseline>.audit.plist (XML/binary) -> {rule_id: {"finding": bool}}
    where finding==true means the rule FAILED (non-compliant). Parsed with stdlib plistlib.
  * the compliance script's console summary (text) -- "rule_id ... passed|failed" lines.

Worker-safe: stdlib only (json + plistlib + re), ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
from typing import Any, Dict, List

SOURCE = "NIST macOS Security (mSCP)"
_RULE = re.compile(r"^\s*([a-z][a-z0-9_]+)\b.*?\b(pass(?:ed)?|fail(?:ed)?|exempt)\b", re.I)


def _result_word(v: Any) -> str:
    s = str(v).strip().lower()
    if s in ("fail", "failed", "false", "non-compliant", "noncompliant", "no"):
        return "fail"
    if s in ("exempt", "exempted", "na", "n/a"):
        return "exempt"
    return "pass"


def _refs_str(refs: Any) -> str:
    """Flatten a references dict/list to '800-53r5: AC-3, SC-7'."""
    if isinstance(refs, dict):
        out = []
        for k, v in refs.items():
            vals = v if isinstance(v, (list, tuple)) else [v]
            out.append("%s: %s" % (k, ", ".join(str(x) for x in vals if str(x) != "N/A")))
        return "; ".join(p for p in out if not p.endswith(": "))
    if isinstance(refs, (list, tuple)):
        return ", ".join(str(x) for x in refs)
    return str(refs or "")


def _from_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in data.get("results") or data.get("rules") or []:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("rule_id") or r.get("rule") or r.get("id") or "").strip()
        if not rid:
            continue
        # mSCP rules use 'finding' (True == failed) when a results JSON mirrors the audit plist.
        if "result" in r:
            res = _result_word(r.get("result"))
        elif "finding" in r:
            res = "fail" if r.get("finding") else "pass"
        else:
            res = "pass"
        out.append({
            "rule_id": rid,
            "title": str(r.get("title") or r.get("name") or rid),
            "result": res,
            "severity": str(r.get("severity") or "").lower() or None,
            "references": _refs_str(r.get("references") or r.get("800-53r5")),
            "discussion": str(r.get("discussion") or r.get("description") or "")[:1500],
        })
    return out


def _from_audit_plist(pl: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rid, v in pl.items():
        if not isinstance(rid, str) or rid.startswith("("):
            continue
        finding = bool(v.get("finding")) if isinstance(v, dict) else bool(v)
        out.append({
            "rule_id": rid, "title": rid.replace("_", " "),
            "result": "fail" if finding else "pass",
            "severity": None, "references": "",
            "discussion": (v.get("exempt_reason") if isinstance(v, dict) else "") or "",
        })
    return out


def _from_text(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ln in text.splitlines():
        m = _RULE.match(ln)
        if m:
            out.append({"rule_id": m.group(1), "title": m.group(1).replace("_", " "),
                        "result": _result_word(m.group(2)), "severity": None, "references": "", "discussion": ""})
    return out


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "rb") as fh:
        raw = fh.read()
    baseline = str(params.get("baseline") or "")
    host = str(params.get("host") or "")
    os_name = ""
    results: List[Dict[str, Any]] = []

    head = raw[:64].lstrip()
    if head.startswith(b"bplist") or head.startswith(b"<?xml") or head.startswith(b"<plist"):
        try:
            pl = plistlib.loads(raw)
            results = _from_audit_plist(pl) if isinstance(pl, dict) else []
        except Exception:  # noqa: BLE001
            results = []
    if not results:
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
            if isinstance(data, dict):
                baseline = baseline or str(data.get("baseline") or data.get("benchmark") or "")
                host = host or str(data.get("host") or data.get("hostname") or "")
                os_name = str(data.get("os") or data.get("os_version") or "")
                results = _from_results(data)
                if not results and all(isinstance(v, dict) for v in data.values()):
                    results = _from_audit_plist(data)  # a JSON-ified audit plist
            elif isinstance(data, list):
                results = _from_results({"results": data})
        except Exception:  # noqa: BLE001
            results = _from_text(raw.decode("utf-8", "replace"))

    return {
        "source": SOURCE,
        "compliance": {
            "benchmark": "macOS Security (mSCP)",
            "baseline": baseline or "macOS baseline",
            "os": os_name, "host": host,
            "results": results,
        },
    }


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    c = r["compliance"]
    fails = sum(1 for x in c["results"] if x["result"] == "fail")
    print("baseline=%s host=%s rules=%d failed=%d" % (c["baseline"], c["host"], len(c["results"]), fails))
