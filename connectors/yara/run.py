"""run.py — XORCISM connector: YARA → host findings + YARA rule store.

YARA (https://github.com/VirusTotal/yara) is the pattern-matching engine used to identify
and classify malware. This connector covers BOTH sides of YARA in XORCISM:

  • USAGE   — scan a path and map each match to a finding on the host asset
              ({assets, vulns}: ref = YARA-<rule>, name = rule + matched file).
  • SUPPORT — if a rules file/dir is given, the rules are parsed and returned under "yara"
              so the runner stores them in XTHREAT.YARARULE (browsable, served to agents).

Modes:
  • Offline (no tool) — params["file"] = a saved YARA scan output to parse (default
      `rule  /path` lines; `-m` meta and `-s` strings output are tolerated).
  • Live — params["target"] = a path to scan + params["rules"] = a .yar/.yara rules file;
      if the `yara` binary is on PATH it runs `yara -r -w <rules> <target>` and parses it.

NO database access here (so the connector also runs on a remote worker).
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional

TOOL_NAME = "YARA"
TOOL_URL = "https://github.com/VirusTotal/yara"

# `rule NAME : tag1 tag2 {`  — header of a YARA rule (private/global modifiers tolerated;
# the opening brace may sit on the next line).
_RULE_HDR = re.compile(r"(?m)^[ \t]*(?:private[ \t]+|global[ \t]+)*rule[ \t]+(\w+)[ \t]*(?::[ \t]*([\w \t]+?))?\s*\{")
# default YARA scan line: `RuleName [meta] /path/to/file`  (rule id then the file path).
_MATCH_LINE = re.compile(r"^([A-Za-z_]\w*)\s+(?:\[[^\]]*\]\s+)?(\S.*)$")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    host = str(params.get("host") or params.get("project") or "").strip() or socket.gethostname().split(".")[0]
    rules_path = params.get("rules")
    yara_items = _parse_rule_file(rules_path) if rules_path else []

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            output = fh.read()
    else:
        target = str(params.get("target") or "").strip()
        if not target:
            raise RuntimeError("yara: provide a 'file' (saved scan output) or a 'target' path + 'rules' for live mode")
        output = _run_yara(rules_path, target, workdir)

    vulns = _parse_matches(output, host)
    out: Dict[str, Any] = {
        "assets": [{"hostname": host, "key": host}],
        "services": [], "cpes": [], "vulns": vulns,
    }
    if yara_items:
        out["yara"] = yara_items
        out["source"] = "YARA connector"
    return out


def _run_yara(rules_path: Optional[str], target: str, workdir: str) -> str:
    exe = shutil.which("yara")
    if not exe:
        raise RuntimeError("yara binary not found on PATH; use the 'file' parameter (a saved scan output) instead")
    if not rules_path:
        raise RuntimeError("yara live mode needs a 'rules' file (.yar/.yara)")
    # -r recursive, -w suppress warnings; argv array (no shell).
    r = subprocess.run([exe, "-r", "-w", rules_path, target],  # noqa: S603
                       capture_output=True, text=True, errors="replace", timeout=1800)
    return r.stdout or ""


def _parse_matches(output: str, host: str) -> List[Dict[str, Any]]:
    """Map YARA scan output → findings. One finding per matched rule (files collapsed)."""
    by_rule: Dict[str, Dict[str, Any]] = {}
    for raw in output.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("0x") or line.startswith("error"):
            continue  # `-s` string-detail lines (0x..) and error lines aren't matches
        m = _MATCH_LINE.match(line)
        if not m:
            continue
        rule, path = m.group(1), m.group(2).strip()
        if not path:
            continue
        agg = by_rule.setdefault(rule, {"files": [], "count": 0})
        agg["count"] += 1
        if len(agg["files"]) < 5:
            agg["files"].append(os.path.basename(path) or path)
    vulns: List[Dict[str, Any]] = []
    for rule, agg in by_rule.items():
        files = ", ".join(agg["files"]) + ("…" if agg["count"] > len(agg["files"]) else "")
        name = f"YARA match: {rule} ({agg['count']} file(s): {files})"
        vulns.append({"asset": host, "ref": f"YARA-{rule}", "name": name[:300], "severity": _severity(rule)})
    return vulns


def _severity(rule: str) -> str:
    r = rule.lower()
    if any(k in r for k in ("ransom", "apt", "backdoor", "rootkit", "mimikatz", "cobalt", "webshell", "trojan")):
        return "critical"
    if any(k in r for k in ("malware", "exploit", "shell", "inject", "packer", "suspicious")):
        return "high"
    return "medium"


def _parse_rule_file(path: str) -> List[Dict[str, Any]]:
    """Parse a .yar/.yara file (or a directory of them) into YARARULE store items.
    Lightweight: extracts rule name, tags, meta and a string count per rule; the per-rule
    source is the slice from its `rule` header to the next one."""
    files: List[str] = []
    if os.path.isdir(path):
        for root, _d, fs in os.walk(path):
            for fn in sorted(fs):
                if fn.lower().endswith((".yar", ".yara")):
                    files.append(os.path.join(root, fn))
    else:
        files = [path]

    items: List[Dict[str, Any]] = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except Exception:
            continue
        ns = os.path.splitext(os.path.basename(fp))[0]
        heads = list(_RULE_HDR.finditer(text))
        for i, h in enumerate(heads):
            name = h.group(1)
            tags = " ".join((h.group(2) or "").split())
            body_end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            body = text[h.start():body_end]
            items.append({
                "name": name,
                "namespace": ns,
                "tags": tags,
                "meta": _meta_blurb(body),
                "description": _meta_value(body, "description") or _meta_value(body, "desc") or "",
                "author": _meta_value(body, "author") or "",
                "string_count": len(re.findall(r"(?m)^\s*\$\w*\s*=", body)),
                "source": body.strip()[:8000],
                "reference": f"yara:{ns}:{name}",
            })
    return items


def _meta_value(body: str, key: str) -> str:
    m = re.search(rf'(?mi)^\s*{re.escape(key)}\s*=\s*"([^"]*)"', body)
    return m.group(1).strip() if m else ""


def _meta_blurb(body: str) -> str:
    seg = re.search(r"(?is)\bmeta\s*:(.*?)(?:\bstrings\s*:|\bcondition\s*:)", body)
    if not seg:
        return ""
    pairs = re.findall(r'(?m)^\s*(\w+)\s*=\s*"?([^"\n]*)"?\s*$', seg.group(1))
    return "; ".join(f"{k}={v.strip()}" for k, v in pairs if v.strip())[:1000]


if __name__ == "__main__":
    import argparse
    import json
    import tempfile

    ap = argparse.ArgumentParser(description="YARA import (dry run)")
    ap.add_argument("--file", help="saved YARA scan output to parse")
    ap.add_argument("--target", default="", help="path to scan (live mode)")
    ap.add_argument("--rules", help="YARA rules file/dir (live scan + rule store)")
    ap.add_argument("--host", default="", help="asset name for the findings")
    a = ap.parse_args()
    res = run({"file": a.file, "target": a.target, "rules": a.rules, "host": a.host}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[yara] {len(res['vulns'])} match finding(s), {len(res.get('yara', []))} rule(s) parsed", flush=True)
