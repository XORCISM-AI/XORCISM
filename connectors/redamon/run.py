"""run.py — XORCISM connector: RedAmon findings -> assets / services / cpes / vulns.

RedAmon (https://github.com/samugit83/redamon) is an autonomous AI red-team
framework (recon + exploitation + post-exploitation) that builds a Neo4j
attack-surface graph and exports JSON scan results. It runs as a containerized
platform driven by the analyst; this connector is IMPORT-ONLY — it never runs
RedAmon or any LLM. It parses RedAmon's exports into the normalized result:

  - host / domain / subdomain / IP   -> ASSET
  - open port / service / technology -> service + CPE on that asset
  - vulnerability finding             -> VULNERABILITY (CVE or Nuclei/GVM
                                         template ref, else the title, + severity)

Inputs (any of):
  - file:     a single RedAmon JSON / JSON-lines export
  - dir:      a directory of exports (*.json / *.jsonl)
  - endpoint: a RedAmon backend export URL returning JSON, fetched with
              'Authorization: Bearer <REDAMON_API_KEY>' (worker env var)
  - target:   default host/URL for findings that don't carry their own

The parser is intentionally shape-tolerant: top-level list, or a dict wrapping
the rows under findings/results/vulnerabilities/hosts/assets/nodes/items/data,
Nuclei JSON-lines, host objects with nested vulnerabilities/ports, and Neo4j
node exports ({labels:[...], properties:{...}}). No XORCISM DB access.
"""
from __future__ import annotations

import glob
import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List

_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_SEVS = ("critical", "high", "medium", "low", "informational", "info", "none", "unknown")
_HOST_KEYS = ("hostname", "host", "fqdn", "domain", "subdomain", "ip", "ip_address",
              "ipaddress", "address", "asset", "target", "url", "matched-at", "matched_at")
_VULN_MARK = ("cve", "cve_id", "template-id", "template_id", "templateid", "nvt", "oid",
              "severity", "risk", "vulnerability", "finding")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    blobs: List[Any] = []

    endpoint = str(params.get("endpoint") or "").strip()
    if endpoint:
        blobs.append(_fetch(endpoint))

    files: List[str] = []
    d = str(params.get("dir") or "").strip()
    if d:
        if not os.path.isdir(d):
            raise RuntimeError(f"redamon: directory not found: {d}")
        for pat in ("*.json", "*.jsonl", "*.ndjson"):
            files += glob.glob(os.path.join(d, "**", pat), recursive=True)
    if params.get("file"):
        files.append(str(params["file"]))
    for path in sorted(set(files)):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            continue
        blobs.append(_loads(raw))

    if not blobs:
        raise RuntimeError(
            "redamon: provide 'file', 'dir', or 'endpoint' (a RedAmon JSON export / backend URL)"
        )

    default_target = str(params.get("target") or "").strip()
    state = _State(default_target)
    for b in blobs:
        for rec in _rows(b):
            if isinstance(rec, dict):
                state.handle(rec)
    return state.result()


# ── input acquisition ────────────────────────────────────────────────────────
def _loads(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # JSON-lines: collect one object per line
        out = []
        for line in raw.splitlines():
            line = line.strip()
            if line and line[0] in "{[":
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out


def _fetch(url: str) -> Any:
    if "://" not in url:
        url = "https://" + url
    req = urllib.request.Request(url, headers={"User-Agent": "XORCISM-RedAmon/1.0", "Accept": "application/json"})
    token = os.environ.get("REDAMON_API_KEY", "").strip()
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (analyst-provided endpoint)
        return _loads(r.read().decode("utf-8", "replace"))


_CONTAINER_KEYS = ("findings", "results", "vulnerabilities", "vulns", "hosts", "assets",
                   "nodes", "items", "data", "scan_results", "scanResults", "issues")


def _rows(blob: Any):
    """Yields record dicts from an arbitrarily-wrapped RedAmon export."""
    if isinstance(blob, list):
        for x in blob:
            yield from _rows(x)
        return
    if not isinstance(blob, dict):
        return
    # An entity record (carries a host or a vuln marker) is yielded as-is — its
    # own nested lists (ports / vulnerabilities / …) are walked later by handle(),
    # so we must NOT mistake it for a pure wrapper and drop its host context.
    flat = _flatten(blob)
    if any(_get(flat, k) for k in _HOST_KEYS) or any(k in flat for k in _VULN_MARK):
        yield blob
        return
    # Otherwise treat it as a wrapper: descend into known container lists.
    wrapped = False
    for k in _CONTAINER_KEYS + ("subdomains", "domains"):
        v = blob.get(k)
        if isinstance(v, list):
            wrapped = True
            for x in v:
                if isinstance(x, str):
                    if x.strip() and k in ("subdomains", "domains", "hosts", "assets"):
                        yield {"hostname": x.strip()}
                else:
                    yield from _rows(x)
    if not wrapped:
        yield blob


# ── helpers ──────────────────────────────────────────────────────────────────
def _host(v: str) -> str:
    s = str(v or "").strip()
    if not s:
        return ""
    if "://" in s or "/" in s:
        if "://" not in s:
            s = "http://" + s
        s = urllib.parse.urlparse(s).netloc or s
    return (s.split("@")[-1].split(":")[0] or "").strip().lower()


def _norm_sev(s: str) -> str:
    s = str(s or "").strip().lower()
    if s == "informational":
        s = "info"
    return s.capitalize() if s in _SEVS else (s.capitalize() if s else "")


def _flatten(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Neo4j node ({labels, properties}) -> a flat dict (+ a synthetic _labels)."""
    if isinstance(obj.get("properties"), dict):
        flat = dict(obj["properties"])
        labels = obj.get("labels") or obj.get("label") or obj.get("type")
        flat["_labels"] = " ".join(labels) if isinstance(labels, list) else str(labels or "")
        return flat
    return obj


def _get(obj: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        for kk in (k, k.lower(), k.replace("-", "_"), k.replace("_", "-")):
            if kk in obj and obj[kk] not in (None, "", []):
                val = obj[kk]
                return str(val[0] if isinstance(val, list) and val else val).strip()
    return ""


# ── stateful normalizer ──────────────────────────────────────────────────────
class _State:
    def __init__(self, default_target: str):
        self.default_target = default_target
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.services: List[Dict[str, str]] = []
        self.cpes: set = set()
        self.vulns: List[Dict[str, str]] = []
        self._seen_v: set = set()
        self._seen_s: set = set()

    def add_asset(self, v: str) -> str:
        host = _host(v) or _host(self.default_target)
        if host:
            self.assets.setdefault(host, {"hostname": host, "key": host})
        return host

    def add_cpe(self, asset: str, label: str) -> None:
        label = (label or "").strip()
        if not label:
            return
        self.cpes.add(label)
        key = (asset, label)
        if asset and key not in self._seen_s:
            self._seen_s.add(key)
            self.services.append({"asset": asset, "cpe": label})

    def add_vuln(self, asset: str, ref: str, name: str, sev: str) -> None:
        ref = (ref or name or "").strip()
        if not ref:
            return
        key = (asset, ref.lower())
        if key in self._seen_v:
            return
        self._seen_v.add(key)
        self.vulns.append({"asset": asset, "ref": ref[:300], "name": (name or ref)[:500], "severity": _norm_sev(sev)})

    def handle(self, raw: Dict[str, Any]) -> None:
        obj = _flatten(raw)
        host = ""
        for k in _HOST_KEYS:
            host = _host(_get(obj, k))
            if host:
                break
        asset = self.add_asset(host)

        # nested children: a host record may carry ports/services/vulnerabilities
        for k in ("vulnerabilities", "vulns", "findings", "cves", "ports", "services", "technologies", "tech"):
            child = obj.get(k)
            if isinstance(child, list):
                for ch in child:
                    if isinstance(ch, str):
                        self._str_child(asset, k, ch)
                    elif isinstance(ch, dict):
                        self._dict_child(asset, k, ch)

        # service / port on this record itself
        port = _get(obj, "port")
        svc = _get(obj, "service", "service_name", "protocol")
        cpe = _get(obj, "cpe")
        tech = _get(obj, "technology", "tech", "product", "app")
        if cpe:
            self.add_cpe(asset, cpe)
        if port and (svc or asset):
            self.add_cpe(asset, f"{svc} {port}".strip() if svc else f"port {port}")
        if tech:
            self.add_cpe(asset, tech + ((" " + _get(obj, "version")) if _get(obj, "version") else ""))

        # vulnerability on this record itself
        self._maybe_vuln(asset, obj)

    def _maybe_vuln(self, asset: str, obj: Dict[str, Any]) -> None:
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        labels = (_get(obj, "_labels") or "").lower()
        ref = _get(obj, "cve", "cve_id")
        if not ref:
            ref = _get(obj, "template-id", "template_id", "templateid", "nvt", "oid")
        title = (_get(obj, "name", "title", "vulnerability", "finding", "template")
                 or _get(info, "name") or "")
        sev = _get(obj, "severity", "risk", "criticality") or _get(info, "severity")
        if not ref:
            m = _CVE.search(" ".join((title, _get(obj, "description"), _get(info, "description"))))
            ref = m.group(0) if m else ""
        is_vuln = bool(ref or sev or "vuln" in labels
                       or any(k in obj for k in ("template-id", "template_id", "templateid", "nvt", "oid")))
        if is_vuln and (ref or title):
            self.add_vuln(asset, ref or title, title or ref, sev)

    def _str_child(self, asset: str, kind: str, val: str) -> None:
        val = val.strip()
        if not val:
            return
        if kind in ("vulnerabilities", "vulns", "findings", "cves"):
            m = _CVE.search(val)
            self.add_vuln(asset, m.group(0) if m else val, val, "")
        elif kind in ("technologies", "tech", "services"):
            self.add_cpe(asset, val)
        elif kind == "ports":
            self.add_cpe(asset, f"port {val}")

    def _dict_child(self, asset: str, kind: str, ch: Dict[str, Any]) -> None:
        ch = _flatten(ch)
        # a child may carry its own host (e.g. subdomain records)
        sub = ""
        for k in _HOST_KEYS:
            sub = _host(_get(ch, k))
            if sub:
                break
        a = self.add_asset(sub) or asset
        if kind in ("ports", "services"):
            port = _get(ch, "port")
            svc = _get(ch, "service", "service_name", "protocol", "name")
            cpe = _get(ch, "cpe")
            if cpe:
                self.add_cpe(a, cpe)
            elif port:
                self.add_cpe(a, f"{svc} {port}".strip() if svc else f"port {port}")
            self._maybe_vuln(a, ch)  # a service row may also carry a CVE
        elif kind in ("technologies", "tech"):
            name = _get(ch, "name", "technology", "product")
            ver = _get(ch, "version")
            self.add_cpe(a, (name + " " + ver).strip())
            self._maybe_vuln(a, ch)
        else:  # vulnerabilities / findings / cves
            self._maybe_vuln(a, ch)

    def result(self) -> Dict[str, Any]:
        for v in self.vulns:
            if v["asset"]:
                self.add_asset(v["asset"])
        if not self.assets and self.default_target:
            self.add_asset(self.default_target)
        return {
            "assets": list(self.assets.values()),
            "services": self.services,
            "cpes": sorted(self.cpes),
            "vulns": self.vulns,
        }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="RedAmon findings import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--dir")
    ap.add_argument("--endpoint")
    ap.add_argument("--target", default="")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "dir": a.dir, "endpoint": a.endpoint, "target": a.target},
                         tempfile.mkdtemp()), indent=2))
