"""run.py — XORCISM connector for CRANE (CRA norm engine; github.com/cra-norm-engine/crane).

CRANE is a self-hosted EU Cyber Resilience Act (Regulation (EU) 2024/2847) compliance platform. This
connector imports a CRANE export into XORCISM's CRA conformity cockpit (/cra-compliance):
  * each product with digital elements -> a CRAPRODUCT (name, class, manufacturer, support period,
                                          conformity route)
  * each release                        -> a CRARELEASE (version, date, status, SBOM link)
  * each Annex I assessment             -> a CRAREQUIREMENT status (Part I product security /
                                          Part II vulnerability handling), by reference

Modes:
    offline : params["file"] -> parse a CRANE products export ({products:[...]} or a list).
    demo    : no file -> emit the bundled sample.json.

Normalized result: {source, cra_products:[{name, class, manufacturer, support_until, conformity_route,
description, releases:[...], requirements:[{ref,status,evidence}]}]} -> runner.import_cra_products.
Worker-safe: stdlib only, no live access, no DB access, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

# CRANE class labels -> XORCISM CRA classes
_CLASS = {
    "default": "default", "none": "default", "": "default",
    "class i": "class-i", "class-i": "class-i", "important-i": "class-i", "i": "class-i",
    "class ii": "class-ii", "class-ii": "class-ii", "important-ii": "class-ii", "ii": "class-ii",
    "critical": "critical",
}
_STATUS = {"met": "met", "compliant": "met", "pass": "met", "passed": "met", "yes": "met",
           "partial": "partial", "in-progress": "partial", "inprogress": "partial",
           "gap": "gap", "fail": "gap", "failed": "gap", "no": "gap", "open": "gap",
           "na": "na", "n/a": "na", "not-applicable": "na"}


def _rows(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for k in ("products", "items", "results", "data"):
            v = data.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def _cls(v: Any) -> str:
    return _CLASS.get(str(v or "").strip().lower(), "default")


def _norm_release(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "version": str(r.get("version") or r.get("name") or r.get("tag") or ""),
        "release_date": str(r.get("release_date") or r.get("date") or r.get("released_at") or "")[:10],
        "status": str(r.get("status") or r.get("state") or "draft"),
        "sbom_id": r.get("sbom_id") or r.get("sbomId"),
    }


def _norm_req(r: Dict[str, Any]) -> Dict[str, Any]:
    ref = str(r.get("ref") or r.get("requirement") or r.get("id") or "").strip()
    return {"ref": ref, "status": _STATUS.get(str(r.get("status") or "").strip().lower(), "gap"),
            "evidence": str(r.get("evidence") or r.get("note") or "")[:1000]}


def _norm_product(p: Dict[str, Any]) -> Dict[str, Any]:
    rels = p.get("releases") or p.get("versions") or []
    reqs = p.get("requirements") or p.get("annex_i") or p.get("assessments") or []
    return {
        "name": str(p.get("name") or p.get("product_name") or p.get("title") or "product"),
        "description": str(p.get("description") or "")[:2000],
        "class": _cls(p.get("class") or p.get("product_class") or p.get("category")),
        "manufacturer": str(p.get("manufacturer") or p.get("vendor") or ""),
        "support_until": str(p.get("support_until") or p.get("support_end") or p.get("eol") or "")[:10],
        "conformity_route": str(p.get("conformity_route") or p.get("conformity") or ""),
        "target_sl": str(p.get("target_sl") or p.get("security_level") or p.get("sl") or ""),
        "releases": [_norm_release(r) for r in rels if isinstance(r, dict)],
        "requirements": [q for q in (_norm_req(r) for r in reqs if isinstance(r, dict)) if q["ref"]],
    }


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    products = [_norm_product(p) for p in _rows(data)]
    return {"source": "crane", "cra_products": products}


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
