"""run.py — XORCISM connector for Open Policy Agent (OPA).

OPA (https://www.openpolicyagent.org) is the CNCF policy engine (Rego language) commonly used as the
external Policy Decision Point (PDP) behind API gateways. This connector imports an OPA authorization
inventory into XORCISM's API Authorization Governance (/authz-governance):
  * the OPA instance         -> a PDP   (engine="opa")
  * each Rego policy module   -> a policy (engine="opa", language="rego"), with default-deny detected
                                from the module text and versioned/tested flags if provided
  * any gateways delegating   -> a gateway (PEP) referencing the PDP

Modes:
    offline : params["file"] -> parse an OPA `/v1/policies` export ({result:[{id,raw,...}]}) or an
              inventory JSON ({pdps, gateways, policies}).
    demo    : no file -> emit the bundled sample.json.

Normalized result: {source, authz_pdps:[...], authz_gateways:[...], authz_policies:[...]} -> runner.import_authz.
Worker-safe: stdlib only, no live access, no DB access, ASCII-only output.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict, List

PDP_NAME = "OPA"


def _default_deny(rego: str) -> bool:
    """A Rego module is deny-by-default if `allow` starts false (e.g. `default allow := false`)."""
    txt = (rego or "").replace(" ", "").lower()
    return ("defaultallow=false" in txt) or ("defaultallow:=false" in txt)


def _policies_from_opa_export(data: Any) -> List[Dict[str, Any]]:
    """OPA GET /v1/policies -> {result: [{id, raw}]}."""
    result = data.get("result") if isinstance(data, dict) else None
    out: List[Dict[str, Any]] = []
    for m in (result or []):
        if not isinstance(m, dict):
            continue
        raw = str(m.get("raw") or "")
        out.append({
            "name": m.get("id") or "policy.rego", "engine": "opa", "language": "rego",
            "pdp_name": PDP_NAME, "default_deny": _default_deny(raw),
            "content_hash": hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16] if raw else None,
        })
    return out


def _normalize(data: Any) -> Dict[str, Any]:
    # inventory JSON ({pdps, gateways, policies}) passes through; OPA export -> policies only.
    if isinstance(data, dict) and ("pdps" in data or "gateways" in data or "policies" in data):
        return {
            "source": "opa", "authz_pdps": data.get("pdps") or [],
            "authz_gateways": data.get("gateways") or [], "authz_policies": data.get("policies") or [],
        }
    pols = _policies_from_opa_export(data)
    return {
        "source": "opa",
        "authz_pdps": [{"name": PDP_NAME, "engine": "opa", "endpoint": "http://localhost:8181", "authzen_compliant": False, "status": "unknown"}],
        "authz_gateways": [],
        "authz_policies": pols,
    }


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    return _normalize(data)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
