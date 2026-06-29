"""run.py — XORCISM connector for an AuthZEN-conformant PDP.

AuthZEN (https://openid.net/wg/authzen/) is the OpenID Foundation's vendor-neutral Authorization API:
a standard request/response for an external Policy Decision Point (POST /access/v1/evaluation with
{subject, action, resource, context} -> {decision: true|false}). Any enforcement point (PEP) can talk to
any conformant decision point (PDP). This connector imports an AuthZEN inventory into XORCISM's API
Authorization Governance (/authz-governance):
  * the PDP                   -> a PDP   (engine="authzen", authzen_compliant=true)
  * each policy                -> a policy
  * any gateways delegating    -> a gateway (PEP) referencing the PDP

Modes:
    offline : params["file"] -> parse an inventory JSON ({pdps, gateways, policies}).
    demo    : no file -> emit the bundled sample.json.

Normalized result: {source, authz_pdps, authz_gateways, authz_policies} -> runner.import_authz.
Worker-safe: stdlib only, no live access, no DB access, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict


def _normalize(data: Any) -> Dict[str, Any]:
    pdps = (data.get("pdps") if isinstance(data, dict) else None) or []
    for p in pdps:
        if isinstance(p, dict):
            p.setdefault("engine", "authzen")
            p.setdefault("authzen_compliant", True)  # by definition of this connector
    return {
        "source": "authzen",
        "authz_pdps": pdps,
        "authz_gateways": (data.get("gateways") if isinstance(data, dict) else None) or [],
        "authz_policies": (data.get("policies") if isinstance(data, dict) else None) or [],
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
