"""run.py — XORCISM connector for Cedar / Amazon Verified Permissions (AVP).

Cedar (https://www.cedarpolicy.com) is the open authorization language behind AWS Verified Permissions,
evaluating Principal-Action-Resource-Context (PARC). This connector imports a Cedar inventory into
XORCISM's API Authorization Governance (/authz-governance):
  * the policy store / AVP   -> a PDP   (engine="cedar")
  * each Cedar policy         -> a policy (engine="cedar", language="cedar"); Cedar is deny-by-default
                                by design (allow only on an explicit `permit`), so default_deny=true
  * any gateways delegating   -> a gateway (PEP) referencing the PDP

Modes:
    offline : params["file"] -> parse an AVP ListPolicies export ({policies:[{policyId,definition,...}]})
              or an inventory JSON ({pdps, gateways, policies}).
    demo    : no file -> emit the bundled sample.json.

Normalized result: {source, authz_pdps, authz_gateways, authz_policies} -> runner.import_authz.
Worker-safe: stdlib only, no live access, no DB access, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

PDP_NAME = "Amazon Verified Permissions"


def _policies_from_avp(data: Any) -> List[Dict[str, Any]]:
    rows = data.get("policies") if isinstance(data, dict) else None
    out: List[Dict[str, Any]] = []
    for p in (rows or []):
        if not isinstance(p, dict):
            continue
        out.append({
            "name": p.get("policyId") or p.get("policyStoreId") or "cedar-policy",
            "engine": "cedar", "language": "cedar", "pdp_name": PDP_NAME,
            "default_deny": True,  # Cedar denies unless an explicit permit matches
            "notes": str(p.get("description") or "")[:200] or None,
        })
    return out


def _normalize(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict) and ("pdps" in data or "gateways" in data or "policies" in data):
        return {
            "source": "cedar", "authz_pdps": data.get("pdps") or [],
            "authz_gateways": data.get("gateways") or [], "authz_policies": data.get("policies") or [],
        }
    return {
        "source": "cedar",
        "authz_pdps": [{"name": PDP_NAME, "engine": "cedar", "endpoint": "https://verifiedpermissions.amazonaws.com", "authzen_compliant": False, "status": "unknown"}],
        "authz_gateways": [],
        "authz_policies": _policies_from_avp(data),
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
