"""CryptoScan connector — parse a CryptoScan (github.com/GreyNOC/Crypto-Scan) output file
and normalize its cryptographic assets into XORCISM's CRYPTOASSET shape.

CryptoScan is a proprietary cryptographic-posture / post-quantum-cryptography migration
scanner (Copyright (c) GreyNOC). This connector ships NONE of its code: it only reads the
standard-format output files the operator produces by running their own licensed copy:

    gs tls example.com:443 --cbom cbom.json        # CycloneDX 1.6 CBOM   (richest)
    gs code ./repo --json findings.json            # JSON findings
    gs code ./repo --sarif out.sarif               # SARIF 2.1.0

The connector is import-type, worker-safe and read-only: it parses an exported file and
performs no scanning or network activity itself. It emits a ``crypto_assets`` list; the
runner's import_crypto_assets() classifies each quantum-safe/-vulnerable and writes it to
XORCISM.CRYPTOASSET (surfaced in the CBOM cockpit /cbom and PQCMM /pqcmm).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _from_cyclonedx(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect CycloneDX components that are cryptographic assets (type or cryptoProperties)."""
    comps = doc.get("components") or []
    out: List[Dict[str, Any]] = []
    for c in comps:
        if not isinstance(c, dict):
            continue
        if str(c.get("type") or "").lower() == "cryptographic-asset" or c.get("cryptoProperties"):
            out.append(c)
    return out


def _from_sarif(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Best-effort: map SARIF results to flat crypto assets. CryptoScan encodes the algorithm
    in the rule id / message (e.g. ``crypto.rsa-2048``), so we surface those as algorithm assets."""
    out: List[Dict[str, Any]] = []
    for run in doc.get("runs") or []:
        rules = {}
        try:
            for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
                rules[r.get("id")] = r
        except Exception:  # noqa: BLE001
            pass
        for res in run.get("results") or []:
            rid = str(res.get("ruleId") or "")
            msg = ""
            try:
                msg = str(res.get("message", {}).get("text") or "")
            except Exception:  # noqa: BLE001
                pass
            name = rid.split(".")[-1].split("/")[-1] or msg[:60] or "crypto-finding"
            out.append({"name": name, "algorithm": name, "assetType": "algorithm",
                        "bom-ref": rid or name, "_note": msg[:200]})
    return out


def _collect(doc: Any) -> List[Dict[str, Any]]:
    if isinstance(doc, list):
        return [c for c in doc if isinstance(c, dict)]
    if not isinstance(doc, dict):
        return []
    # native shapes
    if isinstance(doc.get("cryptoAssets"), list):
        return [c for c in doc["cryptoAssets"] if isinstance(c, dict)]
    if isinstance(doc.get("crypto_assets"), list):
        return [c for c in doc["crypto_assets"] if isinstance(c, dict)]
    if isinstance(doc.get("findings"), list):  # generic CryptoScan JSON findings
        return [c for c in doc["findings"] if isinstance(c, dict)]
    # CycloneDX CBOM
    if str(doc.get("bomFormat") or "").lower() == "cyclonedx" or "components" in doc:
        comps = _from_cyclonedx(doc)
        if comps:
            return comps
    # SARIF 2.1.0
    if doc.get("$schema", "").find("sarif") >= 0 or "runs" in doc:
        return _from_sarif(doc)
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    here = os.path.dirname(os.path.abspath(__file__))
    path = params.get("file") or os.path.join(here, "sample.json")
    if not os.path.isabs(path) and not os.path.exists(path):
        cand = os.path.join(workdir or here, path)
        if os.path.exists(cand):
            path = cand
    source = str(params.get("source") or "CryptoScan").strip() or "CryptoScan"
    limit = int(params.get("limit") or 5000)
    asset_id = params.get("asset_id")
    try:
        asset_id = int(asset_id) if asset_id not in (None, "", "null") else None
    except (TypeError, ValueError):
        asset_id = None

    try:
        doc = _load(path)
    except FileNotFoundError:
        return {"crypto_assets": [], "error": "file not found: %s" % path}
    except (json.JSONDecodeError, ValueError) as exc:
        return {"crypto_assets": [], "error": "not valid JSON (%s): %s" % (path, exc)}

    assets = _collect(doc)[: max(1, limit)]
    return {
        "crypto_assets": assets,
        "source": source,
        "asset_id": asset_id,
        "scanned_file": os.path.basename(path),
        "count": len(assets),
    }


if __name__ == "__main__":  # manual dry-run: python run.py [file.json]
    import sys
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    res = run(p, os.getcwd())
    print(json.dumps({k: (v if k != "crypto_assets" else "[%d items]" % len(v))
                      for k, v in res.items()}, indent=2))
