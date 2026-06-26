"""run.py -- XORCISM connector for Hunt.io (hunt.io) threat-intelligence API.

Hunt.io continuously scans the internet for malicious infrastructure — command-and-control (C2)
servers, malware delivery, SSL certificates, JARM/JA4 hashes, open directories (AttackCapture). This
connector enriches your CTI from the Hunt.io API (https://api.hunt.io/v1, auth header `token: ak_...`):

  - IP enrichment   GET /v1/enrich/ip/{ip}   (param `ip`)   -> one intel record on that IP's activity
  - Active C2 feed  GET /v1/c2s              (default)      -> many intel records of live C2 servers

Each result becomes a XTHREAT.INTELEXCHANGE record (via runner.import_threat_intel, idempotent by the
reference), with the malware family, AS/country, certificate and JARM/JA4 fingerprints, and the
C2 ATT&CK technique (T1071). Offline: pass `file` = a Hunt.io JSON response, or run the bundled sample.

Worker-safe: stdlib only (urllib), API key via env (HUNTIO_API_KEY / HUNT_API_KEY), ASCII-only, no DB.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List

SOURCE = "Hunt.io"
BASE = os.environ.get("HUNTIO_BASE", "https://api.hunt.io/v1").rstrip("/")


def _key() -> str:
    for k in ("HUNTIO_API_KEY", "HUNT_API_KEY", "HUNTIO_TOKEN", "HUNT_IO_TOKEN"):
        v = os.environ.get(k)
        if v:
            return v.strip()
    return ""


def _api(path: str, key: str, timeout: int = 30) -> Any:
    req = urllib.request.Request(f"{BASE}{path}", headers={"token": key, "Accept": "application/json", "User-Agent": "XORCISM-hunt-io"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (https base, key required)
        return json.loads(r.read().decode("utf-8", "replace") or "null")


def _pick(d: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return default


def _csv(xs: Any) -> str:
    if isinstance(xs, (list, tuple, set)):
        return ", ".join(str(x) for x in xs if x not in (None, ""))
    return str(xs) if xs not in (None, "") else ""


def _c2_to_intel(c: Dict[str, Any]) -> Dict[str, Any]:
    ip = _pick(c, ["ip", "ip_address", "host"])
    port = _pick(c, ["port", "dst_port"])
    mal = _pick(c, ["malware", "malware_name", "family", "threat", "tag", "name"], "Unknown")
    country = _pick(c, ["country", "country_code", "geo_country"], "")
    asn = _pick(c, ["as_name", "asn", "as_org", "organization"], "")
    cert = _pick(c, ["cert_subject", "subject", "ssl_subject", "certificate"], "")
    jarm = _pick(c, ["jarm"], "")
    ja4 = _pick(c, ["ja4", "ja4s", "ja4x"], "")
    seen = _pick(c, ["last_seen", "lastseen", "scan_date", "seen", "timestamp", "first_seen"], "")
    conf = _pick(c, ["confidence", "score"], "")
    where = f"{ip}:{port}" if ip and port else (str(ip) if ip else _csv(_pick(c, ["id", "_id"], "")))
    desc = (f"Active C2 server flagged by Hunt.io. malware={mal}"
            + (f"; AS={asn}" if asn else "") + (f"; country={country}" if country else "")
            + (f"; cert={cert}" if cert else "") + (f"; JARM={jarm}" if jarm else "")
            + (f"; JA4={ja4}" if ja4 else "") + (f"; confidence={conf}" if conf != "" else "")
            + (f"; last_seen={seen}" if seen else ""))
    return {
        "name": f"Hunt.io C2: {mal} @ {where}"[:500],
        "description": desc[:8000],
        "reference": f"huntio:c2:{where}" if where else f"huntio:c2:{mal}",
        "external_id": str(where) if where else None,
        "author": SOURCE, "date": str(seen)[:10],
        "attack_tags": "T1071",  # Application Layer Protocol (C2)
        "actor_tags": "", "malware_tags": _csv(mal) if str(mal).lower() != "unknown" else "",
        "cve_tags": "", "tags": _csv([SOURCE, "C2"] + [x for x in (country, mal) if x and str(x).lower() != "unknown"]),
        "views": 0,
    }


def _ip_to_intel(ip: str, d: Dict[str, Any]) -> Dict[str, Any]:
    obj = d.get("data") if isinstance(d.get("data"), dict) else d
    obj = obj if isinstance(obj, dict) else {}
    mal = _pick(obj, ["malware", "malware_name", "family", "threats", "tags"], "")
    asn = _pick(obj, ["as_name", "asn", "as_org", "organization"], "")
    country = _pick(obj, ["country", "country_code"], "")
    ports = _pick(obj, ["open_ports", "ports"], "")
    cls = _pick(obj, ["classification", "verdict", "category"], "")
    desc = (f"Hunt.io IP enrichment for {ip}."
            + (f" classification={cls}" if cls else "") + (f" malware={_csv(mal)}" if mal else "")
            + (f" AS={asn}" if asn else "") + (f" country={country}" if country else "")
            + (f" open_ports={_csv(ports)}" if ports else ""))
    return {
        "name": f"Hunt.io IP enrichment: {ip}"[:500],
        "description": desc[:8000],
        "reference": f"huntio:ip:{ip}", "external_id": ip,
        "author": SOURCE, "date": str(_pick(obj, ["last_seen", "scan_date"], ""))[:10],
        "attack_tags": "", "actor_tags": "", "malware_tags": _csv(mal), "cve_tags": "",
        "tags": _csv([SOURCE, "IP", country] + ([cls] if cls else [])), "views": 0,
    }


def _items(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("data", "c2s", "results", "feed", "items"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    ip = str(params.get("ip") or "").strip()
    key = _key()
    intel: List[Dict[str, Any]] = []

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        if ip:
            intel = [_ip_to_intel(ip, data)]
        else:
            intel = [_c2_to_intel(c) for c in _items(data)]
    elif ip and key:
        intel = [_ip_to_intel(ip, _api(f"/enrich/ip/{ip}", key))]
    elif key:
        try:
            limit = int(params.get("limit") or 200)
        except (TypeError, ValueError):
            limit = 200
        data = _api(f"/c2s?limit={limit}", key)
        intel = [_c2_to_intel(c) for c in _items(data)][:limit]
    else:
        sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.json")
        with open(sample, "r", encoding="utf-8", errors="replace") as fh:
            intel = [_c2_to_intel(c) for c in _items(json.load(fh))]

    return {"source": SOURCE, "intel": intel, "count": len(intel)}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    print("Hunt.io: %d intel record(s)" % r["count"])
    for x in r["intel"][:6]:
        print("  %-22s  %s" % (x["external_id"] or "-", x["name"][:60]))
