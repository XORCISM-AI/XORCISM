#!/usr/bin/env python3
"""
Pulsedive → XORCISM CTI connector.

Normalizes Pulsedive indicators into XORCISM threat-intel records
(XTHREAT.INTELEXCHANGE) via the standard connector `intel` shape
{name, description, reference, external_id, author, date, tags,
 actor_tags, malware_tags} — idempotent by reference (the Pulsedive URL),
see connectors/runner.py import_threat_intel.

Two modes:
  * LIVE  (needs PULSEDIVE_API_KEY): `query` is either a single indicator
    (enriched via info.php) or a Pulsedive Explore query in PDQL
    (searched via explore.php).
  * FILE  (offline): parse a saved export — bulk CSV, an Explore result
    JSON ({"results":[…]}), a single indicator JSON (info.php), or an
    array of indicators.

Worker-safe, read-only, licence-safe: only ever contacts the fixed
pulsedive.com API with the operator's own key, or reads an export file.
No Pulsedive code is vendored.
"""
import csv
import io
import json
import os
import re
import sys
import urllib.parse
import urllib.request

TOOL_URL = "https://pulsedive.com/"
API_BASE = "https://pulsedive.com/api/"
SOURCE = "Pulsedive"
MAX_BYTES = 25 * 1024 * 1024
TIMEOUT = 25

RISKS = ("unknown", "none", "low", "medium", "high", "critical", "retired")
IOC_RX = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{3,}|[\w.-]+\.[a-z]{2,}|https?://\S+|[a-f0-9]{32,64})$", re.I)


def _norm(s):
    return " ".join(str(s or "").lower().replace("_", " ").replace("-", " ").split())


def _http_get(path, params):
    url = API_BASE + path + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "XORCISM-connector/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # nosec B310 — fixed https host
        raw = resp.read(MAX_BYTES + 1)
    return json.loads(raw.decode("utf-8", "replace"))


# ── Indicator → normalized intel item ───────────────────────────────────────────
def _risk_of(ind):
    r = _norm(ind.get("risk") or ind.get("risk_recommended") or "unknown")
    return r if r in RISKS else "unknown"


def _threat_names(ind):
    out = []
    for t in ind.get("threats") or []:
        if isinstance(t, dict):
            n = str(t.get("name") or t.get("tid") or "").strip()
        else:
            n = str(t).strip()
        if n:
            out.append(n)
    return out


def _feed_names(ind):
    out = []
    for f in ind.get("feeds") or []:
        if isinstance(f, dict):
            n = str(f.get("name") or f.get("fid") or "").strip()
        else:
            n = str(f).strip()
        if n:
            out.append(n)
    return out


def _riskfactor_text(ind):
    out = []
    for rf in ind.get("riskfactors") or []:
        if isinstance(rf, dict):
            d = str(rf.get("description") or rf.get("rfid") or "").strip()
        else:
            d = str(rf).strip()
        if d:
            out.append(d)
    return out


def map_indicator(ind):
    value = str(ind.get("indicator") or ind.get("value") or ind.get("Indicator") or "").strip()
    if not value:
        return None
    itype = _norm(ind.get("type") or ind.get("Type") or "indicator") or "indicator"
    risk = _risk_of({"risk": ind.get("risk") or ind.get("Risk"), "risk_recommended": ind.get("risk_recommended")})
    iid = str(ind.get("iid") or "").strip()
    threats = _threat_names(ind)
    feeds = _feed_names(ind)
    rfs = _riskfactor_text(ind)

    ref = f"https://pulsedive.com/indicator/?iid={iid}" if iid else f"pulsedive:{value}"
    parts = [f"Pulsedive risk: {risk}."]
    if rfs:
        parts.append("Risk factors: " + "; ".join(rfs[:8]) + ".")
    if threats:
        parts.append("Threats: " + ", ".join(threats[:12]) + ".")
    if feeds:
        parts.append("Feeds: " + ", ".join(feeds[:12]) + ".")
    seen = str(ind.get("stamp_seen") or ind.get("lastseen") or ind.get("stamp_updated") or "").strip()

    tags = ["pulsedive", "cti", itype, "risk:" + risk]
    for f in feeds[:8]:
        tags.append("feed:" + f)

    return {
        "name": (f"{risk} {itype}: {value}")[:200],
        "description": " ".join(parts)[:1000],
        "reference": ref[:200],
        "external_id": value[:200],
        "author": SOURCE,
        "date": (seen[:10] if seen else None),
        "tags": ",".join(tags)[:500],
        # Pulsedive threats are named campaigns/malware families → surface as actor+malware tags
        "actor_tags": ",".join(threats[:20]) or None,
        "malware_tags": ",".join(threats[:20]) or None,
        "risk": risk,
        "pd_type": itype,
    }


# ── Parsers (offline file mode) ─────────────────────────────────────────────────
def _read_text(path):
    with open(path, "rb") as fh:
        raw = fh.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("file too large")
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _parse_csv(text):
    """Pulsedive bulk CSV export → list of indicator dicts (defensive headers)."""
    try:
        delim = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|").delimiter
    except Exception:
        delim = ","
    out = []
    for row in csv.DictReader(io.StringIO(text), delimiter=delim):
        norm = {_norm(k): v for k, v in row.items() if k}
        value = (norm.get("indicator") or norm.get("ioc") or norm.get("value") or "").strip()
        if not value:
            continue
        threats = [t.strip() for t in re.split(r"[|,;]", norm.get("threats", "")) if t.strip()]
        feeds = [f.strip() for f in re.split(r"[|,;]", norm.get("feeds", "")) if f.strip()]
        out.append({
            "indicator": value,
            "type": norm.get("type") or norm.get("indicator type") or "",
            "risk": norm.get("risk") or "",
            "iid": norm.get("iid") or "",
            "stamp_seen": norm.get("last seen") or norm.get("stamp seen") or "",
            "threats": threats,
            "feeds": feeds,
        })
    return out


def _indicators_from_json(data):
    """Accept a single indicator, an explore result {results:[…]}, {data:{…}}, or an array."""
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data["results"]
        if isinstance(data.get("indicators"), list):
            return data["indicators"]
        if isinstance(data.get("data"), dict):
            return [data["data"]]
        if data.get("indicator") or data.get("iid"):
            return [data]
        return []
    if isinstance(data, list):
        return data
    return []


# ── Live mode ───────────────────────────────────────────────────────────────────
def _looks_like_single_ioc(q):
    q = q.strip()
    return bool(IOC_RX.match(q)) and " " not in q and "=" not in q


def _live(query, key, limit):
    query = query.strip()
    if _looks_like_single_ioc(query):
        data = _http_get("info.php", {"indicator": query, "key": key, "pretty": "0"})
        if isinstance(data, dict) and (data.get("indicator") or data.get("iid")):
            return [data]
        # not found as an existing indicator → nothing to import (avoid queuing a scan silently)
        return []
    # Pulsedive Explore query (PDQL)
    data = _http_get("explore.php", {"q": query, "limit": str(limit), "key": key, "pretty": "0"})
    return _indicators_from_json(data)


# ── Entry point ─────────────────────────────────────────────────────────────────
def run(params, workdir):  # noqa: ARG001
    params = params or {}
    limit = int(params.get("limit") or 500)
    path = params.get("file")
    query = (params.get("query") or "").strip()
    key = os.environ.get("PULSEDIVE_API_KEY", "").strip()

    raw_indicators = []
    if path and os.path.exists(path):
        text = _read_text(path)
        stripped = text.lstrip()
        if stripped[:1] in ("{", "["):
            try:
                raw_indicators = _indicators_from_json(json.loads(text))
            except Exception as e:  # noqa: BLE001
                sys.stderr.write(f"[pulsedive] JSON parse failed: {e}\n")
        else:
            raw_indicators = _parse_csv(text)
    elif query and key:
        try:
            raw_indicators = _live(query, key, limit)
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"[pulsedive] API call failed: {e}\n")
    elif query and not key:
        sys.stderr.write("[pulsedive] live query given but PULSEDIVE_API_KEY is not set.\n")

    intel, seen = [], set()
    by_risk = {r: 0 for r in RISKS}
    for ind in raw_indicators[: limit * 4]:
        if not isinstance(ind, dict):
            continue
        item = map_indicator(ind)
        if not item or item["reference"] in seen:
            continue
        seen.add(item["reference"])
        by_risk[item.get("risk", "unknown")] = by_risk.get(item.get("risk", "unknown"), 0) + 1
        # strip helper keys not consumed by the importer
        item.pop("pd_type", None)
        item.pop("risk", None)
        intel.append(item)
        if len(intel) >= limit:
            break

    counts = {"indicators": len(intel)}
    counts.update({r: by_risk[r] for r in RISKS if by_risk[r]})
    return {"source": SOURCE, "assets": [], "services": [], "cpes": [], "vulns": [], "intel": intel,
            "counts": counts, "tool": TOOL_URL}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Pulsedive → XORCISM CTI (INTELEXCHANGE)")
    ap.add_argument("--file", help="Saved Pulsedive export (CSV / JSON)")
    ap.add_argument("--query", default="", help="Single indicator or PDQL Explore query (live; needs PULSEDIVE_API_KEY)")
    ap.add_argument("--limit", type=int, default=500)
    a = ap.parse_args()

    if not a.file and not (a.query and os.environ.get("PULSEDIVE_API_KEY")):
        # Offline sample: two enriched indicators, as info.php would return them.
        sample = {"results": [
            {"iid": 12345, "indicator": "89.190.156.145", "type": "ip", "risk": "high",
             "riskfactors": [{"description": "Observed in threat feeds"}, {"description": "Open SMB port"}],
             "threats": [{"name": "Emotet"}], "feeds": [{"name": "Feodo Tracker"}], "stamp_seen": "2026-06-30 12:00:00"},
            {"iid": 67890, "indicator": "malicious-example.com", "type": "domain", "risk": "critical",
             "riskfactors": [{"description": "Known phishing domain"}],
             "threats": [{"name": "Phishing Kit"}], "feeds": [{"name": "OpenPhish"}], "stamp_seen": "2026-07-01 09:30:00"},
        ]}
        fp = os.path.join(tempfile.mkdtemp(), "pulsedive_sample.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp

    res = run({"file": a.file, "query": a.query, "limit": a.limit}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[pulsedive] {res['counts']['indicators']} indicator(s) → XTHREAT.INTELEXCHANGE "
          f"(tool: {TOOL_URL})", file=sys.stderr)
