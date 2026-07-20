"""run.py — XORCISM connector for PyAhmia (codeberg.org/rly0nheart/pyahmia, MIT).

PyAhmia searches Tor hidden services via Ahmia.fi (the clearnet search engine for .onion services,
by Juha Nurmi). Each result is a discovered hidden service: title, .onion URL, description and a
"last seen" timestamp. This is darkweb OSINT/discovery, so results map to XORCISM's CTI intel
exchange: each onion service -> one XTHREAT.INTELEXCHANGE item (runner.import_threat_intel), keyed
by its .onion URL, tagged darkweb/tor/onion — surfacing at /cti-expert, the STIX graph and the
threat-intel views (same home as the X-OSINT / RedRoom / IRONSIGHT OSINT connectors).

Modes (in order):
    live : query Ahmia.fi (AHMIA_BASE, default https://ahmia.fi) /search/?q=<query> and parse the
           HTML results. Set AHMIA_BASE to Ahmia's onion + route the worker through Tor for --use-tor
           parity. A `query` parameter is required for live mode.
    file : params["file"] -> a PyAhmia CSV export, or a saved Ahmia results HTML page.
    demo : neither -> the bundled sample.json.

Authorised OSINT only. Worker-safe: stdlib only (urllib + html.parser), a fixed operator-configurable
endpoint (anti-SSRF), no secrets, ASCII-only output.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional

SOURCE = "PyAhmia (Ahmia.fi)"
# match a COMPLETE onion label (v3=56 chars, legacy v2=16) — the lookbehind stops a 16-char tail of a
# longer alnum run from matching a non-onion substring.
_ONION_RE = re.compile(r"(?<![a-z2-7])([a-z2-7]{56}|[a-z2-7]{16})\.onion", re.I)
_PERIODS = {"day": "1", "week": "7", "month": "30"}


def _onion(text: str) -> str:
    m = _ONION_RE.search(text or "")
    return (m.group(0).lower() if m else "")


class _AhmiaParser(HTMLParser):
    """Tolerant parser for Ahmia's /search results: each <li class='result'> holds an <a> title
    (its href is a /search/redirect?...redirect_url=<onion>), a <cite> onion, a <p> description and
    a last-seen span. We collect text per result and pull the onion from any href or visible text."""

    def __init__(self) -> None:
        super().__init__()
        self.results: List[Dict[str, str]] = []
        self._cur: Optional[Dict[str, Any]] = None
        self._buf: List[str] = []
        self._depth = 0
        self._in_title = False
        self._title: List[str] = []

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        a = dict(attrs)
        cls = (a.get("class") or "")
        if tag == "li" and "result" in cls:
            self._cur = {"onion": "", "title": "", "text": []}
            self._depth = 1
            return
        if self._cur is None:
            return
        if tag == "li":
            self._depth += 1
        if tag == "a":
            href = a.get("href") or ""
            # onion may be in a redirect_url query param or the href itself
            if "redirect_url=" in href:
                self._cur["onion"] = self._cur["onion"] or _onion(urllib.parse.unquote(href))
            elif ".onion" in href:
                self._cur["onion"] = self._cur["onion"] or _onion(href)
            if not self._cur.get("title"):
                self._in_title = True
                self._title = []

    def handle_endtag(self, tag: str) -> None:
        if self._cur is None:
            return
        if tag == "a" and self._in_title:
            self._in_title = False
            self._cur["title"] = " ".join("".join(self._title).split())[:300]
        if tag == "li":
            self._depth -= 1
            if self._depth <= 0:
                blob = " ".join(self._cur["text"])
                self._cur["onion"] = self._cur["onion"] or _onion(blob)
                if self._cur["onion"]:
                    self._cur["text"] = " ".join(blob.split())[:2000]
                    self.results.append(self._cur)  # type: ignore[arg-type]
                self._cur = None

    def handle_data(self, data: str) -> None:
        if self._cur is None:
            return
        if self._in_title:
            self._title.append(data)
        s = data.strip()
        if s:
            self._cur["text"].append(s)


def _parse_html(html: str) -> List[Dict[str, str]]:
    p = _AhmiaParser()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001 — tolerant of malformed markup
        pass
    if p.results:
        return p.results
    # fallback: no <li class=result> matched — pull bare onion mentions with nearby text
    out, seen = [], set()
    for m in _ONION_RE.finditer(html):
        o = m.group(0).lower()
        if o in seen:
            continue
        seen.add(o)
        ctx = re.sub(r"<[^>]+>", " ", html[max(0, m.start() - 160):m.end() + 160])
        out.append({"onion": o, "title": "", "text": " ".join(ctx.split())[:500]})
    return out


def _parse_csv(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for r in csv.DictReader(io.StringIO(text)):
        low = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
        onion = _onion(low.get("url", "") or low.get("onion", "") or low.get("link", "") or " ".join(low.values()))
        if not onion:
            continue
        rows.append({"onion": onion, "title": low.get("title", "") or low.get("name", ""),
                     "text": low.get("description", "") or low.get("snippet", ""),
                     "last_seen": low.get("last_seen", "") or low.get("lastseen", "") or low.get("seen", "")})
    return rows


def _fetch_live(query: str, params: Dict[str, Any]) -> str:
    base = (os.environ.get("AHMIA_BASE") or "https://ahmia.fi").rstrip("/")
    q = {"q": query}
    period = str(params.get("period") or "").lower()
    if period in _PERIODS:
        q["d"] = _PERIODS[period]
    url = f"{base}/search/?" + urllib.parse.urlencode(q)
    proxy = os.environ.get("AHMIA_SOCKS") or os.environ.get("HTTPS_PROXY")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy})) if proxy else urllib.request.build_opener()
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (XORCISM pyahmia connector)"})
    with opener.open(req, timeout=int(params.get("timeout") or 45)) as resp:  # noqa: S310 (fixed, operator-configurable host)
        return resp.read().decode("utf-8", "replace")


def _to_intel(rows: List[Dict[str, str]], query: str, limit: int) -> List[Dict[str, Any]]:
    intel: List[Dict[str, Any]] = []
    seen = set()
    for r in rows:
        onion = r.get("onion") or ""
        if not onion or onion in seen:
            continue
        seen.add(onion)
        url = f"http://{onion}/"
        title = (r.get("title") or "").strip() or onion
        desc = (r.get("text") or "").strip()
        last = (r.get("last_seen") or "").strip()
        body = f"Tor hidden service discovered via Ahmia.fi for query '{query}'. {desc}".strip()
        if last:
            body += f" [last seen: {last}]"
        body += f"\n{url}"
        tags = ["darkweb", "tor", "onion", "ahmia", "osint"]
        if query and query.lower() not in tags:
            tags.append(query)
        intel.append({
            "name": title[:300],
            "description": body[:4000],
            "reference": url,                       # onion URL = idempotency key
            "external_id": onion,
            "date": None,
            "tags": ",".join(dict.fromkeys(tags)),  # dedupe, preserve order
        })
        if len(intel) >= limit:
            break
    return intel


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    query = str(params.get("query") or params.get("target") or "").strip()
    limit = int(params.get("limit") or 100)
    rows: List[Dict[str, str]] = []

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        low = text.lstrip().lower()
        if low.startswith("<") or ".onion" in low and ("<html" in low or "<li" in low or "<a " in low):
            rows = _parse_html(text)
        else:
            try:
                data = json.loads(text)
                items = data.get("results") or data.get("intel") or data if isinstance(data, (list, dict)) else []
                if isinstance(items, dict):
                    items = items.get("results") or []
                for it in items:
                    if isinstance(it, dict):
                        rows.append({"onion": _onion(it.get("url") or it.get("onion") or it.get("reference") or ""),
                                     "title": it.get("title") or it.get("name") or "",
                                     "text": it.get("description") or it.get("snippet") or "",
                                     "last_seen": it.get("last_seen") or ""})
            except json.JSONDecodeError:
                rows = _parse_csv(text)
    elif query:
        rows = _parse_html(_fetch_live(query, params))
    else:
        with open(os.path.join(os.path.dirname(__file__), "sample.json"), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        query = query or data.get("query") or "sample"
        for it in data.get("results") or []:
            rows.append({"onion": _onion(it.get("url", "")), "title": it.get("title", ""),
                         "text": it.get("description", ""), "last_seen": it.get("last_seen", "")})

    return {"source": SOURCE, "assets": [], "services": [], "cpes": [], "vulns": [],
            "intel": _to_intel(rows, query or "ahmia", limit)}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    print(json.dumps({"source": r["source"], "intel": len(r["intel"])}))
    print(json.dumps(r["intel"][:2], indent=1))
