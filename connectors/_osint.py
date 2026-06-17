"""_osint.py — shared engine for the OSINT Newsletter "pivot" connectors.

These connectors wrap third-party OSINT web tools/services imported from
https://tools.osintnewsletter.com/ into XORCISM.TOOL. Most are interactive (no
automatable API), so a connector does not "scan": it turns a `target` observable
(email / domain / IP / username / hash / crypto address / phone / URL / name) into
a PIVOT — a deep-link into the tool with the target injected when the tool exposes
a stable query URL, otherwise a reference to the tool's page so the analyst opens
it manually.

Pivots are returned as `intel` records → XTHREAT.INTELEXCHANGE (idempotent by the
reference URL, see connectors/runner.py import_threat_intel). No database access
here, so the connector also runs on a remote worker.

run() contract (returned to the runner):
    {"assets": [], "services": [], "cpes": [], "vulns": [],
     "intel": [{"name","description","reference","author","tags", ...}],
     "source": "OSINT Newsletter tools library"}
"""
from __future__ import annotations

import os
import re
import urllib.parse
from typing import Any, Dict, List

# ── Observable classification ───────────────────────────────────────────────
_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_PHONE = re.compile(r"^\+?[0-9][0-9 .()\-]{6,}$")
_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_BTC = re.compile(r"^(bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
_URL = re.compile(r"^https?://", re.I)
_USERNAME = re.compile(r"^@?[A-Za-z0-9._\-]{2,40}$")


def classify(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return "empty"
    if _URL.match(t):
        return "url"
    if _EMAIL.match(t):
        return "email"
    if _IPV4.match(t):
        return "ip"
    if _ETH.match(t) or _BTC.match(t):
        return "crypto"
    if _SHA256.match(t) or _SHA1.match(t) or _MD5.match(t):
        return "hash"
    if _DOMAIN.match(t):
        return "domain"
    if _PHONE.match(t):
        return "phone"
    if _USERNAME.match(t):
        return "username"
    return "name"


def _enc(s: Any) -> str:
    return urllib.parse.quote(str(s), safe="")


# ── Pivot templates ─────────────────────────────────────────────────────────
# Keyed by the library slug (last segment of the tool's osintnewsletter URL).
# Value maps an observable type ("*" = any) to a URL template; "{t}" is replaced
# by the URL-encoded target. Only stable, well-known query URLs are listed here;
# every other tool/observable falls back to a manual reference to the tool page.
PIVOTS: Dict[str, Dict[str, str]] = {
    "epieos": {"email": "https://epieos.com/?q={t}", "phone": "https://epieos.com/?q={t}"},
    "urlscan.io": {"*": "https://urlscan.io/search/#{t}"},
    "host.io": {"domain": "https://host.io/{t}", "url": "https://host.io/{t}"},
    "ipinfo": {"ip": "https://ipinfo.io/{t}", "domain": "https://ipinfo.io/{t}"},
    "intelligencex": {"*": "https://intelx.io/?s={t}"},
    "netlas": {"ip": "https://app.netlas.io/host/{t}/"},
    "arin": {"*": "https://search.arin.net/rdap/?query={t}"},
    "central-ops": {"domain": "https://centralops.net/co/DomainDossier.aspx?dom={t}",
                    "ip": "https://centralops.net/co/DomainDossier.aspx?addr={t}"},
    "domain-dossier": {"domain": "https://centralops.net/co/DomainDossier.aspx?dom={t}",
                       "ip": "https://centralops.net/co/DomainDossier.aspx?addr={t}"},
    "idcrawl": {"username": "https://www.idcrawl.com/u/{t}", "name": "https://www.idcrawl.com/search?q={t}"},
    "forebears": {"name": "https://forebears.io/surnames/{t}"},
    "opensecrets": {"*": "https://www.opensecrets.org/search?q={t}"},
    "companies-house": {"*": "https://find-and-update.company-information.service.gov.uk/search?q={t}"},
    "wayback-machine": {"*": "https://web.archive.org/web/*/{t}"},
    "annas-archive": {"*": "https://annas-archive.org/search?q={t}"},
    "deepl-translator": {"*": "https://www.deepl.com/translator#auto/en/{t}"},
    "tineye": {"url": "https://www.tineye.com/search?url={t}"},
    "google-lens": {"url": "https://lens.google.com/uploadbyurl?url={t}"},
    "apple-maps": {"*": "https://maps.apple.com/?q={t}"},
    "arkham": {"crypto": "https://platform.arkhamintelligence.com/explorer/address/{t}"},
    "block-explorer": {"*": "https://www.blockchain.com/explorer/search?search={t}"},
}


def build_pivot(slug: str, otype: str, target: str) -> str:
    tpl = PIVOTS.get(slug) or {}
    url = tpl.get(otype) or tpl.get("*")
    return url.replace("{t}", _enc(target)) if url else ""


def _targets(params: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    tg = str(params.get("target") or "").strip()
    if tg:
        out.append(tg)
    f = params.get("file")
    if f and os.path.exists(str(f)):
        with open(str(f), "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and line not in out:
                    out.append(line)
    return out


def osint_run(slug: str, tool_name: str, tool_url: str, category: str,
              params: Dict[str, Any], workdir: str = "") -> Dict[str, Any]:  # noqa: ARG001
    intel: List[Dict[str, Any]] = []
    for t in _targets(params):
        otype = classify(t)
        pivot = build_pivot(slug, otype, t)
        if pivot:
            intel.append({
                "name": f"{tool_name} pivot — {t}",
                "description": f"{category}: open {tool_name} for the {otype} '{t}'. Pivot link: {pivot}",
                "reference": pivot,
                "author": tool_name,
                "tags": f"osint,pivot,{otype}",
            })
        else:
            intel.append({
                "name": f"{tool_name} — investigate {t}",
                "description": (f"{category}: {tool_name} has no automatable query URL; open {tool_url} "
                                f"and search the {otype} '{t}' manually."),
                "reference": f"{tool_url}#{_enc(t)}",
                "author": tool_name,
                "tags": f"osint,manual,{otype}",
            })
    # No target supplied → still yield a single catalogue reference for the tool.
    if not intel:
        intel.append({
            "name": f"{tool_name} (OSINT tool)",
            "description": f"{category}. {tool_name} — {tool_url}",
            "reference": tool_url,
            "author": tool_name,
            "tags": "osint,catalogue",
        })
    return {"assets": [], "services": [], "cpes": [], "vulns": [],
            "intel": intel, "source": "OSINT Newsletter tools library"}
