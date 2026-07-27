"""Obstracts connector — turn security blogs into structured threat intel in XTHREAT.INTELEXCHANGE.

Obstracts (dogesec) monitors security blogs and extracts STIX 2.1 intelligence — IoCs, ATT&CK
techniques, threat actors, malware and vulnerabilities — from every post. This connector pulls that
structured intel into XORCISM: each blog post becomes one INTELEXCHANGE report whose AttackTags /
ActorTags / MalwareTags / CveTags are derived from the post's extracted STIX objects (ATT&CK ids are
then cross-linked into INTELEXCHANGEATTACK by runner.import_threat_intel).

Offline: an Obstracts export via the `file` param — a STIX bundle ({"objects":[…]}) or a posts JSON
([{…}] / {"posts":[…]}). Live: OBSTRACTS_API_KEY (API-KEY header; omit for an unauthenticated
self-hosted instance) + optional OBSTRACTS_BASE (default https://api.obstracts.com). Iterates
/api/v1/feeds/ → /posts/ → /objects/. Returns {"intel": [...], "source": "Obstracts"}.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402  (reuse http_json / rows)

ATT = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def tags_from_objects(objs):
    """Derive (attack, actors, malware, cves) tag sets from a list of STIX objects."""
    attack, actors, malware, cves = set(), set(), set(), set()
    for o in objs or []:
        if not isinstance(o, dict):
            continue
        typ = o.get("type")
        name = (o.get("name") or "").strip()
        refs = o.get("external_references") or []
        if typ == "attack-pattern":
            for r in refs:
                ext = str(r.get("external_id") or "")
                if r.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack") and ATT.fullmatch(ext):
                    attack.add(ext.upper())
        elif typ in ("threat-actor", "intrusion-set"):
            if name:
                actors.add(name)
        elif typ == "malware":
            if name:
                malware.add(name)
        elif typ == "vulnerability":
            for r in refs:
                ext = str(r.get("external_id") or "")
                if ext.upper().startswith("CVE-"):
                    cves.add(ext.upper())
            m = CVE.search(name)
            if m:
                cves.add(m.group(0).upper())
    return attack, actors, malware, cves


def _post_intel(post, objs, base):
    pid = post.get("id") or post.get("post_id")
    name = post.get("title") or post.get("name") or "Obstracts post"
    desc = post.get("description") or post.get("summary") or ""
    url = post.get("link") or post.get("url")
    attack, actors, malware, cves = tags_from_objects(objs)
    blob = f"{name} {desc}"                       # also scavenge ids from the title/summary text
    attack |= {m.upper() for m in ATT.findall(blob)}
    cves |= {m.upper() for m in CVE.findall(blob)}
    ref = url or (f"{base}/api/v1/posts/{pid}/" if pid else None) or name
    date = (post.get("pubdate") or post.get("datetime_published") or post.get("created") or post.get("modified") or "")
    return {
        "name": str(name)[:250], "description": str(desc)[:8000], "reference": ref,
        "external_id": str(pid) if pid else None,
        "author": post.get("author") or post.get("profile_id") or "Obstracts",
        "date": (str(date)[:10] or None),
        "attack_tags": ", ".join(sorted(attack)) or None,
        "actor_tags": ", ".join(sorted(actors)) or None,
        "malware_tags": ", ".join(sorted(malware)) or None,
        "cve_tags": ", ".join(sorted(cves)) or None,
    }


def _from_bundle(objects):
    """Offline STIX bundle → one intel item per report object (tags from the whole bundle)."""
    reports = [o for o in objects if isinstance(o, dict) and o.get("type") == "report"]
    attack, actors, malware, cves = tags_from_objects(objects)
    tags = {"attack_tags": ", ".join(sorted(attack)) or None, "actor_tags": ", ".join(sorted(actors)) or None,
            "malware_tags": ", ".join(sorted(malware)) or None, "cve_tags": ", ".join(sorted(cves)) or None}
    out = []
    for r in reports:
        url = None
        for ref in r.get("external_references") or []:
            if ref.get("source_name") in ("obstracts", "url") and ref.get("url"):
                url = ref["url"]; break
        out.append({
            "name": str(r.get("name") or "Obstracts report")[:250],
            "description": str(r.get("description") or "")[:8000],
            "reference": url or r.get("id"), "external_id": r.get("id"),
            "author": "Obstracts", "date": (str(r.get("created") or "")[:10] or None), **tags,
        })
    if not out and objects:                       # bundle with no report object → single rollup item
        out.append({"name": "Obstracts STIX bundle", "description": f"{len(objects)} STIX objects",
                    "reference": None, "external_id": None, "author": "Obstracts", "date": None, **tags})
    return out


def _offline(params):
    f = params.get("file")
    if not f or not os.path.exists(f):
        return None
    with open(f, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        return _from_bundle(data["objects"])
    posts = data if isinstance(data, list) else (data.get("posts") if isinstance(data, dict) else None)
    if isinstance(posts, list):
        return [_post_intel(p, p.get("objects"), "") for p in posts if isinstance(p, dict)]
    return []


def run(params, workdir):
    offline = _offline(params)
    if offline is not None:
        return {"intel": [i for i in offline if i.get("reference") or i.get("external_id")], "source": "Obstracts"}

    key = os.getenv("OBSTRACTS_API_KEY")
    base = (params.get("base") or os.getenv("OBSTRACTS_BASE") or "https://api.obstracts.com").rstrip("/")
    hdr = {"Accept": "application/json"}
    if key:
        hdr["API-KEY"] = key
    cap = int(params.get("max_items") or 100)
    enrich = str(params.get("enrich", "true")).lower() not in ("false", "0", "no")
    only_feed = params.get("feed_id")

    def _list(url):
        try:
            data = g.http_json(url, hdr)
        except Exception:  # noqa: BLE001
            return [], None
        if isinstance(data, dict):
            for k in ("feeds", "posts", "objects"):
                if isinstance(data.get(k), list):
                    return data[k], data
        return g.rows(data), data if isinstance(data, dict) else None

    # feeds to sweep
    feeds = []
    if only_feed:
        feeds = [{"id": only_feed}]
    else:
        page = 1
        while page <= 25:
            batch, meta = _list(f"{base}/api/v1/feeds/?page={page}")
            if not batch:
                break
            feeds.extend(batch)
            if not (isinstance(meta, dict) and meta.get("next")):
                break
            page += 1

    intel = []
    for feed in feeds:
        if len(intel) >= cap:
            break
        fid = feed.get("id") or feed.get("feed_id")
        if not fid:
            continue
        page = 1
        while page <= 25 and len(intel) < cap:
            posts, meta = _list(f"{base}/api/v1/feeds/{fid}/posts/?page={page}")
            if not posts:
                break
            for post in posts:
                if len(intel) >= cap:
                    break
                pid = post.get("id") or post.get("post_id")
                objs = []
                if enrich and pid:
                    op = 1
                    while op <= 5:                # bounded object paging per post
                        batch, ometa = _list(f"{base}/api/v1/feeds/{fid}/posts/{pid}/objects/?page={op}")
                        if not batch:
                            break
                        objs.extend(batch)
                        if not (isinstance(ometa, dict) and ometa.get("next")):
                            break
                        op += 1
                intel.append(_post_intel(post, objs, base))
            if not (isinstance(meta, dict) and meta.get("next")):
                break
            page += 1

    return {"intel": [i for i in intel[:cap] if i.get("reference") or i.get("external_id")], "source": "Obstracts"}
