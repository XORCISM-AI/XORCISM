# Obstracts connector

[Obstracts](https://www.obstracts.com) ([dogesec](https://www.dogesec.com), open source —
[github.com/muchdogesec/obstracts](https://github.com/muchdogesec/obstracts), Apache 2.0) turns any
security blog into **structured STIX 2.1 threat intelligence**: it monitors blog feeds and
automatically extracts IoCs, ATT&CK techniques, threat actors, malware families and vulnerabilities
from every post, connecting them with the relationships described in the source.

This connector imports that intelligence into XORCISM. **Each blog post becomes one
`XTHREAT.INTELEXCHANGE` report**, and its `AttackTags` / `ActorTags` / `MalwareTags` / `CveTags` are
derived from the post's extracted STIX objects. ATT&CK technique ids are then cross-linked into
`INTELEXCHANGEATTACK` (contributing to the ATT&CK matrix coverage) by `runner.import_threat_intel`.
Items are idempotent by their source URL.

## Modes

**Offline** — pass a `file`:
- a **STIX bundle** `{"objects": [...]}` (one intel item per `report` object, tags from the bundle), or
- a **posts JSON** export `[{...}]` / `{"posts": [...]}` (optionally with embedded `objects`).

```bash
python connectors/runner.py --connector obstracts --params '{"file":"connectors/obstracts/sample.json"}'
```

**Live** — set the API key in the worker environment and (optionally) the base URL:
- `OBSTRACTS_API_KEY` — sent as the `API-KEY` header. Omit for an unauthenticated self-hosted instance.
- `OBSTRACTS_BASE` — default `https://api.obstracts.com`. Self-hosted default is `http://127.0.0.1:8001`.

The connector sweeps `/api/v1/feeds/` → `/api/v1/feeds/{feed_id}/posts/` → (per post)
`/api/v1/feeds/{feed_id}/posts/{post_id}/objects/`.

## Parameters

| Param | Default | Description |
|-------|---------|-------------|
| `file` | — | Offline export (STIX bundle or posts JSON). |
| `base` | `https://api.obstracts.com` | API base URL. |
| `feed_id` | — | Restrict to a single blog feed id; omit to sweep all feeds. |
| `enrich` | `true` | Fetch each post's STIX objects to derive ATT&CK / actor / malware / CVE tags. `false` = fast metadata-only pull. |
| `max_items` | `100` | Maximum posts to import. |

## Output

`{"intel": [ { name, description, reference, external_id, author, date, attack_tags, actor_tags,
malware_tags, cve_tags } ... ], "source": "Obstracts"}` → `runner.import_threat_intel` →
`XTHREAT.INTELEXCHANGE` (+ `INTELEXCHANGEATTACK`). Browse the result under XORCISM threat intelligence
(the intel feeds the STIX graph, FTS search, threat-actor / malware views and ATT&CK coverage).

Obstracts also exposes a **TAXII 2.1** API and OpenCTI integration; this connector uses the REST API.

## Secrets

Set `OBSTRACTS_API_KEY` (and any custom `OBSTRACTS_BASE`) as **environment variables** on the worker —
never pass secrets as connector parameters.
