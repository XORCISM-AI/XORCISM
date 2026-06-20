# ZettelForge

`zettelforge` · **import** connector · category **threat-intel**

Agentic CTI memory (ZettelForge, https://github.com/rolandpg/zettelforge): extracts and organises threat intelligence from analyst notes and reports so institutional knowledge isn't lost. Each note/report becomes an XTHREAT.INTELEXCHANGE item (idempotent by content reference); ZettelForge's entity extraction surfaces CVEs, MITRE ATT&CK techniques (Txxxx), threat-actor groups with alias resolution (Fancy Bear / Sofacy / STRONTIUM -> APT28), malware/tools and IOCs (IPs, domains, URLs, hashes, emails) as tags, and ATT&CK techniques are cross-linked into INTELEXCHANGEATTACK so they count toward the ATT&CK coverage. When the 'zettelforge' Python package is installed (pip install zettelforge) it is used for LLM-grade NER and the notes are also persisted into ZettelForge's local knowledge graph (data dir ZETTELFORGE_DATA_DIR, default ~/.amem); otherwise a built-in regex+alias extractor (stdlib only, fully offline) is used. Read-only, non-intrusive, no external API keys. Point 'notes' at a file or a directory of markdown/text notes, or use 'file' to import a saved ZettelForge JSON export.

**Upstream:** https://github.com/rolandpg/zettelforge

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `notes` | file | no | — | Path to a CTI note/report file, or a directory of .md/.txt/.markdown notes (worker-local). Entities are extracted from each and imported into INTELEXCHANGE. |
| `file` | file | no | — | Offline mode: import a saved ZettelForge JSON export (memories/entities) instead of extracting from notes. |
| `author` | string | no | `ZettelForge` | Author/source recorded on the imported intel items. |
| `max_items` | int | no | `200` | Maximum number of notes/items to import. (range 1–2000) |
| `use_zettelforge` | bool | no | `True` | Use the installed 'zettelforge' package for entity extraction + knowledge-graph persistence when available (falls back to the built-in regex extractor). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *ZettelForge*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:zettelforge`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/zettelforge/sample.json --connector zettelforge
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
