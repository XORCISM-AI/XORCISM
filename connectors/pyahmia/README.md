# PyAhmia connector

Imports Tor hidden-service discovery from [PyAhmia](https://codeberg.org/rly0nheart/pyahmia)
(MIT, by rly0nheart) into XORCISM's CTI intel exchange.

PyAhmia is a CLI (`pip install pyahmia` → `ahmia QUERY`) that searches **.onion** services via
[Ahmia.fi](https://ahmia.fi) — the clearnet search engine for Tor hidden services (by Juha Nurmi).
Each result is a discovered hidden service: **title, .onion URL, description, and a "last seen"
timestamp**.

## What it maps to

| PyAhmia / Ahmia | XORCISM | Path |
|---|---|---|
| Each discovered onion service (title, .onion URL, description, last-seen) | `XTHREAT.INTELEXCHANGE` | runner `intel` → `import_threat_intel` |

Darkweb discovery is OSINT/CTI, so it lands in the same place as the X-OSINT / RedRoom / IRONSIGHT
OSINT connectors — surfacing at `/cti-expert`, the STIX graph and the threat-intel views. Items are
**idempotent by the .onion URL** (the natural key), tagged `darkweb, tor, onion, ahmia, osint` plus
your query. Search for a brand, domain or keyword to pull matching onion services into CTI.

## Modes

1. **Live.** `query` = a search string. The worker fetches `AHMIA_BASE` (default `https://ahmia.fi`)
   `/search/?q=<query>` and parses the HTML results. `period` = `day` / `week` / `month` filters by
   Ahmia's last-seen window. To search over Tor (`--use-tor` parity), set `AHMIA_BASE` to Ahmia's
   onion address and route the worker through a Tor SOCKS proxy via `AHMIA_SOCKS` or `HTTPS_PROXY`.
2. **File.** `file` = a **PyAhmia CSV export** (`ahmia QUERY --export`) or a **saved Ahmia results
   HTML page**. The parser tolerates both (and a JSON `{results:[...]}` export).
3. **Demo.** No input → the bundled `sample.json`.

The endpoint is fixed and operator-configurable (anti-SSRF); the connector is stdlib-only
(`urllib` + `html.parser`) and holds no secrets.

```bash
python connectors/pyahmia/run.py                                  # demo
python connectors/runner.py --selftest results.html --connector pyahmia   # a saved Ahmia HTML page
```

> **Authorised OSINT only.** Darkweb discovery must respect your engagement scope and local law. The
> connector queries Ahmia.fi (a clearnet index) and never connects to the onion services it returns.
