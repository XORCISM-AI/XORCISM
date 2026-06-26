# Hunt.io connector (C2 & malicious-infrastructure CTI)

Enriches your threat intelligence from [Hunt.io](https://hunt.io) — a platform that continuously scans
the internet for **malicious infrastructure**: command-and-control (C2) servers, malware delivery, SSL
certificates, **JARM/JA4** fingerprints and open directories (AttackCapture).

## Modes
| Call | Hunt.io endpoint | Result |
|---|---|---|
| `ip=<addr>` | `GET /v1/enrich/ip/{ip}` | one intel record on that IP's malicious activity |
| *(no `ip`)* | `GET /v1/c2s` | the active-C2 feed → many intel records |
| `file=<path>` | — | parse a saved Hunt.io JSON response offline |

## Mapping
Each result → a `XTHREAT.INTELEXCHANGE` record (via `runner.import_threat_intel`, idempotent by
reference `huntio:c2:<ip>:<port>` / `huntio:ip:<ip>`), carrying the **malware family**, **AS/country**,
**certificate subject**, **JARM/JA4** hashes, confidence, and the C2 **ATT&CK technique T1071**
(Application Layer Protocol). These flow into the CTI graph and can be cross-referenced by the CTI-Expert.

## Usage
```bash
export HUNTIO_API_KEY=ak_xxxxxxxx          # header: token: ak_...
python run.py                              # active-C2 feed (or the bundled sample if no key)
HUNTIO_API_KEY=ak_... python run.py        # live feed
python run.py  # with params: {"ip":"45.61.136.10"}  -> IP enrichment
```
Worker-safe: stdlib only (urllib), API key via env (never in the UI), ASCII-only output, no DB access.
Returns `{source:"Hunt.io", intel:[...]}`.
