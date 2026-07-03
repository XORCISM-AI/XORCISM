# Pulsedive — CTI connector

[Pulsedive](https://pulsedive.com/) is a threat-intelligence platform that ingests,
enriches and **risk-scores indicators** (IPs, domains, URLs, hashes), groups them
into **threats**, and curates **feeds**. It offers a community **free tier** and a
REST API ([docs.pulsedive.com](https://docs.pulsedive.com/)).

This connector normalizes Pulsedive indicators into XORCISM threat-intel records
(**`XTHREAT.INTELEXCHANGE`**) via the standard connector `intel` shape — idempotent
by reference (the Pulsedive indicator URL). Each record carries the indicator value
and type, the Pulsedive **risk** (`unknown` / `none` / `low` / `medium` / `high` /
`critical` / `retired`), its **risk factors**, and its linked **threats** (surfaced
as actor / malware tags) and **feeds** — feeding the CTI views, the STIX store and
ATT&CK coverage.

## Modes

### Live (needs a Pulsedive API key)

Set your free/community API key in the environment and pass a `query`:

```bash
export PULSEDIVE_API_KEY="<your key>"

# Enrich a single indicator (info.php):
python run.py --query 8.8.8.8
python run.py --query malicious-example.com

# Pulsedive Explore search in PDQL (explore.php):
python run.py --query 'risk=high and type=ip' --limit 500
python run.py --query 'threat=Emotet'
```

The connector calls only the fixed `https://pulsedive.com/api/` host
(`info.php` for a single indicator, `explore.php` for a PDQL query).

### Offline (parse a saved export — no key needed)

```bash
python run.py --file export.csv        # a Pulsedive bulk CSV export
python run.py --file explore.json      # an Explore result {"results":[…]}
python run.py --file indicator.json    # a single info.php indicator JSON
python run.py                          # built-in sample (offline demo)
```

Both CSV and JSON headers are matched defensively (case-insensitive); threats and
feeds in a CSV cell may be separated by `|`, `,` or `;`.

## Mapping

| Pulsedive | XORCISM `INTELEXCHANGE` |
|---|---|
| indicator + type | `IntelName` / `IntelExternalID` |
| indicator URL (by `iid`) | `IntelReference` (idempotency key) |
| risk + risk factors + threats + feeds | `IntelDescription` |
| `pulsedive`, `cti`, type, `risk:<level>`, `feed:<name>` | `IntelTags` |
| linked threats (named campaigns / families) | `ActorTags` + `MalwareTags` |
| `Pulsedive` | `IntelSource` / `IntelAuthor` |
| full indicator object | `RawJson` (lossless → STIX store) |

## Safety & licence

- **Worker-safe, read-only, non-intrusive**: it only queries the fixed pulsedive.com
  API with the operator's own key, or parses an operator-produced export. It never
  scans third-party infrastructure.
- **Secret handling**: the API key is read from the `PULSEDIVE_API_KEY` environment
  variable — never hard-coded or logged.
- **Licence-safe**: no Pulsedive code is vendored; the connector consumes the public
  API / exported data under the operator's own Pulsedive account and terms.
