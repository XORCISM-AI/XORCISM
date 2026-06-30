# CryptoScan connector

Imports the output of **CryptoScan** ([github.com/GreyNOC/Crypto-Scan](https://github.com/GreyNOC/Crypto-Scan), by GreyNOC) — a cryptographic posture-management & **post-quantum-cryptography (PQC)** migration scanner — into XORCISM's Cryptographic Bill of Materials (`/cbom`) and Post-Quantum Crypto Maturity (`/pqcmm`) cockpits.

CryptoScan discovers cryptography in use across:

- **live TLS 1.3 endpoints** — negotiated key-exchange groups + PQC-hybrid detection, full cipher-suite enumeration
- **SSH** endpoints — KEX / host-key / cipher / MAC algorithm sets
- **IPsec / IKEv2** gateways — encryption / integrity / DH-group negotiation
- **PKI / X.509** certificate files (`.pem`, `.crt`, `.der`, …)
- **source code & dependencies** across pip / npm / Cargo / Go / Maven / Gradle / Ruby / Composer

…and classifies each by quantum risk (**shor-broken / grover-weakened / pq-safe / classically-weak**) with a **Mosca** harvest-now-decrypt-later timeline.

## ⚖️ License note

CryptoScan is **proprietary** software — *Copyright (c) GreyNOC. All rights reserved.* This connector ships **none** of CryptoScan's code and does **not** download, embed, or reproduce it. It only **reads the standard-format output files** you produce by running **your own licensed copy** of CryptoScan. Those output formats — CycloneDX 1.6 CBOM, SARIF 2.1.0, and a plain JSON findings list — are open specifications and the resulting files are your own data.

## How it works

The connector is **import-type, worker-safe and read-only**: it parses an exported file and performs **no scanning or network activity** itself. It accepts (auto-detected):

1. **CycloneDX 1.6 CBOM** *(richest — recommended)* — `components[type = "cryptographic-asset"]` with `cryptoProperties`.
2. A plain **`{ "cryptoAssets": [...] }`** / top-level array / **`{ "findings": [...] }`** JSON list.
3. **SARIF 2.1.0** — best-effort: each result's rule id / message is surfaced as an algorithm asset.

Each cryptographic asset is normalized and written to **`XORCISM.CRYPTOASSET`** (via the runner's `import_crypto_assets`), where it is re-classified quantum-safe vs quantum-vulnerable using the same deterministic rules as the in-app CBOM importer (Shor breaks RSA/ECC/DH/DSA; ML-KEM/ML-DSA/SPHINCS+/Falcon/XMSS and declared NIST-PQC levels are safe; AES-256 / SHA-384+ safe, AES-128 / SHA-256 Grover-weakened, MD5 / SHA-1 / DES / RC4 deprecated). It then rolls into the CBOM cockpit and PQCMM posture.

A connector run is treated as a **full posture snapshot**: re-importing the same `source` label replaces that source's previous rows (idempotent).

## Producing the input

```bash
gs tls example.com:443 --cbom cbom.json --report report.md   # live TLS posture → CBOM
gs ssh example.com --report report.md                         # SSH algorithm sets
gs code ./my-repo --json findings.json --sarif out.sarif      # source-code crypto usage
gs scan ./my-repo --tls example.com:443 --mosca               # combined scan + Mosca risk
```

## Parameters

| name | type | required | notes |
|------|------|----------|-------|
| `file` | file | no | A CryptoScan CBOM / findings / SARIF export. Defaults to the bundled `sample.json` (a synthetic CycloneDX 1.6 CBOM). |
| `source` | string | no | Source label stamped on imported assets (default `CryptoScan`). Re-importing the same source replaces its snapshot. |
| `asset_id` | int | no | Optional XORCISM `AssetID` to attach the discovered crypto assets to (the scanned host / repo). |
| `limit` | int | no | Max assets to import (default 5000). |

## Dry-run

```bash
python run.py                 # uses the bundled sample CBOM
python run.py cbom.json       # parse your own CryptoScan CBOM export
```

## See also

- In-app CBOM import: `POST /api/cbom/import` (`/cbom`) — same normalization, file upload.
- `/pqcmm` — Post-Quantum Crypto Maturity, fed by the quantum-vulnerable rollup.
