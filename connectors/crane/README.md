# CRANE (CRA norm engine) connector

Imports a [CRANE](https://github.com/cra-norm-engine/crane) export into XORCISM's **EU Cyber Resilience
Act conformity cockpit** (`/cra-compliance`).

CRANE is a self-hosted CRA (Regulation (EU) 2024/2847) compliance platform — product/release management,
SBOM analysis, vulnerability + VEX, an Annex I requirement matrix and conformity evidence. This connector
maps a CRANE products export onto XORCISM's CRA model:

- each product with digital elements → a **CRAPRODUCT** (name, class per Annex III/IV, manufacturer,
  support period, conformity route)
- each release → a **CRARELEASE** (version, date, status, SBOM link)
- each Annex I assessment → a **CRAREQUIREMENT** status (Part I product security / Part II vulnerability
  handling), matched by reference (e.g. `Annex I.1.(2)(a)`, `Annex I.2.(5)`, `Annex V`)

The imported data drives the per-product **conformity score** and the **release-readiness gate**, reusing
XORCISM's SBOM (`/sca`), vulnerability, evidence and Art. 14 reporting subsystems. The CRA itself is also
imported as a CONTROL vocabulary via `xorcism_python/importers/import_cra.py`.

## Usage

Worker-safe and **offline** — no live access, stdlib only.

- **CRANE export**: a `{products:[...]}` document (or a bare list) from CRANE's `/api/v1` via `file`.
- **Demo**: run with no `file` → bundled `sample.json` (two PDEs, releases and Annex I assessments).

```bash
python run.py
```

Result key: `cra_products` → `runner.import_cra_products` → `XCOMPLIANCE.CRAPRODUCT / CRARELEASE / CRAREQUIREMENT`.
