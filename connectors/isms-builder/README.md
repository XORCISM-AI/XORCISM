# ISMS Builder connector

Imports from [ISMS Builder](https://github.com/coolstartnow/isms-builder) (AGPL-3.0, by Claude
Hecker) into XORCISM's compliance and policy modules.

ISMS Builder is a self-hosted Information Security Management System — ISO 27001:2022, NIS2,
GDPR/DSGVO, BSI IT-Grundschutz, EUCS, EU AI Act and CRA — giving SMEs and consultants a real ISMS
(Statement of Applicability across 313 controls / 8 frameworks, policy templates, a risk register,
assets, suppliers, BCM and audit tooling) without a five-figure vendor contract.

> ⚠️ ISMS Builder ships **no packaged releases or installers** — the only legitimate source is its
> GitHub repository (malicious impersonations distributing Windows malware exist). This connector
> only reads a JSON export you produce from your own instance; it downloads and runs nothing.

## What it maps to

| ISMS Builder | XORCISM | Path |
|---|---|---|
| Statement of Applicability (per control: applicable, status, justification) | one Compliance `AUDIT` per framework + one `AUDITFINDING` per gap | runner `soa` → `import_soa` → `/compliance-management` |
| Risk register (open risks) | a "Risk register" `AUDIT` + a finding per open risk | runner `risks` → `import_soa` |
| Policy templates (lifecycle, version) | `XORCISM.DOCUMENT` | runner `documents` → `import_documents` → `/policy-management` |

- A control that is **applicable and not yet `implemented`** becomes an audit finding (the SoA gap);
  `implemented` and `not_applicable` controls are counted in the audit description, not stored.
  Gap severity: `not_started` → High, `in_progress` → Medium. Linked policies and the owner are kept
  in the finding.
- Risk severity is banded from `score` (or `probability × impact`): ≥20 Critical, ≥12 High, ≥6
  Medium, else Low. Closed/accepted/mitigated risks are skipped.
- Findings feed XORCISM's control-assurance, audit-package and Enterprise-Risk views. Everything is
  idempotent (AUDIT by name+tenant; findings by `isms-soa:<id>` / `isms-risk:<id>`).

Assets are intentionally **not** mapped — XORCISM's ASSET import is host-oriented, and ISMS Builder's
org-assets (hardware/software/data/service/facility) would not fit it cleanly.

## Modes

1. **File.** `file` = an ISMS Builder JSON export. Accepts a combined export
   `{"soa":[…], "risks":[…], "templates":[…]}` (or `controls` / `policies` aliases, or a `{"data":{…}}`
   wrapper) or a single-entity file (a bare control array, or `{"controls":[…]}` etc.).
2. **Demo.** No file → the bundled `sample.json` (an 8-control SoA across ISO 27001 + NIS2, 4 risks,
   3 policies).

```bash
python connectors/isms-builder/run.py                                    # demo
python connectors/runner.py --selftest export.json --connector isms-builder
```
