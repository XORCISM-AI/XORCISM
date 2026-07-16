# ENISA SME Cyber Resilience Maturity connector

Imports a filled-in copy of ENISA's official **SME Cyber Resilience Maturity Assessment** tool into
XORCISM's native [`/cra-maturity`](../../xorcism_ts/client/cra-maturity.html) cockpit.

- Publication: [SME Cyber Resilience Maturity Assessment Model](https://www.enisa.europa.eu/publications/sme-cyber-resilience-maturity-assessment-model) (ENISA, July 2026, TLP:CLEAR)
- Tool: `CRA_Maturity_Model_TOOL.xlsx` (the "Questionnaire" sheet holds the 25 scores)

## What it is

A Cyber Resilience Act (Regulation (EU) 2024/2847) **readiness self-check** for SMEs making products
with digital elements. 25 questions across five domains — governance & documentation; risk
management & security-by-design/default; vulnerability & patch management; product lifecycle
management; awareness, competence & skills — each scored 1–5 on an anchored rubric. It is a maturity
self-assessment, **not** a proof of CRA compliance (ENISA is explicit: an advanced score does not
replace the legal obligations).

## What it maps to

| ENISA tool | XORCISM | Path |
|---|---|---|
| The 25 question scores (Questionnaire sheet) | `XCOMPLIANCE.SMEMATURITYASSESSMENT` + `SMEMATURITYANSWER` | runner `sme_maturity` → `import_sme_maturity` |

XORCISM recomputes the domain averages, the overall maturity band (Basic 1–2.5 / Intermediate
2.6–3.9 / Advanced 4–5), the per-question RAG and the Annex B improvement roadmap on read — so an
imported assessment behaves exactly like one filled in natively at `/cra-maturity`. Assessments are
idempotent by (tenant, name): re-importing the same file updates the one row.

## Modes

1. **File — the ENISA xlsx.** `file` = your filled `CRA_Maturity_Model_TOOL.xlsx`. Parsed with a
   compact stdlib reader (zipfile + ElementTree — **no openpyxl**): it reads the Questionnaire
   sheet's Ref (column B) and Score (column E) for each of the 25 questions, falling back to the
   leading digit of the selected level text (column D) if the score cell is blank.
2. **File — a JSON export.** `file` = `{"assessments":[{"name","org","answers":[{"ref":"1.1","score":3}]}]}`,
   or a bare `{"scores":{"1.1":3, "1.2":2, ...}}`, or `[{"ref":"1.1","score":3}, ...]`.
3. **Demo.** No file → the bundled `sample.json` (ENISA's own worked example — overall 3.0 →
   Intermediate).

No API and no secrets: the ENISA tool is an offline spreadsheet.

## Parameters

| Name | Meaning |
|---|---|
| `file` | The filled ENISA `.xlsx`, or a JSON export of the scores |
| `name` | Assessment name (defaults to the tool title) |
| `org` | Organisation (SME) name |
| `product_scope` | Product(s) with digital elements in scope |

```bash
python connectors/enisa-sme-cra/run.py                                   # demo (sample.json)
python connectors/runner.py --selftest CRA_Maturity_Model_TOOL.xlsx --connector enisa-sme-cra
```
