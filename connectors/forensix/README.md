# Forensix connector

Imports a filled-in **Forensix DFIR mission workbook** (Excel) into XORCISM's CERT/Forensics module
([`/cert-ops`](../../xorcism_ts/client/cert-ops.html)).

Forensix is a digital-forensics / incident-response mission checklist: **85 controls across 6
phases** — methodology & legal framework, disk acquisition, network PCAP, memory & live forensics,
correlation & report, logs & SIEM — each with a status and a normative reference (ISO/IEC 27037,
RFC 3227, French CPP, GDPR/RGPD, Code pénal, NIS2, ANSSI, MITRE ATT&CK). XORCISM replicates this
natively as the per-case **forensic methodology conformity checklist**; this connector loads a real
filled workbook into a case.

## What it maps to

| Forensix | XORCISM | Path |
|---|---|---|
| The mission (cover page) | `XINCIDENT.FORENSICCASE` (found or created by title) | runner `forensic_checklist` → `import_forensic_checklist` |
| Each phase control's status + evidence | `FORENSICCHECK` (per-case checklist item, keyed by ref) | ″ |

XORCISM then computes the per-phase and overall **conformity** (compliant / 85) and surfaces the
checklist in the case's *Forensic methodology* tab. Idempotent by (case title, control ref):
re-importing an updated workbook refreshes the statuses.

## How it reads the workbook

A compact stdlib reader (zipfile + ElementTree — **no openpyxl**) opens each phase sheet, finds the
`Contrôle | Description | Statut | Preuve | Référence` table, and reads each control row's **status**
(column C) and **evidence** (column D) in order. The French status vocabulary
(`Conforme` / `Non conforme` / `En cours` / `À vérifier`) maps to XORCISM's
`compliant` / `non-compliant` / `in-progress` / `to-verify`. Statuses are positioned onto the bundled
English control catalogue (`catalogue.json`) by phase and order, so the imported case shows the
standard 85-control methodology with the analyst's real statuses.

## Modes

1. **File — the Forensix xlsx.** `file` = your filled `Forensix.xlsx`.
2. **File — a JSON export.** `file` = `{"case": {...}, "checks": [{"ref": "P2.3", "status": "compliant", "evidence": "..."}]}`.
3. **Demo.** No file → the bundled `sample.json`.

Offline only — no API, no secrets.

```bash
python connectors/forensix/run.py                                  # demo
python connectors/runner.py --selftest Forensix.xlsx --connector forensix
```
