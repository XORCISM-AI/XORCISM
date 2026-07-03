# MADIS (Soluris) — GDPR / RGPD connector

[MADIS](https://madis.app/) is an **open-source (AGPLv3)** GDPR/RGPD compliance
application for **Data Protection Officers**, developed by **Soluris** (main
development by Datakode) and widely used by French local authorities, health
establishments and public digital-service networks (OPSN). Source:
[gitlab.adullact.net/soluris/madis](https://gitlab.adullact.net/soluris/madis).

This connector **parses a MADIS export** and normalizes it into XORCISM's
**GDPR / DPO cockpit** (`/privacy`), landing each MADIS register in its XORCISM
counterpart:

| MADIS register | XORCISM register (table) |
|---|---|
| Registre des traitements (RoPA, Art 30) | `PRIVACYPROCESSING` |
| Sous-traitants (Art 28) | `PRIVACYPROCESSOR` |
| Demandes / exercice de droits | `DSAR` |
| Violations de données (Art 33/34) | `PRIVACYBREACH` |
| Actions de protection / plan d'actions | `PRIVACYACTION` |

The CNIL / WP248 **DPIA-trigger criteria** (systematic monitoring, large-scale,
sensitive data, scoring, automated decisions, matching, vulnerable subjects,
innovative use, blocking a right) carried in the MADIS processing register are
mapped through so XORCISM can flag processing that requires a DPIA (≥2 criteria).

## Inputs accepted

- A **JSON bundle** — either already shaped as
  `{ "processing": [...], "processors": [...], "dsar": [...], "breaches": [...], "actions": [...] }`,
  or a MADIS-shaped object whose keys use French register names
  (`traitements`, `sous-traitants`, `demandes`, `violations`, `actions`).
- A **single CSV** register export (the register is auto-detected from the
  headers; force it with `--register traitements|sous-traitants|demandes|violations|actions`).
- A **directory of CSVs** (routed by filename keyword).

French **and** English headers are both accepted — matching is
accent/case-insensitive, e.g. `Nom du sous-traitant`, `Clauses contractuelles
vérifiées`, `Envoi des données hors UE`, `Base légale`, `Finalités`…

## Usage

```bash
# Normalize a MADIS export (prints the payload to stdout):
python run.py --file madis_export/            # a folder of per-register CSVs
python run.py --file traitements.csv          # a single register CSV
python run.py --file madis_bundle.json        # a JSON bundle
python run.py                                 # built-in sample (offline demo)
```

The normalized JSON is imported into XORCISM via **`POST /api/privacy/import`**
(a compliance-write session), which upserts each register **idempotently by
name** (re-running skips rows already present in the tenant). It then appears in
the DPO cockpit at **/privacy** — processors without a verified Art 28 agreement,
cross-border transfers without safeguards, DPIA-required processing without an
approved DPIA and overdue actions surface automatically in the DPO worklist.

## Safety & licence

- **Worker-safe, read-only, non-intrusive**: it only parses an export the
  operator produced from their own MADIS instance. It never connects to MADIS.
- **Licence-safe**: no MADIS (AGPLv3) source is vendored or redistributed here;
  this connector only reads MADIS's exported data files (interoperability).
  MADIS itself is run by the operator under its own AGPLv3 licence.
