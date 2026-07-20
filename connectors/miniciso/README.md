# miniCISO connector

Imports a [miniCISO](https://github.com/icidade/miniCISO) assessment (MIT, by Irlan Cidade —
"agentic security staff") into XORCISM's native [`/miniciso`](../../xorcism_ts/client/miniciso.html)
evidence-driven assessment cockpit.

## What miniCISO is

Nine specialist roles — **Chief of Staff** (coordinator) plus **Threat Modeling, Security
Architecture, Code Review, AppSec, Compliance Mapper, Offensive Security, Recon & Attack Surface,
Security QA** — run a disciplined workflow that classifies every output as a **Finding**,
**Observation**, **Hypothesis** or **Missing-Evidence**. The operating discipline: *evidence before
narrative*, *recon surfaces candidates — not findings*, *confidence follows evidence quality*, a
GO/RESEARCH/NO-GO gate, and a **mandatory Security-QA gate** before anything is delivered. XORCISM
replicates all of this in `/miniciso`.

## What it maps to

| miniCISO | XORCISM | Path |
|---|---|---|
| Assessment (scope, objective, operator) | `XCOMPLIANCE.MINICISOASSESSMENT` | runner `miniciso` → `import_miniciso` |
| Tiered evidence (declared / runtime / validated) | `MINICISOEVIDENCE` | ″ |
| Classified outputs (role, class, gate, confidence, QA, cited evidence) | `MINICISOOUTPUT` | ″ |

Assessments are idempotent by (tenant, name): re-importing rebuilds the evidence + outputs. The
cockpit **re-applies the discipline on import** — recon output never lands as a finding, and a
finding that cites no evidence is demoted to a hypothesis — and enforces the QA delivery gate.

## Modes

1. **File.** `file` = a miniCISO JSON export. The parser is tolerant of the shape:
   - `{"assessments":[{name, objective, scope, evidence:[…], outputs:[…]}]}`
   - a single assessment object `{name, evidence, outputs}`
   - a bare list of outputs `[{role, cls, title, …}]`
   Role/class/tier/severity names are normalized to the cockpit vocabulary (e.g. `"Missing Evidence"`
   → `missing-evidence`, `"AppSec"` → `appsec-assessment`, `"validated behavior"` → `validated`).
2. **Demo.** No file → the bundled `sample.json` (a payments-API review: 4 evidence items, 5 outputs
   including a QA-passed finding and a QA-pending finding that blocks delivery).

No API and no secrets — miniCISO runs locally and you import its output.

```bash
python connectors/miniciso/run.py                                   # demo
python connectors/runner.py --selftest export.json --connector miniciso
```
