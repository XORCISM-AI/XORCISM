# SkillAegis — Cyber-exercise scenarios (CEXF)

`skillaegis` · **import** connector · category **Crisis Management**

Imports cyber-exercise scenarios from [**SkillAegis**](https://github.com/SkillAegis) (CIRCL / MISP ecosystem) — a platform to *design, run and monitor* training exercises. The [SkillAegis-Editor](https://github.com/SkillAegis/SkillAegis-Editor) authors scenarios in the **Common Exercise Format (CEXF)** (JSON); the [SkillAegis-Dashboard](https://github.com/SkillAegis/SkillAegis-Dashboard) runs them and tracks participants, injects and scores in real time.

This connector maps a CEXF scenario into XORCISM's **Crisis Management / Tabletop-Exercise** library:

| CEXF | → XORCISM |
|---|---|
| `exercise` (name, description, meta.level, tags, duration) | **CRISISSCENARIO** — a reusable scenario template (name, description, objectives, severity from level, ATT&CK tags, author, duration, `Source = SkillAegis (CEXF)`) |
| each `inject` (task), ordered by `inject_flow` | **EXERCISEINJECT** — StepOrder, Title = inject name, Description = the flow description, InjectType = the inject action / target-tool, ExpectedAction = the evaluation `result` |

The imported scenario can then be **launched as a tabletop exercise** at **/crisis-management** (one click copies its injects into an AUDIT of type *Tabletop Exercise*, tracks participants/roles, and produces an after-action report).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | A SkillAegis CEXF scenario (`.json`), a directory of scenarios, or a JSON list/export. |

Get scenarios from the SkillAegis-Editor, or the ready-made ones in the [`SkillAegis/scenarios`](https://github.com/SkillAegis/SkillAegis/tree/main/scenarios) folder (ransomware, phishing, MISP workflows, …).

## Output → XORCISM

`run(params, workdir)` returns (imported by `runner.import_exercises`, idempotent by the CEXF exercise UUID):
```jsonc
{
  "source": "SkillAegis (CEXF)",
  "exercises": [
    { "guid", "name", "description", "type": "Cyber Exercise", "severity", "objectives",
      "attack", "author", "duration", "refs",
      "injects": [ { "guid", "title", "description", "type", "expected", "order" } ] }
  ],
  "summary": { "exercises", "injects" }
}
```
The connector performs **no database access** (runs on a remote worker). Required permission: `connector:skillaegis`.

## Running it

- **From XORCISM** — **Connectors → SkillAegis**, provide the scenario file, run (admin only; creates a job for `connectors/runner.py`).
- **Self-test** — parse & import the bundled `sample.json` (a ransomware tabletop):
  ```bash
  python connectors/runner.py --selftest connectors/skillaegis/sample.json --connector skillaegis
  ```
  > `--selftest` writes to the DB — use a throwaway `XORCISM_DB_DIR` to avoid touching live data.
- **CLI** — `python connectors/skillaegis/run.py connectors/skillaegis/sample.json` prints the normalized JSON.

---
<sub>SkillAegis is AGPL-3.0 (Sami Mokaddem / CIRCL). CEXF = Common Exercise Format. This connector imports scenario definitions; it does not connect to a live Dashboard session (the Dashboard streams state over Socket.IO/ZMQ).</sub>
