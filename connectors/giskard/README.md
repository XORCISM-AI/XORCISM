# Giskard — AI model scan (LLM vulnerabilities) import

`giskard` · **import** connector · category **AI Security**

Imports **[Giskard](https://github.com/Giskard-AI/giskard)** (Apache-2.0) scan results into XORCISM's **AI red-team cockpit**. Giskard is the open-source evaluation & testing framework for AI systems: `giskard.scan(model, dataset)` probes an ML/LLM model or agent and returns a **ScanReport** whose issues each carry an **IssueGroup**, a **level** (`major` / `medium` / `minor`), a description, a metric + deviation, and examples.

This connector parses a Giskard scan report (`report.to_json()`), maps every issue to the **OWASP LLM Top 10** and to XORCISM's AI-BAS probe categories, and imports them as red-team results (`XORCISM.AIBASRUN` + `AIBASRESULT`) — so Giskard findings show up at **`/ai-redteam`** next to garak / PyRIT / promptfoo imports, with an exposure score and grade.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `system` | string | no | — | XORCISM AI system name to attach the run to (defaults to the model name in the report) |
| `min_level` | string | no | `minor` | Drop issues below this Giskard level: `minor` \| `medium` \| `major` |
| `file` | file | no | — | Offline: a saved Giskard scan report JSON (`report.to_json()`) to parse instead of the Hub API |

## How it works

`run.py` returns `{"source": "Giskard", "ai_system": "...", "ai_results": [...]}`; the XORCISM runner imports it via `import_ai_results` — one **AIBASRUN** (mode `imported`, source `Giskard`) plus one **AIBASRESULT** per issue. Because a Giskard issue *is* a detected vulnerability, every issue is imported with `outcome = fail`, which drives the run's exposure score (severity-weighted) and grade. The connector performs **no database access** itself, so it is safe to run on a remote worker.

### Mapping

| Giskard IssueGroup | OWASP LLM | XORCISM AI-BAS category |
|---|---|---|
| Prompt Injection | LLM01 | Prompt injection |
| Sensitive Information Disclosure · Data Leakage | LLM02 | Sensitive info disclosure |
| Harmfulness · Output Formatting | LLM05 | Insecure output handling |
| Hallucination and Misinformation | LLM09 | Misinformation |
| Robustness · Performance · Stereotypes · Stochasticity · Spurious correlation · Over/Underconfidence | — | (the Giskard group is kept as the category) |

An OWASP id carried in the issue's own `taxonomy` (e.g. `owasp:llm01`) always wins over the table above. The model-quality groups have no honest OWASP-LLM equivalent, so their OWASP column is left empty and the category carries the meaning.

**Levels** map `major → High`, `medium → Medium`, `minor → Low`.

### Producing a report

```python
import giskard
report = giskard.scan(giskard_model, giskard_dataset)
report.to_json("giskard_scan.json")     # → pass this file to the connector
```

Optionally point at a Giskard Hub instead:

```bash
export GISKARD_HUB_URL="https://hub.example.com"
export GISKARD_API_KEY="…"
export GISKARD_PROJECT="customer-support-rag"   # optional
```

## Running it

- **From XORCISM** — open **Connectors**, choose *Giskard — AI model scan (LLM vulnerabilities) import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:giskard`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/giskard/sample.json --connector giskard
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
