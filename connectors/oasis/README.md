# OASIS connector (AI SAST — Ollama security scanner)

Imports a report from [OASIS](https://github.com/psyray/oasis) — the **Ollama Automated Security
Intelligence Scanner** (by psyray, GPL-3.0). OASIS is an **AI-powered SAST** tool: rather than rule-based
pattern matching, it uses **local Ollama LLMs + vector embeddings** in a two-phase pipeline (a
lightweight model flags suspicious code, a powerful model deep-analyzes it) to detect **24+ vulnerability
classes** across many languages — SQL injection, XSS, command injection, RCE, SSRF, path traversal,
insecure deserialization, JWT flaws, sensitive-data exposure, auth/session issues, crypto weaknesses,
CORS misconfiguration and more. Everything runs locally; no code leaves your machine.

## Mapping
OASIS writes a **SARIF 2.1.0** report under `security_reports/<project>/<timestamp>/`. This connector
parses that SARIF with the shared `connectors/_sarif.py` parser:
- the scanned project → an **`ASSET`**
- each finding → a **`VULNERABILITY` / `ASSETVULNERABILITY`** (severity from the SARIF
  `security-severity` / level; rule, message and `file:line` in the description; a referenced CVE
  becomes the finding ref, else a stable `SARIF-<rule>` ref)
- the run is also recorded as a **DevSecOps SAST scan** (`/devsecops`), since `oasis` is registered in
  the runner's `_DEVSECOPS_TOOLS`.

## Usage
```bash
pipx install oasis-scanner            # or Docker Compose (see the OASIS repo)
ollama pull gemma3:4b && ollama pull llama3:latest
oasis -i ./my-app -sm gemma3:4b -m llama3:latest --vulns all --output-format sarif
# then import the produced .sarif via the connector (file param), or run the demo:
python run.py                          # bundled sample (6 findings)
python run.py --file security_reports/my-app/<ts>/report.sarif --project my-app
```

Worker-safe: stdlib only, ASCII-only output, no DB access. The normalized result
(`{assets, services, cpes, vulns}`) is consumed by `runner.import_findings`. Because the output is
standard SARIF, the same connector also works for OASIS reports regenerated in CI. Sibling of the
generic `sarif` import connector and the `drogonsec` / `semgrep` SAST connectors.
