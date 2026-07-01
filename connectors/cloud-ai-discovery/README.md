# Cloud AI Discovery (Shadow AI / AI-SPM)

`cloud-ai-discovery` · **import** connector · category **AI Security**

Agentless discovery of AI/LLM services across your cloud accounts (AWS Bedrock / SageMaker, Azure OpenAI / ML, GCP Vertex AI) — the AI-SPM inventory layer. Each discovered model/endpoint becomes an AISYSTEM (provider / model / hosting / endpoint, Discovered=1, DiscoverySource); any that aren't already governed (no owner, no framework) surface as Shadow AI on /ai-systems. Reads from the cloud control plane (no agent). Config: per-cloud read-only credentials in the worker environment (AWS_*, AZURE_*, GOOGLE_APPLICATION_CREDENTIALS); or pass `file` = a saved discovery export JSON (or run with no config for the bundled sample).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `limit` | int | no | `500` | Maximum AI services to import (range 1–5000) |
| `file` | file | no | — | Offline: a saved cloud-AI discovery export JSON |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Cloud AI Discovery (Shadow AI / AI-SPM)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:cloud-ai-discovery`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/cloud-ai-discovery/sample.json --connector cloud-ai-discovery
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
