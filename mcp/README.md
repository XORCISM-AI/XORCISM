# XORCISM MCP server

Expose the XORCISM Cyber Risk Operations Center to any **Model Context Protocol** client
(Claude Desktop, Cursor, Claude Code, …) so an AI agent can query your posture, assets, exposures,
risk, incidents and compliance — and open incidents — through the public REST API
(`/api/v1`, API-key auth, **scopes enforced server-side**).

Zero dependencies: [`xorcism-mcp.mjs`](xorcism-mcp.mjs) implements MCP JSON-RPC 2.0 over
newline-delimited stdio by hand and proxies to v1 with the built-in `fetch` (Node 18+). Read-only by
default; the one write tool (`create_incident`) needs a key with the `incidents:write` scope.

## Setup

1. In XORCISM, create an API key (**/api-keys**) with the scopes you want the agent to have
   (e.g. `assets:read`, `risk:read`, `incidents:read`, optionally `incidents:write`).
2. Point the server at your instance and run it from your MCP client.

### Claude Desktop / Cursor (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "xorcism": {
      "command": "node",
      "args": ["C:/Users/jerom/OneDrive/Documents/XORCISM/mcp/xorcism-mcp.mjs"],
      "env": {
        "XORCISM_API_URL": "http://localhost:9292/api/v1",
        "XORCISM_API_KEY": "xor_xxxxxxxxxxxxxxxx"
      }
    }
  }
}
```

(Use the portable Node if you prefer: set `"command"` to
`C:/Users/jerom/OneDrive/Documents/XORCISM/tools/nodejs/node.exe`.)

## Tools

| Tool | Scope | What it does |
|---|---|---|
| `xorcism_health` | none | API health/version |
| `xorcism_whoami` | — | identity, tenant & scopes of the key |
| `list_assets` / `get_asset` | `assets:read` | inventory + per-asset detail |
| `top_exposures` | `risk:read` | prioritised exposure worklist |
| `risk_summary` / `risk_register` | `risk:read` | enterprise posture + treatment worklist |
| `list_incidents` | `incidents:read` | incidents, recent first |
| `create_incident` | `incidents:write` | open an incident |
| `compliance_posture` | `compliance:read` | audits/findings/policies + score |
| `threat_informed_defense` | `tid:read` | ATT&CK technique coverage |
| `xorcism_get` | (per path) | escape hatch — GET any `/api/v1` read endpoint |

## Notes

- The MCP server holds **no credentials of its own** — it forwards your API key as a bearer token and
  the XORCISM server enforces the key's scopes and tenant. A read-only key keeps the agent read-only.
- Transport: stdio (newline-delimited JSON-RPC 2.0), MCP protocol `2024-11-05`.
- Quick check: `XORCISM_API_URL=… XORCISM_API_KEY=… node mcp/xorcism-mcp.mjs` then send
  `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` on stdin.
