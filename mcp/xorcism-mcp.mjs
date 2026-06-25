#!/usr/bin/env node
/**
 * xorcism-mcp.mjs — Model Context Protocol (MCP) server for XORCISM.
 *
 * Exposes the XORCISM Cyber Risk Operations Center to any MCP client (Claude Desktop, Cursor, …) so
 * an AI agent can query your posture, assets, exposures, risk, incidents and compliance — and open
 * incidents — over the public REST API (/api/v1, API-key auth, scopes enforced server-side).
 *
 * Zero dependencies: implements MCP JSON-RPC 2.0 over newline-delimited stdio by hand, and proxies
 * to the v1 API with the global fetch (Node 18+). Read-only by default; the one write tool
 * (create_incident) needs an API key with the incidents:write scope.
 *
 * Run (configured in your MCP client):
 *   XORCISM_API_URL=http://localhost:9292/api/v1 XORCISM_API_KEY=xor_... node mcp/xorcism-mcp.mjs
 */
import process from "node:process";

const API_URL = (process.env.XORCISM_API_URL || "http://localhost:9292/api/v1").replace(/\/+$/, "");
const API_KEY = process.env.XORCISM_API_KEY || "";
const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "xorcism", version: "1.0.0" };

const log = (...a) => process.stderr.write(`[xorcism-mcp] ${a.join(" ")}\n`); // stderr only — stdout is the JSON-RPC channel

// ── REST helpers ──────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const url = API_URL + path;
  const headers = { Accept: "application/json" };
  if (API_KEY) headers.Authorization = `Bearer ${API_KEY}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!r.ok) throw new Error(`HTTP ${r.status} ${method} ${path}: ${typeof data === "string" ? data.slice(0, 200) : JSON.stringify(data).slice(0, 300)}`);
  return data;
}
const qs = (o) => { const p = Object.entries(o || {}).filter(([, v]) => v != null && v !== "").map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`); return p.length ? "?" + p.join("&") : ""; };

// ── Tool catalogue ────────────────────────────────────────────────────────────
const TOOLS = [
  { name: "xorcism_health", description: "Service health/version of the XORCISM API. No auth.", schema: {}, run: () => api("GET", "/health") },
  { name: "xorcism_whoami", description: "The identity, tenant and scopes of the configured API key.", schema: {}, run: () => api("GET", "/me") },
  { name: "list_assets", description: "List assets in the inventory (optionally filter by query).", schema: { q: { type: "string", description: "name/host filter" }, limit: { type: "integer", description: "max rows (default 50)" } },
    run: (a) => api("GET", "/assets" + qs({ q: a.q, limit: a.limit ?? 50 })) },
  { name: "get_asset", description: "Full detail for one asset by id (vulns, services, exposure).", schema: { id: { type: "integer", description: "AssetID", required: true } },
    run: (a) => api("GET", `/assets/${encodeURIComponent(a.id)}`) },
  { name: "top_exposures", description: "The prioritised exposure worklist (exploitability + relevance fused).", schema: {}, run: () => api("GET", "/exposures") },
  { name: "risk_summary", description: "Enterprise risk posture summary (score, contributors).", schema: {}, run: () => api("GET", "/risk") },
  { name: "list_incidents", description: "List incidents (most recent first).", schema: { limit: { type: "integer" } }, run: (a) => api("GET", "/incidents" + qs({ limit: a.limit ?? 50 })) },
  { name: "create_incident", description: "Open an incident. Requires an API key with incidents:write scope.",
    schema: { title: { type: "string", required: true }, severity: { type: "string", description: "Critical|High|Medium|Low|Info" }, description: { type: "string" }, category: { type: "string" } },
    run: (a) => api("POST", "/incidents", { title: a.title, severity: a.severity, description: a.description, category: a.category }) },
  { name: "compliance_posture", description: "Compliance inventory + posture score (audits/findings/policies).", schema: {}, run: () => api("GET", "/compliance-management") },
  { name: "risk_register", description: "Risk register: inherent→residual posture + treatment worklist.", schema: {}, run: () => api("GET", "/risk-register") },
  { name: "threat_informed_defense", description: "ATT&CK technique coverage (adversary use vs detect/mitigate/test).", schema: {}, run: () => api("GET", "/threat-informed-defense") },
  { name: "xorcism_get", description: "Escape hatch: GET any read endpoint under /api/v1 (e.g. '/pqcmm', '/sca', '/fair-mam').",
    schema: { path: { type: "string", description: "a path under /api/v1 starting with /", required: true } },
    run: (a) => api("GET", a.path.startsWith("/") ? a.path : "/" + a.path) },
];
const TOOL_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

function toolSchema(t) {
  const properties = {}; const required = [];
  for (const [k, v] of Object.entries(t.schema)) { const { required: req, ...rest } = v; properties[k] = rest; if (req) required.push(k); }
  return { type: "object", properties, ...(required.length ? { required } : {}) };
}

// ── JSON-RPC plumbing ─────────────────────────────────────────────────────────
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\n"); }
function reply(id, result) { send({ jsonrpc: "2.0", id, result }); }
function replyError(id, code, message) { send({ jsonrpc: "2.0", id, error: { code, message } }); }

async function handle(req) {
  const { id, method, params } = req;
  if (method === "initialize") {
    return reply(id, { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO });
  }
  if (method === "notifications/initialized" || method === "notifications/cancelled") return; // notification, no reply
  if (method === "ping") return reply(id, {});
  if (method === "tools/list") {
    return reply(id, { tools: TOOLS.map((t) => ({ name: t.name, description: t.description, inputSchema: toolSchema(t) })) });
  }
  if (method === "tools/call") {
    const t = TOOL_BY_NAME.get(params?.name);
    if (!t) return replyError(id, -32602, `unknown tool: ${params?.name}`);
    try {
      const out = await t.run(params.arguments || {});
      return reply(id, { content: [{ type: "text", text: typeof out === "string" ? out : JSON.stringify(out, null, 2) }] });
    } catch (e) {
      return reply(id, { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true });
    }
  }
  if (id !== undefined) return replyError(id, -32601, `method not found: ${method}`);
}

// newline-delimited JSON-RPC over stdin
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
    if (!line) continue;
    let req; try { req = JSON.parse(line); } catch { log("bad JSON line"); continue; }
    Promise.resolve(handle(req)).catch((e) => { if (req?.id !== undefined) replyError(req.id, -32603, e.message); });
  }
});
process.stdin.on("end", () => process.exit(0));
log(`ready — proxying ${API_URL} (key ${API_KEY ? "set" : "MISSING"})`);
