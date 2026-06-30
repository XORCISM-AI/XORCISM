/**
 * aware.ts — AWARE autonomous AI-agent governance cockpit (/aware).
 * KPIs + the T0–T4 constraint-tier ladder, the agent governance table (set tier / revoke-cascade /
 * reinstate), the parent→child hierarchy (cascade view), framework coverage, and the ungoverned worklist.
 * All from /api/aware*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }

const TIERS = ["T0", "T1", "T2", "T3", "T4"];
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="aw-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
const tierTag = (t: string | null): string => t ? `<span class="tier ${t}">${esc(t)}</span>` : `<span class="tier none">ungoverned</span>`;

async function load(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/aware"); } catch (e) { $("aw-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; return; }
  const s = d.summary || {};
  if (!s.agents) {
    $("aw-body").innerHTML = `<div class="aw-card" style="max-width:560px"><div class="muted" style="margin-bottom:8px">No AI agents discovered yet. Run an <code>aiguard</code> agent scan (/ai-guardrails), import via the AWARE connector, or seed a demo fleet (parent→child agents with mixed tiers).</div><button class="btn" id="seed">Seed demo fleet</button></div>`;
    $("seed").onclick = async () => { await postJSON("/api/aware/seed"); load(); };
    return;
  }
  const cards = [
    card("AI agents", String(s.agents ?? 0), "under governance scope"),
    card("Governed", `${s.governed ?? 0}`, `${s.ungoverned ?? 0} ungoverned`, (s.ungoverned ? "#fbbf24" : "#22c55e")),
    card("Cryptographic identity", String(s.withIdentity ?? 0), "T1+ non-human identity"),
    card("Autonomous, under-governed", String(s.autonomousUngoverned ?? 0), "autonomous below T3", (s.autonomousUngoverned ? "#f87171" : "#22c55e")),
    card("Revoked", String(s.revoked ?? 0), "kill-switch active", (s.revoked ? "#f87171" : "#94a3b8")),
    card("Frameworks covered", `${s.frameworksCovered ?? 0}/5`, "AICM·AIRMF·ISO·DORA·LLM", "#60a5fa"),
  ].join("");

  const ladder = (d.tierDist || []).map((t: any) => `<div class="lstep">
    <span class="n tier ${t.tier}" style="float:right">${t.count}</span>
    <div class="h">${esc(t.tier)} · ${esc(t.name)}</div>
    <div class="e">${esc(t.enforces)}</div>
    <div>${Object.values(t.frameworks || {}).map((f: any) => `<span class="chip">${esc(f)}</span>`).join("")}</div></div>`).join("");

  $("aw-body").innerHTML = `
    <div class="aw-cards">${cards}</div>
    <div class="aw-sec">Constraint-enforcement tiers (T0 → T4)</div>
    <div class="ladder">${ladder}</div>
    <div class="aw-sec">AI agents — governance</div>
    <div id="aw-agents" style="overflow-x:auto"></div>
    <div class="aw-sec">Agent hierarchy &amp; revocation cascade</div>
    <div id="aw-tree"></div>
    <div class="aw-sec">Compliance-framework coverage <span class="muted" style="font-weight:400;text-transform:none">— ≥1 governed agent mapped per framework</span></div>
    <div id="aw-fw"></div>`;

  renderAgents(d.agents || []);
  renderTree(d.roots || [], d.edges || [], d.agents || []);
  renderFrameworks(d.frameworks || []);
}

function renderAgents(agents: any[]): void {
  const opts = (sel: string | null): string => `<option value=""${sel ? "" : " selected"}>—</option>` + TIERS.map((t) => `<option${sel === t ? " selected" : ""}>${t}</option>`).join("");
  const rows = agents.map((a) => `<tr style="${a.revoked ? "opacity:.6" : ""}">
    <td><b>${esc(a.name)}</b>${a.autonomous ? ` <span class="chip">autonomous</span>` : ""}${a.parent ? `<div class="muted" style="font-size:10px">child of ${esc(a.parent)}</div>` : ""}</td>
    <td>${esc(a.framework)}</td>
    <td>${tierTag(a.tier)}</td>
    <td>${a.fingerprint ? `<span class="fp">${esc(a.fingerprint)}…</span>` : `<span class="chip off">none</span>`}</td>
    <td>${a.revoked ? `<span class="revoked">revoked</span><div class="muted" style="font-size:10px">${esc(a.revokedReason)}</div>` : `<span class="muted">active</span>`}</td>
    <td style="white-space:nowrap">
      <select class="in" data-tier="${esc(a.name)}">${opts(a.tier)}</select>
      ${a.revoked ? `<button class="btn sm sec" data-reinstate="${esc(a.name)}">Reinstate</button>` : `<button class="btn sm danger" data-revoke="${esc(a.name)}">Revoke ↯</button>`}
    </td></tr>`).join("") || `<tr><td colspan="6" class="muted">No agents.</td></tr>`;
  $("aw-agents").innerHTML = `<table class="tt"><thead><tr><th>Agent</th><th>Framework</th><th>Tier</th><th>Crypto identity</th><th>Status</th><th>Govern</th></tr></thead><tbody>${rows}</tbody></table>`;
  document.querySelectorAll("[data-tier]").forEach((el) => (el as HTMLSelectElement).onchange = async () => {
    const name = (el as HTMLElement).dataset.tier!; const tier = (el as HTMLSelectElement).value;
    await postJSON(`/api/aware/agent/${encodeURIComponent(name)}/tier`, { tier }); load();
  });
  document.querySelectorAll("[data-revoke]").forEach((el) => (el as HTMLElement).onclick = async () => {
    const name = (el as HTMLElement).dataset.revoke!;
    if (!confirm(`Revoke "${name}" and CASCADE to all its child agents (kill-switch)?`)) return;
    const r = await postJSON(`/api/aware/agent/${encodeURIComponent(name)}/revoke-cascade`, { reason: "operator kill-switch" });
    if (r && r.revoked) alert(`↯ Revocation cascade: ${r.revoked} agent(s) disabled — ${r.agents.join(", ")}`);
    load();
  });
  document.querySelectorAll("[data-reinstate]").forEach((el) => (el as HTMLElement).onclick = async () => { await postJSON(`/api/aware/agent/${encodeURIComponent((el as HTMLElement).dataset.reinstate!)}/reinstate`); load(); });
}

function renderTree(roots: any[], edges: any[], agents: any[]): void {
  const byName = new Map(agents.map((a) => [a.name, a]));
  const childrenOf = new Map<string, string[]>();
  for (const e of edges) { const arr = childrenOf.get(e.parent) || []; arr.push(e.child); childrenOf.set(e.parent, arr); }
  const line = (name: string, cls: string): string => { const a = byName.get(name); return `<div class="${cls}">${esc(name)} ${a ? tierTag(a.tier) : ""}${a && a.revoked ? ` <span class="revoked">↯ revoked</span>` : ""}</div>`; };
  const html = roots.map((r: any) => line(r.name, "root") + (childrenOf.get(r.name) || []).map((c) => line(c, "kid")).join("")).join("");
  $("aw-tree").innerHTML = html ? `<div class="tree">${html}</div><div class="muted" style="font-size:11px;margin-top:6px">Revoking a parent cascades to every child below it — AWARE's distributed kill-switch.</div>` : `<div class="muted">No agent hierarchy.</div>`;
}

function renderFrameworks(fw: any[]): void {
  $("aw-fw").innerHTML = `<div>${fw.map((f) => `<span class="chip ${f.covered ? "" : "off"}" style="font-size:11px;padding:3px 9px;margin:2px">${f.covered ? "✓" : "○"} ${esc(f.name)}</span>`).join("")}</div>`;
}

document.addEventListener("DOMContentLoaded", load);
