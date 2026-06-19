/**
 * incident-management.ts — Incident Management inventory + governance worklist
 * (/incident-management). Renders the incident queue with posture + derived findings,
 * from /api/incident-management.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Row {
  id: number; name: string; severity: string; status: string; open: boolean; assignee: string | null;
  classification: string; determination: string; reported: string | null; durationHours: number | null;
  ageDays: number | null; assets: number; breached: boolean; compromise: boolean; flags: string[]; score: number;
}
interface Finding { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; incidentId: number; incident: string; }
interface Inventory {
  rows: Row[]; findings: Finding[];
  summary: { total: number; open: number; criticalOpen: number; breached: number; unassigned: number; stale: number; compromises: number; mttrHours: number | null; byStatus: Record<string, number>; bySeverity: Record<string, number>; };
}

const sevClass = (s: string): string => `s-${(s || "unrated").toLowerCase().replace(/[^a-z]/g, "")}`;
const stClass = (s: string): string => (/resolv|clos|done/i.test(s) ? "st-resolved" : "st-open");
const scoreClass = (n: number): string => (n >= 40 ? "s-hi" : n >= 15 ? "s-md" : "s-lo");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="im-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: Row): string {
  const flags = r.flags.length ? r.flags.map((f) => `<span class="flag">${esc(f)}</span>`).join("") : `<span class="muted">—</span>`;
  const badges = [r.breached ? `<span class="badge b-breach">breach</span>` : "", r.compromise ? `<span class="badge b-comp">compromise</span>` : ""].filter(Boolean).join(" ");
  const age = r.open && r.ageDays != null ? `${r.ageDays}d open` : (r.durationHours != null ? `${r.durationHours}h` : "—");
  return `<tr>
    <td><div class="iname">${esc(r.name)}</div>${badges ? `<div style="margin-top:3px">${badges}</div>` : ""}</td>
    <td><span class="sev ${sevClass(r.severity)}">${esc(r.severity)}</span></td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${esc(r.assignee || "—")}</td>
    <td>${esc(age)}</td>
    <td>${r.assets || `<span class="muted">0</span>`}</td>
    <td>${flags}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  return `<li><span class="sev-dot dot-${f.severity}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> —
    <a href="/?db=XINCIDENT&table=INCIDENT">${esc(f.label)}</a></li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/incident-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("im-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("im-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No incidents yet. <a href="/?db=XINCIDENT&table=INCIDENT">Open your first incident</a> — set its severity,
      status, owner and scoped assets, then come back to see the governance worklist.</div>`;
    return;
  }

  const cards = [
    card("Incidents", String(s.total), `${s.open} open`),
    card("Open critical", String(s.criticalOpen), "high/critical, still open", s.criticalOpen ? "#f87171" : "#34d399"),
    card("SLA / RTO breached", String(s.breached), "past target", s.breached ? "#fb923c" : "#34d399"),
    card("Unassigned", String(s.unassigned), "open · no owner", s.unassigned ? "#fb923c" : "#34d399"),
    card("Stale", String(s.stale), "open > 7 days", s.stale ? "#fbbf24" : undefined),
    card("Compromises", String(s.compromises), "confirmed", s.compromises ? "#f87171" : "#34d399"),
    card("MTTR", s.mttrHours != null ? `${s.mttrHours}h` : "—", "mean time to resolve"),
  ].join("");

  const bySev = Object.entries(s.bySeverity).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="sev ${sevClass(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
  const byStat = Object.entries(s.byStatus).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No governance findings — every incident is owned, classified, within SLA and scoped.</div>`;

  const table = `<table class="im"><thead><tr>
      <th>Incident</th><th>Severity</th><th>Status</th><th>Owner</th><th>Age / Duration</th><th>Assets</th><th>Findings</th><th title="Derived priority">Priority</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("im-body").innerHTML = `<div class="im-cards">${cards}</div>
    <div class="im-section">Response worklist (${d.findings.length})</div>${findings}
    <div class="im-section">By severity</div><div class="breakdown">${bySev}</div>
    <div class="im-section">By status</div><div class="breakdown">${byStat}</div>
    <div class="im-section">Queue (${d.rows.length})</div>${table}
    <div class="legend">↳ <b>Priority</b> is a derived score (0–100): confirmed compromise +30, open high/critical +25,
      SLA/RTO breach +20, unassigned +12, stale (&gt;7d) / no-scope / unclassified +5–10. Manage under
      <a href="/?db=XINCIDENT&table=INCIDENT">Manage incidents</a>; SLA/RTO breach detail on
      <a href="/incident-sla">SLA / RTO</a>.</div>`;
}

document.addEventListener("DOMContentLoaded", () => void load());
