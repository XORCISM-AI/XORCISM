/**
 * compliance-management.ts — Compliance / GRC inventory + governance worklist
 * (/compliance-management). Audits + open-findings/policy worklist, from /api/compliance-management.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface AuditRow { id: number; name: string; type: string; status: string; date: string | null; completed: boolean; findings: number; open: number; high: number; overdue: number; unassigned: number; score: number; }
interface Finding { id: number; audit: string; name: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; overdue: boolean; unassigned: boolean; noPlan: boolean; kind: "finding" | "policy"; label: string; }
interface Inventory {
  rows: AuditRow[]; findings: Finding[];
  summary: { audits: number; inProgress: number; planned: number; completed: number; completionRate: number | null; findings: number; openFindings: number; highOpen: number; overdue: number; unassigned: number; policiesReview: number; bySeverity: Record<string, number>; byStatus: Record<string, number>; byType: Record<string, number>; };
}

const sevClass = (s: string): string => `s-${(s || "low").toLowerCase()}`;
const stClass = (s: string): string => (/complet|clos|done/i.test(s) ? "st-completed" : /progress|cours/i.test(s) ? "st-progress" : "st-planned");
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="cp-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: AuditRow): string {
  const posture = r.open
    ? `<span class="pill p-open">${r.open} open</span>${r.high ? `<span class="pill p-high">${r.high} high</span>` : ""}${r.overdue ? `<span class="tag">${r.overdue} overdue</span>` : ""}`
    : `<span class="pill p-clean">clean</span>`;
  return `<tr>
    <td><div class="aname">${esc(r.name)}</div><div class="muted" style="font-size:11px">${esc(r.type)}${r.date ? ` · ${esc(r.date)}` : ""}</div></td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${r.findings}</td>
    <td>${posture}</td>
    <td>${r.unassigned ? `<span class="tag">${r.unassigned}</span>` : `<span class="muted">0</span>`}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  return `<li><span class="dot" style="background:${f.kind === "policy" ? "#c084fc" : "#fb923c"}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="/?db=XCOMPLIANCE&table=AUDITFINDING">${esc(f.audit)}</a> — ${esc(f.label)}</li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/compliance-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("cp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No audits yet. <a href="/?db=XCOMPLIANCE&table=AUDIT">Create your first audit</a>, record its
      <a href="/?db=XCOMPLIANCE&table=AUDITFINDING">findings</a>, and the governance worklist appears here.</div>`;
    return;
  }

  const cards = [
    card("Audits", String(s.audits), `${s.inProgress} in progress · ${s.completed} done`),
    card("Completion", s.completionRate != null ? `${s.completionRate}%` : "—", "audits completed", s.completionRate != null ? (s.completionRate >= 70 ? "#34d399" : s.completionRate >= 40 ? "#fbbf24" : "#f87171") : undefined),
    card("Open findings", String(s.openFindings), `of ${s.findings} total`, s.openFindings ? "#fb923c" : "#34d399"),
    card("High / critical", String(s.highOpen), "open, high severity", s.highOpen ? "#f87171" : "#34d399"),
    card("Overdue", String(s.overdue), "remediation past due", s.overdue ? "#f87171" : "#34d399"),
    card("Unassigned", String(s.unassigned), "findings · no owner", s.unassigned ? "#fbbf24" : "#34d399"),
    card("Policies to review", String(s.policiesReview), "past review date", s.policiesReview ? "#fbbf24" : undefined),
  ].join("");

  const bySev = Object.entries(s.bySeverity).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="sev ${sevClass(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
  const byType = Object.entries(s.byType).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No open findings or overdue policies — clean compliance posture.</div>`;

  const table = `<table class="cp"><thead><tr>
      <th>Audit</th><th>Status</th><th>Findings</th><th>Posture</th><th>Unassigned</th><th title="Posture score">Score</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("cp-body").innerHTML = `<div class="cp-cards">${cards}</div>
    <div class="cp-section">Remediation worklist (${d.findings.length})</div>${findings}
    <div class="cp-section">Open findings by severity</div><div class="breakdown">${bySev || '<span class="muted">none</span>'}</div>
    <div class="cp-section">Audits by type</div><div class="breakdown">${byType}</div>
    <div class="cp-section">Audits (${d.rows.length})</div>${table}
    <div class="legend">↳ <b>Score</b> is an audit's posture (higher = worse): open findings weighted by severity
      (critical 25 / high 18 / medium 8 / low 3) + overdue +10 + unassigned +3. Manage under
      <a href="/?db=XCOMPLIANCE&table=AUDIT">Audits</a> / <a href="/?db=XCOMPLIANCE&table=AUDITFINDING">Findings</a>.</div>`;
}

document.addEventListener("DOMContentLoaded", () => void load());
