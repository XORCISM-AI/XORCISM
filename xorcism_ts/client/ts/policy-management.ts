/**
 * policy-management.ts — Policy & document management inventory + governance worklist
 * (/policy-management). Policy lifecycle + controlled-document register, from
 * /api/policy-management. Read-only; CRUD stays in the schema-driven explorer.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface PolicyRow { id: number; name: string; reference: string; category: string; framework: string; language: string; status: string; version: string; owner: string | null; effectiveDate: string | null; reviewDate: string | null; reviewInDays: number | null; published: boolean; retired: boolean; score: number; issues: string[]; }
interface DocumentRow { id: number; name: string; type: string; category: string; status: string; version: string; language: string; owner: string | null; reviewDate: string | null; validUntil: string | null; expired: boolean; issues: string[]; }
interface Finding { id: number; name: string; kind: "policy" | "document"; severity: "High" | "Medium" | "Low"; reason: string; label: string; }
interface Inventory {
  rows: PolicyRow[]; documents: DocumentRow[]; findings: Finding[];
  summary: { policies: number; published: number; draft: number; inReview: number; approved: number; retired: number; overdueReview: number; dueSoon: number; noOwner: number; noVersion: number; notEffective: number; documents: number; expiredDocs: number; docsNoOwner: number; frameworks: number; languages: number; avgScore: number; byStatus: Record<string, number>; byFramework: Record<string, number>; byCategory: Record<string, number>; byLanguage: Record<string, number>; };
}

const stClass = (s: string): string => {
  const v = (s || "").toLowerCase();
  return /publish|publié|vigueur|active/.test(v) ? "st-published"
    : /approv/.test(v) ? "st-approved"
    : /review|revue|relecture/.test(v) ? "st-review"
    : /retir|archiv|obsolet|abrog/.test(v) ? "st-retired" : "st-draft";
};
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="pp-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function policyHtml(r: PolicyRow): string {
  const issues = r.issues.length
    ? r.issues.map((i) => `<span class="tag${/due in|effective|version/.test(i) ? " tag-w" : ""}">${esc(i)}</span>`).join("")
    : (r.retired ? `<span class="muted">retired</span>` : `<span class="s-lo">✓ ok</span>`);
  return `<tr>
    <td><div class="pname">${esc(r.name)}${r.language !== "—" ? `<span class="lang">${esc(r.language)}</span>` : ""}</div>
      <div class="muted" style="font-size:11px">${esc(r.framework)}${r.reference !== "—" ? ` · <span class="ref">${esc(r.reference)}</span>` : ""}</div></td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${esc(r.version)}</td>
    <td>${r.owner ? esc(r.owner) : `<span class="tag">none</span>`}</td>
    <td>${r.reviewDate ? `${esc(r.reviewDate)}${r.reviewInDays != null && r.reviewInDays < 0 ? ` <span class="tag">${-r.reviewInDays}d</span>` : ""}` : `<span class="muted">—</span>`}</td>
    <td>${issues}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function docHtml(d: DocumentRow): string {
  const issues = d.issues.length ? d.issues.map((i) => `<span class="tag${/version/.test(i) ? " tag-w" : ""}">${esc(i)}</span>`).join("") : `<span class="s-lo">✓ ok</span>`;
  return `<tr>
    <td><div class="pname">${esc(d.name)}${d.language !== "—" ? `<span class="lang">${esc(d.language)}</span>` : ""}</div>
      <div class="muted" style="font-size:11px">${esc(d.type)}${d.category !== "—" ? ` · ${esc(d.category)}` : ""}</div></td>
    <td>${d.status !== "—" ? `<span class="st ${stClass(d.status)}">${esc(d.status)}</span>` : `<span class="muted">—</span>`}</td>
    <td>${esc(d.version)}</td>
    <td>${d.owner ? esc(d.owner) : `<span class="tag">none</span>`}</td>
    <td>${d.validUntil ? esc(d.validUntil) : `<span class="muted">—</span>`}</td>
    <td>${issues}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  return `<li><span class="dot" style="background:${f.kind === "document" ? "#38bdf8" : "#c084fc"}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="/?db=${f.kind === "document" ? "XCOMPLIANCE&table=DOCUMENT" : "XORCISM&table=POLICY"}">${f.kind}</a> — ${esc(f.label)}</li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/policy-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("pp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length && !d.documents.length) {
    $("pp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No policies yet. <a href="/?db=XORCISM&table=POLICY">Create your first policy</a> (or run the ISO 42001 seeder),
      and the governance worklist appears here.</div>`;
    return;
  }

  const cards = [
    card("Policies", String(s.policies), `${s.published} published · ${s.retired} retired`),
    card("Published", String(s.published), s.policies ? `${Math.round((s.published / s.policies) * 100)}% of policies` : "—", s.published ? "#34d399" : undefined),
    card("Drafts / review", String(s.draft + s.inReview + s.approved), `${s.inReview} in review · ${s.approved} approved`, (s.draft + s.inReview + s.approved) ? "#fbbf24" : undefined),
    card("Overdue review", String(s.overdueReview), "past review date", s.overdueReview ? "#f87171" : "#34d399"),
    card("Due soon", String(s.dueSoon), "review in ≤90d", s.dueSoon ? "#fbbf24" : undefined),
    card("No owner", String(s.noOwner), "active · unaccountable", s.noOwner ? "#fbbf24" : "#34d399"),
    card("Documents", String(s.documents), `${s.expiredDocs} expired`, s.expiredDocs ? "#fb923c" : undefined),
    card("Avg score", String(s.avgScore), "governance gap (↓ better)", s.avgScore >= 30 ? "#f87171" : s.avgScore >= 10 ? "#fbbf24" : "#34d399"),
  ].join("");

  const chip = (k: string, n: number): string => `<span class="bd">${esc(k)} <b>${n}</b></span>`;
  const byFw = Object.entries(s.byFramework).sort((a, b) => b[1] - a[1]).map(([k, n]) => chip(k, n)).join("");
  const byCat = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]).map(([k, n]) => chip(k, n)).join("");
  const byLang = Object.entries(s.byLanguage).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="lang">${esc(k)}</span> <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No overdue reviews, unpublished/unowned policies or expired documents — clean posture.</div>`;

  const policyTable = `<table class="pp"><thead><tr>
      <th>Policy</th><th>Status</th><th>Ver.</th><th>Owner</th><th>Review</th><th>Gaps</th><th title="Governance score">Score</th>
    </tr></thead><tbody>${d.rows.map(policyHtml).join("")}</tbody></table>`;

  const docTable = d.documents.length ? `<div class="pp-section">Document register (${d.documents.length})</div>
    <table class="pp"><thead><tr>
      <th>Document</th><th>Status</th><th>Ver.</th><th>Owner</th><th>Valid until</th><th>Gaps</th>
    </tr></thead><tbody>${d.documents.map(docHtml).join("")}</tbody></table>` : "";

  $("pp-body").innerHTML = `<div class="pp-cards">${cards}</div>
    <div class="pp-section">Governance worklist (${d.findings.length})</div>${findings}
    ${byFw ? `<div class="pp-section">By framework</div><div class="breakdown">${byFw}</div>` : ""}
    ${byCat ? `<div class="pp-section">By category</div><div class="breakdown">${byCat}</div>` : ""}
    ${byLang ? `<div class="pp-section">By language</div><div class="breakdown">${byLang}</div>` : ""}
    <div class="pp-section">Policies (${d.rows.length})</div>${policyTable}
    ${docTable}
    <div class="legend">↳ <b>Score</b> is a policy's governance gap (higher = worse): review overdue +30 / due-soon +6 / no review date +8,
      not published +15, no owner +15, no version +8, no effective date +6. Manage under
      <a href="/?db=XORCISM&table=POLICY">Policies</a> / <a href="/?db=XCOMPLIANCE&table=DOCUMENT">Documents</a>.</div>`;
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
