/**
 * risk-register.ts — Risk Register inventory + treatment worklist (/risk-register).
 * Inherent→residual posture, treatment, CRQ/FAIR ALE, from /api/risk-register.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Row { id: number; ref: string; title: string; category: string; owner: string | null; asset: string | null; status: string; open: boolean; inherent: string; current: string; residual: string; residualRank: number; treatment: string; hasPlan: boolean; ale: number | null; sle: number | null; currency: string; reviewInDays: number | null; reviewOverdue: boolean; score: number; }
interface Finding { id: number; ref: string; title: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; reason: string; kind: string; label: string; }
interface Inventory {
  rows: Row[]; findings: Finding[];
  summary: { risks: number; open: number; closed: number; treatedRate: number | null; highCritical: number; untreated: number; accepted: number; overdueReview: number; noOwner: number; quantified: number; totalALE: number; currency: string; byLevel: Record<string, number>; byStatus: Record<string, number>; byTreatment: Record<string, number>; byCategory: Record<string, number>; riskScore: number; };
}

let CUR = "EUR";
const rankOf = (label: string): number => ({ critical: 0, "very high": 0, high: 1, medium: 2, moderate: 2, low: 3, "very low": 4 }[label.toLowerCase()] ?? 5);
const lvl = (label: string): string => `<span class="lvl lvl-${rankOf(label)}">${esc(label)}</span>`;
const scoreClass = (n: number): string => (n >= 50 ? "s-hi" : n >= 25 ? "s-md" : "s-lo");
const postureColor = (n: number): string => (n >= 60 ? "#f87171" : n >= 35 ? "#fbbf24" : "#34d399");
function money(n: number | null): string {
  if (n == null) return "—";
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency: CUR, maximumFractionDigits: 0 }).format(n); }
  catch { return `${CUR} ${Math.round(n).toLocaleString()}`; }
}

function card(lbl: string, val: string, foot: string, color?: string, cls = "rr-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: Row): string {
  const treat = r.treatment !== "—" ? `<span class="tr">${esc(r.treatment)}</span>${r.hasPlan ? "" : ` <span class="muted" style="font-size:11px">no plan</span>`}` : `<span class="tag">untreated</span>`;
  const review = r.reviewInDays == null ? `<span class="muted">—</span>` : r.reviewOverdue ? `<span class="tag">${-r.reviewInDays}d overdue</span>` : `<span class="muted">${r.reviewInDays}d</span>`;
  return `<tr>
    <td><div class="rname">${esc(r.ref)} <span style="font-weight:400">${esc(r.title)}</span></div>
      <div class="muted" style="font-size:11px">${esc(r.category)}${r.owner ? ` · ${esc(r.owner)}` : ""}${r.asset ? ` · ${esc(r.asset)}` : ""}</div></td>
    <td>${lvl(r.inherent)}<span class="arrow">→</span>${lvl(r.residual)}</td>
    <td>${treat}</td>
    <td><span class="st ${r.open ? "st-open" : "st-closed"}">${esc(r.status)}</span></td>
    <td class="num">${r.ale != null ? `<b>${esc(money(r.ale))}</b>` : "<span class=\"muted\">—</span>"}</td>
    <td>${review}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const color = f.kind === "untreated" ? "#f87171" : f.kind === "accepted" ? "#fb923c" : f.kind === "owner" ? "#64748b" : "#fbbf24";
  return `<li><span class="dot" style="background:${color}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="/?db=XCOMPLIANCE&table=RISKREGISTERENTRY&filterCol=RiskRegisterEntryID&filterVal=${esc(f.id)}">${esc(f.ref)}</a>
    ${f.title ? `<span class="muted">${esc(f.title)}</span> — ` : "— "}${esc(f.label)}</li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/risk-register"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("rr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  CUR = d.summary.currency || "EUR";
  const s = d.summary;

  if (!d.rows.length) {
    $("rr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No risks in the register yet. <a href="/?db=XCOMPLIANCE&table=RISKREGISTERENTRY">Add your first risk</a>
      (inherent &amp; residual level, treatment, owner, review — optionally CRQ/FAIR ALE), and the
      governance worklist appears here.</div>`;
    return;
  }

  const cards = [
    card("Residual posture", String(s.riskScore), "open risks · severity-weighted", postureColor(s.riskScore), "rr-card rr-score"),
    card("Open risks", String(s.open), `${s.closed} closed · ${s.risks} total`),
    card("High / critical", String(s.highCritical), "open · residual", s.highCritical ? "#f87171" : "#34d399"),
    card("Untreated", String(s.untreated), "high/critical · no plan", s.untreated ? "#f87171" : "#34d399"),
    card("Overdue reviews", String(s.overdueReview), "past review date", s.overdueReview ? "#fbbf24" : "#34d399"),
    card("Treated", s.treatedRate != null ? `${s.treatedRate}%` : "—", "open risks with a plan", s.treatedRate != null ? (s.treatedRate >= 70 ? "#34d399" : s.treatedRate >= 40 ? "#fbbf24" : "#f87171") : undefined),
    card("Annualized exposure", money(s.totalALE), `${s.quantified}/${s.risks} quantified (FAIR)`),
  ].join("");

  const byLevel = ["Critical", "High", "Medium", "Low", "Very Low"].filter((k) => s.byLevel[k]).map((k) => `<span class="bd">${lvl(k)} <b>${s.byLevel[k]}</b></span>`).join("");
  const byTreat = Object.entries(s.byTreatment).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");
  const byCat = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No untreated risks, overdue reviews or governance gaps — clean risk posture.</div>`;

  const table = `<table class="rr"><thead><tr>
      <th>Risk</th><th title="inherent → residual">Inherent → Residual</th><th>Treatment</th><th>Status</th><th class="num" title="Annualized Loss Expectancy (FAIR)">ALE</th><th title="next review">Review</th><th title="priority score">Score</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("rr-body").innerHTML = `<div class="rr-cards">${cards}</div>
    <div class="rr-section">Treatment worklist (${d.findings.length})</div>${findings}
    <div class="rr-section">Open risks by residual level</div><div class="breakdown">${byLevel || '<span class="muted">none</span>'}</div>
    ${byTreat ? `<div class="rr-section">By treatment strategy</div><div class="breakdown">${byTreat}</div>` : ""}
    ${byCat ? `<div class="rr-section">By category</div><div class="breakdown">${byCat}</div>` : ""}
    <div class="rr-section">Risks (${d.rows.length})</div>${table}
    <div class="legend">↳ <b>Score</b> is a risk's priority (higher = worse): residual severity + ALE + overdue review +
      untreated high/critical + no owner. <b>Treated</b> = open risks with a treatment plan or an explicit accept.
      <b>ALE</b> = Annualized Loss Expectancy from the risk's CRQ/FAIR fields; decompose a single loss with
      <a href="/fair-mam">FAIR-MAM</a>. Manage under <a href="/?db=XCOMPLIANCE&table=RISKREGISTERENTRY">Risk entries</a>.</div>`;
}

document.addEventListener("DOMContentLoaded", () => void load());
