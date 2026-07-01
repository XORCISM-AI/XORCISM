/**
 * policy-management.ts — Policy & document management (/policy-management): lifecycle inventory +
 * governance worklist + controlled-document register, PLUS policy publication and per-user
 * acceptance tracking. From /api/policy-management. Publish/retire/acknowledge actions POST back.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("pp-toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2800); }

interface Legal { legalStatus: string | null; validationStatus: string | null; legallyCleared: boolean; legalOverdue: boolean; }
interface PolicyRow extends Legal { id: number; name: string; reference: string; docType?: string; parentId?: number | null; category: string; framework: string; language: string; status: string; version: string; owner: string | null; effectiveDate: string | null; reviewDate: string | null; reviewInDays: number | null; published: boolean; retired: boolean; publishedDate: string | null; requiresAck: boolean; accepted: number; ackTarget: number; ackRate: number | null; versions: number; score: number; issues: string[]; }
interface DocumentRow extends Legal { id: number; name: string; type: string; category: string; status: string; version: string; language: string; owner: string | null; reviewDate: string | null; validUntil: string | null; expired: boolean; issues: string[]; classification?: string; tlp?: string; }
interface Review { id: number; reviewType: string; status: string; versionReviewed: string; legalBasis: string; jurisdiction: string; reviewerName: string; comments: string; requestedDate: string; reviewedDate: string; validUntil: string; createdBy: string; }
interface Finding { id: number; name: string; kind: "policy" | "document"; severity: "High" | "Medium" | "Low"; reason: string; label: string; }
interface Pending { id: number; name: string; version: string; publishedDate: string | null; }
interface Inventory {
  rows: PolicyRow[]; documents: DocumentRow[]; findings: Finding[];
  summary: { policies: number; published: number; draft: number; inReview: number; approved: number; retired: number; overdueReview: number; dueSoon: number; noOwner: number; noVersion: number; notEffective: number; documents: number; expiredDocs: number; docsNoOwner: number; frameworks: number; languages: number; avgScore: number; requiringAck: number; ackTarget: number; requiredAcks: number; completedAcks: number; ackCoverage: number; pendingAcks: number; fullyAcknowledged: number; legalReviewed: number; legalCleared: number; legalPendingLegal: number; legalPendingValidation: number; legalRejected: number; legalOverdue: number; byStatus: Record<string, number>; byFramework: Record<string, number>; byCategory: Record<string, number>; byLanguage: Record<string, number>; };
  me: { userId: number; name: string; pending: Pending[] };
}

const stClass = (s: string): string => {
  const v = (s || "").toLowerCase();
  return /publish|publié|vigueur|active/.test(v) ? "st-published"
    : /approv/.test(v) ? "st-approved"
    : /review|revue|relecture/.test(v) ? "st-review"
    : /retir|archiv|obsolet|abrog/.test(v) ? "st-retired" : "st-draft";
};
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");
const pctColor = (n: number): string => (n >= 90 ? "#34d399" : n >= 50 ? "#fbbf24" : "#f87171");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="pp-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}
const BTN = "background:#1e2440;border:1px solid #2d3250;color:#cbd5e1;border-radius:6px;font-size:11px;padding:3px 9px;cursor:pointer";
function acceptanceBar(r: PolicyRow): string {
  if (!r.published || !r.requiresAck) return `<span class="muted">—</span>`;
  const pct = r.ackRate ?? 0;
  return `<div style="min-width:120px"><div style="display:flex;justify-content:space-between;font-size:11px"><span>${r.accepted}/${r.ackTarget}</span><span style="color:${pctColor(pct)}">${pct}%</span></div>
    <div style="height:6px;background:#0f1117;border-radius:4px;overflow:hidden;margin-top:2px"><div style="height:100%;width:${pct}%;background:${pctColor(pct)}"></div></div></div>`;
}
function actionsHtml(r: PolicyRow): string {
  const a: string[] = [];
  if (!r.retired && !r.published) a.push(`<button style="${BTN}" data-publish="${r.id}" data-ver="${esc(r.version === "—" ? "" : r.version)}">Publish</button>`);
  if (r.published) { a.push(`<button style="${BTN}" data-retire="${r.id}">Retire</button>`); if (r.requiresAck) a.push(`<button style="${BTN}" data-cov="${r.id}">Coverage</button>`); }
  a.push(`<button style="${BTN}" data-hist="${r.id}" title="Version history">History${r.versions ? ` (${r.versions})` : ""}</button>`);
  a.push(`<button style="${BTN}" data-validate="${r.id}" title="Validate this policy against live evidence (on-prem / cloud / hybrid)">🛡 Validate</button>`);
  a.push(`<button style="${BTN}" data-legal="policy:${r.id}" title="Legal review & validation trail">⚖ Legal</button>`);
  return a.join(" ");
}

// clickable chip summarising a policy/document's legal-review + validation state
function legalBadge(kind: "policy" | "document", r: Legal & { id: number }): string {
  const st = r.legallyCleared ? { bg: "#34d399", c: "#06240f", t: "⚖ cleared" }
    : (r.legalStatus === "rejected" || r.validationStatus === "rejected") ? { bg: "#f87171", c: "#2a0b0f", t: "⚖ rejected" }
    : (r.legalStatus || r.validationStatus) ? { bg: "#fbbf24", c: "#221803", t: "⚖ in review" }
    : { bg: "#2d3250", c: "#94a3b8", t: "⚖ review" };
  return `<button data-legal="${kind}:${r.id}"${r.legalOverdue ? ' title="re-review overdue"' : ""} style="border:none;border-radius:5px;font-size:9px;font-weight:700;padding:1px 7px;cursor:pointer;background:${st.bg};color:${st.c}">${st.t}${r.legalOverdue ? " !" : ""}</button>`;
}

function policyHtml(r: PolicyRow): string {
  const issues = r.issues.length
    ? r.issues.map((i) => `<span class="tag${/due in|effective|version|acceptance/.test(i) ? " tag-w" : ""}">${esc(i)}</span>`).join("")
    : (r.retired ? `<span class="muted">retired</span>` : `<span class="s-lo">✓ ok</span>`);
  const dt = r.docType && r.docType !== "Policy" ? `<span class="lang" title="document type" style="background:#3b2f63;color:#ddd6fe">${esc(r.docType)}</span>` : "";
  return `<tr>
    <td><div class="pname">${esc(r.name)}${dt}${r.language !== "—" ? `<span class="lang">${esc(r.language)}</span>` : ""} ${legalBadge("policy", r)}</div>
      <div class="muted" style="font-size:11px">${esc(r.framework)}${r.reference !== "—" ? ` · <span class="ref">${esc(r.reference)}</span>` : ""}${r.publishedDate ? ` · published ${esc(r.publishedDate)}` : ""}</div></td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span>${r.published && r.requiresAck ? ` <span class="tag" title="acknowledgement required">ack</span>` : ""}</td>
    <td>${esc(r.version)}</td>
    <td>${r.owner ? esc(r.owner) : `<span class="tag">none</span>`}</td>
    <td>${acceptanceBar(r)}</td>
    <td>${issues}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
    <td style="white-space:nowrap">${actionsHtml(r)}</td>
  </tr>`;
}

const CLASS_COLOR: Record<string, string> = { Public: "#34d399", Internal: "#60a5fa", Confidential: "#fbbf24", Restricted: "#f87171" };
const TLP_COLOR: Record<string, string> = { "TLP:CLEAR": "#94a3b8", "TLP:GREEN": "#34d399", "TLP:AMBER": "#fbbf24", "TLP:AMBER+STRICT": "#fb923c", "TLP:RED": "#f87171" };
function sensBadge(d: DocumentRow): string {
  const parts: string[] = [];
  if (d.classification) parts.push(`<span class="tag" style="background:${CLASS_COLOR[d.classification] || "#334155"};color:#0b1220">${esc(d.classification)}</span>`);
  if (d.tlp) parts.push(`<span class="tag" style="background:${TLP_COLOR[d.tlp] || "#334155"};color:#0b1220;font-size:9px">${esc(d.tlp)}</span>`);
  return parts.length ? parts.join(" ") : `<span class="muted">—</span>`;
}
function docHtml(d: DocumentRow): string {
  const issues = d.issues.length ? d.issues.map((i) => `<span class="tag${/version|unclassified/.test(i) ? " tag-w" : ""}">${esc(i)}</span>`).join("") : `<span class="s-lo">✓ ok</span>`;
  return `<tr>
    <td><div class="pname">${esc(d.name)}${d.language !== "—" ? `<span class="lang">${esc(d.language)}</span>` : ""} ${legalBadge("document", d)}</div>
      <div class="muted" style="font-size:11px">${esc(d.type)}${d.category !== "—" ? ` · ${esc(d.category)}` : ""}</div></td>
    <td>${d.status !== "—" ? `<span class="st ${stClass(d.status)}">${esc(d.status)}</span>` : `<span class="muted">—</span>`}</td>
    <td>${sensBadge(d)}</td>
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

function myPanel(me: Inventory["me"]): string {
  if (!me) return "";
  if (!me.pending.length) {
    return `<div class="pp-section">My acknowledgements</div><div class="muted" style="padding:8px 0">✓ You're up to date — no published policies awaiting your acknowledgement.</div>`;
  }
  const rows = me.pending.map((p) => `<li style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #1e2133">
      <span class="dot" style="background:#fb923c"></span>
      <span><b style="color:#e2e8f0">${esc(p.name)}</b> <span class="muted" style="font-size:11px">v${esc(p.version)}${p.publishedDate ? ` · published ${esc(p.publishedDate)}` : ""}</span></span>
      <span style="flex:1"></span>
      <button style="${BTN};border-color:#fb923c;color:#fdba74" data-ack="${p.id}">I acknowledge</button></li>`).join("");
  return `<div class="pp-section">My acknowledgements — ${me.pending.length} pending</div>
    <div class="muted" style="font-size:12px;margin-bottom:4px">Published policies that require <b>your</b> acknowledgement:</div>
    <ul style="list-style:none;margin:0;padding:0">${rows}</ul>`;
}

// ── lightweight modal ────────────────────────────────────────────────────────
function ensureModal(): void {
  if (document.getElementById("pp-modal")) return;
  const m = document.createElement("div"); m.id = "pp-modal";
  m.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;z-index:50";
  m.innerHTML = `<div id="pp-dlg" style="background:#0f1117;border:1px solid #2d3250;border-radius:12px;padding:18px;max-width:560px;width:92%;max-height:86vh;overflow:auto;color:#cbd5e1"></div>`;
  m.addEventListener("click", (e) => { if (e.target === m) closeModal(); });
  document.body.appendChild(m);
  const t = document.createElement("div"); t.id = "pp-toast";
  t.style.cssText = "position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1e2440;border:1px solid #2d3250;color:#e2e8f0;padding:10px 16px;border-radius:8px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:60";
  document.body.appendChild(t);
  const st = document.createElement("style");
  st.textContent = "#pp-toast.show{opacity:1}";
  document.head.appendChild(st);
}
function openModal(html: string): void { ensureModal(); $("pp-dlg").innerHTML = html; $("pp-modal").style.display = "flex"; const c = document.getElementById("pp-close"); if (c) c.onclick = closeModal; }
function closeModal(): void { const m = document.getElementById("pp-modal"); if (m) m.style.display = "none"; }

function post(url: string, body?: unknown): Promise<any> {
  return fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: body == null ? "{}" : JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }));
}

function publishDialog(id: number, currentVer: string): void {
  const today = new Date().toISOString().slice(0, 10);
  const INP = "width:100%;box-sizing:border-box;background:#13162a;border:1px solid #2d3250;color:#e2e8f0;border-radius:6px;padding:7px 9px;font-size:13px;margin-top:3px";
  openModal(`<div style="display:flex;align-items:center;margin-bottom:8px"><b style="font-size:15px;color:#e7ebf3">Publish policy</b><span style="flex:1"></span><button style="${BTN}" id="pp-close">Close</button></div>
    <label style="font-size:12px;color:#94a3b8">Version<input id="pub-ver" style="${INP}" value="${esc(currentVer || "1.0")}"></label>
    <label style="font-size:12px;color:#94a3b8;display:block;margin-top:8px">Effective date<input id="pub-eff" type="date" style="${INP}" value="${today}"></label>
    <label style="display:flex;align-items:center;gap:6px;margin-top:10px;font-size:12px;color:#cbd5e1"><input type="checkbox" id="pub-ack" checked> Require all users to acknowledge this policy</label>
    <div class="muted" style="font-size:11px;margin-top:6px">Publishing sets the status to <b>Published</b>; if acknowledgement is required, every active user must accept it (existing acceptances of an earlier version are reset on a version change).</div>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button style="${BTN};border-color:#34d399;color:#86efac" id="pub-go">Publish</button></div>`);
  ($("pub-go") as HTMLButtonElement).onclick = () => {
    post(`/api/policy-management/policy/${id}/publish`, { version: ($("pub-ver") as HTMLInputElement).value.trim() || undefined, effectiveDate: ($("pub-eff") as HTMLInputElement).value || undefined, requiresAck: ($("pub-ack") as HTMLInputElement).checked })
      .then(() => { toast("Policy published"); closeModal(); void load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function coverageDialog(id: number): void {
  fetch(`/api/policy-management/policy/${id}/acceptance`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d: { name: string; version: string; target: number; accepted: number; acknowledgements: { name: string; date: string }[]; pending: { name: string; email: string }[] }) => {
      const pct = d.target ? Math.round((d.accepted / d.target) * 100) : 0;
      const acked = d.acknowledgements.length ? d.acknowledgements.map((a) => `<li style="padding:3px 0;border-bottom:1px solid #1e2133">✓ ${esc(a.name)} <span class="muted" style="font-size:11px">${esc(a.date)}</span></li>`).join("") : `<li class="muted">none yet</li>`;
      const pend = d.pending.length ? d.pending.map((p) => `<li style="padding:3px 0;border-bottom:1px solid #1e2133">○ ${esc(p.name)} <span class="muted" style="font-size:11px">${esc(p.email)}</span></li>`).join("") : `<li class="muted">none — fully acknowledged 🎉</li>`;
      openModal(`<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${esc(d.name)}</b> <span class="muted">v${esc(d.version)}</span><span style="flex:1"></span><button style="${BTN}" id="pp-close">Close</button></div>
        <div style="font-size:13px;margin-bottom:8px">Acceptance: <b style="color:${pctColor(pct)}">${d.accepted}/${d.target} (${pct}%)</b></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
          <div><div style="font-size:12px;color:#86efac;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">Acknowledged (${d.acknowledgements.length})</div><ul style="list-style:none;margin:0;padding:0;font-size:13px;max-height:50vh;overflow:auto">${acked}</ul></div>
          <div><div style="font-size:12px;color:#fdba74;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">Pending (${d.pending.length})</div><ul style="list-style:none;margin:0;padding:0;font-size:13px;max-height:50vh;overflow:auto">${pend}</ul></div>
        </div>`);
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

// ── Legal review & validation trail ──────────────────────────────────────────
const REVIEW_TYPES = ["legal", "validation"];
const REVIEW_LABEL: Record<string, string> = { legal: "Legal review", validation: "Validation / sign-off" };
const LR_STATUSES = ["requested", "in-review", "approved", "approved-with-changes", "rejected"];
const LR_COLOR: Record<string, string> = { requested: "#94a3b8", "in-review": "#fbbf24", approved: "#34d399", "approved-with-changes": "#4ade80", rejected: "#f87171" };
const LINP = "width:100%;box-sizing:border-box;background:#13162a;border:1px solid #2d3250;color:#e2e8f0;border-radius:6px;padding:6px 8px;font-size:12px;margin-top:3px";

function legalDialog(kind: string, id: number): void {
  fetch(`/api/policy-management/legal-reviews?type=${kind}&id=${id}`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d: { items: Review[]; summary: { total: number; legalStatus: string | null; validationStatus: string | null; legallyCleared: boolean; reviewOverdue: boolean } }) => {
      const chip = (label: string, st: string | null) => `<span style="font-size:11px">${label}: <b style="color:${st ? (LR_COLOR[st] || "#cbd5e1") : "#64748b"}">${esc(st || "—")}</b></span>`;
      const cleared = d.summary.legallyCleared
        ? `<span style="background:#34d399;color:#06240f;border-radius:5px;font-size:10px;font-weight:700;padding:2px 8px">⚖ LEGALLY CLEARED</span>`
        : `<span style="background:#2d3250;color:#cbd5e1;border-radius:5px;font-size:10px;padding:2px 8px">not yet cleared</span>`;
      const items = d.items.length ? d.items.map((rv) => {
        const sopts = LR_STATUSES.map((sx) => `<option value="${sx}"${sx === rv.status ? " selected" : ""}>${sx}</option>`).join("");
        return `<div style="border:1px solid #232842;border-radius:8px;padding:9px 11px;margin-bottom:7px;background:#0f1322">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-weight:700;font-size:12px;color:#e2e8f0">${esc(REVIEW_LABEL[rv.reviewType] || rv.reviewType)}</span>
            <select data-lrupd="${rv.id}" style="background:#13162a;border:1px solid #2d3250;color:${LR_COLOR[rv.status] || "#cbd5e1"};border-radius:5px;font-size:11px;padding:2px 6px">${sopts}</select>
            <span style="flex:1"></span>
            <button style="${BTN};border-color:#5a1f2e;color:#fca5a5" data-lrdel="${rv.id}">Delete</button>
          </div>
          ${rv.legalBasis ? `<div style="font-size:11px;margin-top:5px"><span class="muted">Legal basis:</span> ${esc(rv.legalBasis)}${rv.jurisdiction ? ` · <span class="muted">Jurisdiction:</span> ${esc(rv.jurisdiction)}` : ""}</div>` : ""}
          ${rv.comments ? `<div style="font-size:11px;margin-top:4px;color:#cbd5e1">${esc(rv.comments)}</div>` : ""}
          <div class="muted" style="font-size:10px;margin-top:5px">${rv.reviewerName ? esc(rv.reviewerName) + " · " : ""}${rv.versionReviewed ? "v" + esc(rv.versionReviewed) + " · " : ""}${rv.reviewedDate ? "reviewed " + esc(rv.reviewedDate) : (rv.requestedDate ? "requested " + esc(rv.requestedDate) : "")}${rv.validUntil ? ` · re-review by ${esc(rv.validUntil)}` : ""}</div>
        </div>`;
      }).join("") : `<div class="muted" style="padding:8px 0">No legal review or validation recorded yet.</div>`;
      const topts = REVIEW_TYPES.map((rt) => `<option value="${rt}">${esc(REVIEW_LABEL[rt])}</option>`).join("");
      const sopts = LR_STATUSES.map((sx) => `<option value="${sx}"${sx === "approved" ? " selected" : ""}>${sx}</option>`).join("");
      openModal(`<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">⚖ Legal review &amp; validation</b><span style="flex:1"></span><button style="${BTN}" id="pp-close">Close</button></div>
        <div style="display:flex;gap:14px;align-items:center;margin-bottom:8px">${chip("Legal", d.summary.legalStatus)}${chip("Validation", d.summary.validationStatus)}${cleared}</div>
        <div style="max-height:40vh;overflow:auto;margin-bottom:10px">${items}</div>
        <div style="border-top:1px solid #232842;padding-top:10px">
          <div style="font-weight:700;font-size:12px;margin-bottom:6px">+ Record a review</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
            <label style="font-size:11px;color:#94a3b8">Type<select id="lr-type" style="${LINP}">${topts}</select></label>
            <label style="font-size:11px;color:#94a3b8">Outcome<select id="lr-status" style="${LINP}">${sopts}</select></label>
            <label style="font-size:11px;color:#94a3b8">Reviewer<input id="lr-reviewer" style="${LINP}" placeholder="legal counsel / authority"></label>
            <label style="font-size:11px;color:#94a3b8">Version reviewed<input id="lr-version" style="${LINP}" placeholder="e.g. 1.2"></label>
            <label style="font-size:11px;color:#94a3b8">Jurisdiction<input id="lr-jur" style="${LINP}" placeholder="e.g. EU / FR"></label>
            <label style="font-size:11px;color:#94a3b8">Re-review by<input id="lr-valid" type="date" style="${LINP}"></label>
            <label style="font-size:11px;color:#94a3b8;grid-column:1/3">Legal basis / obligations checked<input id="lr-basis" style="${LINP}" placeholder="e.g. GDPR, DUAA, NIS2, employment law"></label>
            <label style="font-size:11px;color:#94a3b8;grid-column:1/3">Comments<textarea id="lr-comments" style="${LINP};min-height:52px;resize:vertical"></textarea></label>
          </div>
          <div style="display:flex;justify-content:flex-end;margin-top:8px"><button style="${BTN};border-color:#34d399;color:#86efac" id="lr-add">Record review</button></div>
        </div>`);
      const v = (idv: string) => (document.getElementById(idv) as HTMLInputElement)?.value || "";
      (document.getElementById("lr-add") as HTMLButtonElement).onclick = () => {
        post("/api/policy-management/legal-reviews", { type: kind, id, reviewType: v("lr-type"), status: v("lr-status"), reviewerName: v("lr-reviewer"), versionReviewed: v("lr-version"), jurisdiction: v("lr-jur"), validUntil: v("lr-valid"), legalBasis: v("lr-basis"), comments: v("lr-comments") })
          .then(() => { toast("Review recorded"); legalDialog(kind, id); void load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
      };
      document.querySelectorAll<HTMLSelectElement>("[data-lrupd]").forEach((sel) => sel.onchange = () => {
        post(`/api/policy-management/legal-reviews/${sel.getAttribute("data-lrupd")}`, { status: sel.value })
          .then(() => { toast("Status updated"); legalDialog(kind, id); void load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
      });
      document.querySelectorAll<HTMLElement>("[data-lrdel]").forEach((b) => b.onclick = () => {
        if (!confirm("Delete this review record?")) return;
        fetch(`/api/policy-management/legal-reviews/${b.getAttribute("data-lrdel")}`, { method: "DELETE" }).then((r) => r.json()).then(() => { toast("Deleted"); legalDialog(kind, id); void load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
      });
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function wire(): void {
  const on = (attr: string, fn: (id: number, el: HTMLElement) => void) =>
    Array.prototype.forEach.call(document.querySelectorAll(`[data-${attr}]`), (el: HTMLElement) => { el.onclick = () => fn(Number(el.getAttribute(`data-${attr}`)), el); });
  on("publish", (id, el) => publishDialog(id, el.getAttribute("data-ver") || ""));
  on("retire", (id) => { if (confirm("Retire (withdraw) this policy?")) post(`/api/policy-management/policy/${id}/retire`).then(() => { toast("Policy retired"); void load(); }).catch((e) => toast("⚠️ " + (e.message || e))); });
  on("cov", (id) => coverageDialog(id));
  on("hist", (id) => versionsDialog(id));
  on("ack", (id) => post(`/api/policy-management/policy/${id}/acknowledge`).then((j) => { toast(j.already ? "Already acknowledged" : "Acknowledged — thank you"); void load(); }).catch((e) => toast("⚠️ " + (e.message || e))));
  on("validate", (id) => validateDialog(id));
  document.querySelectorAll<HTMLElement>("[data-legal]").forEach((el) => el.onclick = () => {
    const [kind, id] = (el.getAttribute("data-legal") || "").split(":");
    if (kind && id) legalDialog(kind, Number(id));
  });
}

// ── Policy validation (AI requirement extraction + cross-environment evidence checks) ──
interface VReq { requirementId: number; attribute: string; description: string; collectorKey: string; controlRef: string; scope: string; approved: boolean; status: string; pass: number; fail: number; total: number }
interface VReport { policyName: string; compliancePct: number; measurable: number; passed: number; evaluatedAt: string | null;
  byEnv: { env: string; pass: number; fail: number; total: number }[];
  requirements: VReq[]; violations: { requirement: string; env: string; target: string; detail: string; evidenceRef: string }[]; gaps: { requirement: string; reason: string }[];
  trend?: { at: string; pct: number }[]; drift?: { requirementId: number; name: string; from: string; to: string; dir: string }[]; }
function trendSpark(trend?: { at: string; pct: number }[]): string {
  if (!trend || trend.length < 2) return "";
  const W = 240, H = 32, n = trend.length;
  const pts = trend.map((p, i) => `${(i / (n - 1)) * W},${(H - (p.pct / 100) * H).toFixed(1)}`).join(" ");
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:160px;height:32px"><polyline points="${pts}" fill="none" stroke="${pctColor(trend[n - 1].pct)}" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`;
}
const resColor = (s: string): string => s === "pass" ? "#34d399" : s === "fail" ? "#f87171" : s === "partial" ? "#fbbf24" : "#64748b";

function validateDialog(id: number): void {
  openModal(`<div class="muted" style="padding:10px">Loading…</div>`);
  fetch(`/api/policy-validation?policy=${id}`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d: { report: VReport }) => renderValidate(id, d.report))
    .catch((e) => openModal(`<div class="muted" style="padding:10px">⚠️ ${esc(e.message || e)}</div><div style="text-align:right"><button style="${BTN}" id="pp-close">Close</button></div>`));
}

function renderValidate(id: number, rep: VReport): void {
  const reqRows = rep.requirements.length ? rep.requirements.map((q) => `<tr style="border-bottom:1px solid #1e2133">
      <td style="padding:5px 8px"><label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" data-appr="${q.requirementId}" ${q.approved ? "checked" : ""}> <span style="color:#e2e8f0">${esc(q.description || q.attribute)}</span></label>
        <div class="muted" style="font-size:10px;margin-left:22px">${esc(q.collectorKey)}${q.controlRef ? " · " + esc(q.controlRef) : ""} · scope ${esc(q.scope)}</div></td>
      <td style="padding:5px 8px;text-align:center"><span style="color:${resColor(q.status)};font-weight:600">${esc(q.approved ? q.status : "(unapproved)")}</span>${q.total ? `<div class="muted" style="font-size:10px">${q.pass}✓ / ${q.fail}✗ of ${q.total}</div>` : ""}</td>
      <td style="padding:5px 8px;text-align:right"><button style="${BTN}" data-delreq="${q.requirementId}" title="Remove">✕</button></td></tr>`).join("")
    : `<tr><td colspan="3" class="muted" style="padding:8px">No requirements yet — click <b>Extract (AI)</b> to parse this policy into checkable rules.</td></tr>`;
  const byEnv = rep.byEnv.length ? rep.byEnv.map((e) => `<span class="bd">${esc(e.env)} <b style="color:#34d399">${e.pass}✓</b>${e.fail ? ` <b style="color:#f87171">${e.fail}✗</b>` : ""}</span>`).join("") : "";
  const regressed = (rep.drift || []).filter((d) => d.dir === "down");
  const driftHtml = (rep.drift && rep.drift.length) ? `<div style="margin:6px 0 10px;padding:8px 10px;border:1px solid ${regressed.length ? "#7f1d1d" : "#14532d"};border-radius:8px;background:#13162a;font-size:12px">
      <b style="color:${regressed.length ? "#f87171" : "#86efac"}">${regressed.length ? "⚠ Regressed since last run" : "✓ Improved since last run"}</b> ${rep.drift.map((d) => `<span class="bd" style="background:${d.dir === "down" ? "#3b1418" : "#0c2a20"};color:${d.dir === "down" ? "#fecaca" : "#86efac"}">${d.dir === "down" ? "▼" : "▲"} ${esc(d.name)} (${esc(d.from)}→${esc(d.to)})</span>`).join(" ")}</div>` : "";
  const viol = rep.violations.length ? `<div class="pp-section" style="color:#f87171">Violations (${rep.violations.length})</div>` + rep.violations.slice(0, 40).map((v) => `<div style="font-size:12px;padding:3px 0;border-bottom:1px solid #1e2133"><span class="bd" style="background:#3b1418;color:#fecaca">${esc(v.env)}</span> <b>${esc(v.target)}</b> — ${esc(v.detail)} <span class="muted" style="font-size:10px">[${esc(v.evidenceRef)}]</span></div>`).join("") : "";
  const gaps = rep.gaps.length ? `<div class="pp-section" style="color:#fbbf24">Gaps / unverifiable (${rep.gaps.length})</div>` + rep.gaps.map((g) => `<div style="font-size:12px;padding:2px 0" class="muted">○ ${esc(g.requirement)} — ${esc(g.reason)}</div>`).join("") : "";
  openModal(`<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><b style="font-size:15px;color:#e7ebf3">🛡 Policy validation</b> <span class="muted">${esc(rep.policyName)}</span><span style="flex:1"></span>
      <button style="${BTN};border-color:#7c3aed;color:#c4b5fd" id="pv-extract">✨ Extract (AI)</button>
      <button style="${BTN};border-color:#34d399;color:#86efac" id="pv-run">▶ Validate</button>
      <button style="${BTN}" id="pp-close">Close</button></div>
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:8px">
      <span style="font-size:28px;font-weight:700;color:${pctColor(rep.compliancePct)}">${rep.compliancePct}%</span>
      <div class="muted" style="font-size:12px;flex:1">${rep.passed}/${rep.measurable} measurable requirements pass${rep.evaluatedAt ? ` · ${esc(rep.evaluatedAt.slice(0, 19).replace("T", " "))}` : ""}<div>${byEnv}</div></div>
      ${trendSpark(rep.trend)}</div>
    ${driftHtml}
    <table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr style="color:#94a3b8;font-size:11px;text-transform:uppercase">
      <th style="text-align:left;padding:4px 8px">Requirement (✓ = approved to enforce)</th><th style="padding:4px 8px">Result</th><th></th></tr></thead><tbody>${reqRows}</tbody></table>
    ${viol}${gaps}
    <div class="muted" style="font-size:11px;margin-top:10px">AI structures the policy into rules — <b>you approve</b> which ones count; deterministic checks against your cloud CIS findings, asset/identity MFA and agentless host baseline decide pass/fail (evidence-cited). Uncollected evidence → <i>unverifiable</i>, never a false pass.</div>`);
  document.querySelectorAll<HTMLInputElement>("[data-appr]").forEach((c) => c.onchange = () => {
    post(`/api/policy-validation/requirement/${c.getAttribute("data-appr")}`, { approved: c.checked }).catch((e) => toast("⚠️ " + (e.message || e)));
  });
  document.querySelectorAll<HTMLElement>("[data-delreq]").forEach((b) => b.onclick = () => {
    fetch(`/api/policy-validation/requirement/${b.getAttribute("data-delreq")}`, { method: "DELETE" }).then(() => validateDialog(id)).catch((e) => toast("⚠️ " + (e.message || e)));
  });
  (document.getElementById("pv-extract") as HTMLButtonElement).onclick = () => {
    toast("Extracting requirements…");
    post(`/api/policy-validation/extract`, { policyId: id }).then((j) => { toast(j.ai ? `Extracted (AI: ${j.model})` : "Extracted (offline heuristics)"); validateDialog(id); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
  (document.getElementById("pv-run") as HTMLButtonElement).onclick = () => {
    toast("Validating against evidence…");
    post(`/api/policy-validation/validate`, { policyId: id }).then((rep2: VReport) => renderValidate(id, rep2)).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

interface PolicyVersion { versionId: number; version: string; status: string; effectiveDate: string | null; publishedDate: string | null; changeNote: string; changedBy: string | null; at: string; hasContent: boolean; }
function versionsDialog(id: number): void {
  fetch(`/api/policy-management/policy/${id}/versions`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d: { versions: PolicyVersion[] }) => {
      const rows = d.versions.length
        ? d.versions.map((v) => `<tr style="border-bottom:1px solid #1e2133">
            <td style="padding:5px 8px;font-weight:600;color:#e2e8f0">v${esc(v.version)}</td>
            <td style="padding:5px 8px"><span class="st ${stClass(v.status)}">${esc(v.status)}</span></td>
            <td style="padding:5px 8px" class="muted">${esc(v.at)}${v.changedBy ? ` · ${esc(v.changedBy)}` : ""}</td>
            <td style="padding:5px 8px" class="muted">${esc(v.changeNote || "")}</td>
            <td style="padding:5px 8px;white-space:nowrap;text-align:right">
              ${v.hasContent ? `<button style="${BTN}" data-vview="${v.versionId}">View</button> ` : ""}
              <button style="${BTN}" data-vrestore="${v.versionId}" data-pid="${id}" title="Restore this version as a new draft">Restore</button></td></tr>`).join("")
        : `<tr><td colspan="5" class="muted" style="padding:8px">No versions yet — a snapshot is saved each time the policy is published, or use “Snapshot now”.</td></tr>`;
      openModal(`<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><b style="font-size:15px;color:#e7ebf3">Version history</b><span style="flex:1"></span>
          <button style="${BTN}" data-snap="${id}">Snapshot now</button><button style="${BTN}" id="dlg-close">Close</button></div>
        <table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr style="color:#94a3b8;font-size:11px;text-transform:uppercase">
          <th style="text-align:left;padding:4px 8px">Version</th><th style="text-align:left;padding:4px 8px">Status</th><th style="text-align:left;padding:4px 8px">When</th><th style="text-align:left;padding:4px 8px">Change</th><th></th>
        </tr></thead><tbody>${rows}</tbody></table>`);
      const snap = document.querySelector("[data-snap]") as HTMLElement | null;
      if (snap) snap.onclick = () => { const note = prompt("Change note for this snapshot (optional):", "") ?? ""; post(`/api/policy-management/policy/${id}/snapshot`, { changeNote: note }).then(() => { toast("Snapshot saved"); versionsDialog(id); void load(); }).catch((e) => toast("⚠️ " + (e.message || e))); };
      Array.prototype.forEach.call(document.querySelectorAll("[data-vview]"), (b: HTMLElement) => { b.onclick = () => versionView(Number(b.getAttribute("data-vview"))); });
      Array.prototype.forEach.call(document.querySelectorAll("[data-vrestore]"), (b: HTMLElement) => {
        b.onclick = () => { if (!confirm("Restore this version's content onto the policy as a new draft? (the current state is snapshotted first)")) return;
          post(`/api/policy-management/policy/${id}/restore`, { versionId: Number(b.getAttribute("data-vrestore")) }).then(() => { toast("Restored as draft"); closeModal(); void load(); }).catch((e) => toast("⚠️ " + (e.message || e))); };
      });
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function versionView(versionId: number): void {
  fetch(`/api/policy-management/version/${versionId}`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((v: { policyId: number; name: string; version: string; status: string; content: string; effectiveDate: string | null; changeNote: string }) => {
      openModal(`<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${esc(v.name)}</b> <span class="muted">v${esc(v.version)} · ${esc(v.status)}${v.effectiveDate ? " · effective " + esc(v.effectiveDate) : ""}</span><span style="flex:1"></span><button style="${BTN}" id="v-back">‹ History</button><button style="${BTN}" id="dlg-close">Close</button></div>
        ${v.changeNote ? `<div class="muted" style="font-size:12px;margin-bottom:6px">${esc(v.changeNote)}</div>` : ""}
        <div style="background:#13162a;border:1px solid #2d3250;border-radius:8px;padding:12px;max-height:60vh;overflow:auto;font-size:13px;line-height:1.6;color:#cbd5e1">${v.content || "<span class='muted'>(no content)</span>"}</div>`);
      const back = document.getElementById("v-back"); if (back) back.onclick = () => versionsDialog(v.policyId);
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

// ── POLICY ↔ ASSET coverage panel ─────────────────────────────────────────────
interface Coverage {
  summary: { policies: number; assets: number; links: number; coveredAssets: number; coveragePct: number; uncoveredAssets: number; uncoveredCritical: number; policiesNoAsset: number };
  perPolicy: { policyId: number; policyName: string; status: string; assetCount: number }[];
  uncovered: { assetId: number; assetName: string; criticality: string | null; businessValue: number | null }[];
  policiesNoAsset: { policyId: number; policyName: string; status: string }[];
}
async function loadCoverage(): Promise<void> {
  const host = document.getElementById("pp-coverage"); if (!host) return;
  let c: Coverage;
  try { const r = await fetch("/api/policy-management/coverage"); if (!r.ok) throw new Error(`HTTP ${r.status}`); c = await r.json(); }
  catch { host.innerHTML = ""; return; }
  const s = c.summary;
  if (!s.assets && !s.policies) { host.innerHTML = ""; return; }
  const cards = [
    card("Asset coverage", `${s.coveragePct}%`, `${s.coveredAssets}/${s.assets} assets governed`, pctColor(s.coveragePct)),
    card("Uncovered assets", String(s.uncoveredAssets), `${s.uncoveredCritical} critical/high`, s.uncoveredCritical ? "#f87171" : s.uncoveredAssets ? "#fbbf24" : "#34d399"),
    card("Policy↔asset links", String(s.links), `across ${s.policies} policies`, "#60a5fa"),
    card("Policies w/o assets", String(s.policiesNoAsset), "published, govern nothing", s.policiesNoAsset ? "#fbbf24" : "#34d399"),
  ].join("");
  const critTag = (cr: string | null): string => cr && /crit|high/i.test(cr) ? `<span class="tag tag-w">${esc(cr)}</span>` : (cr ? `<span class="muted">${esc(cr)}</span>` : `<span class="muted">—</span>`);
  const uncRows = c.uncovered.length
    ? c.uncovered.slice(0, 40).map((a) => `<tr>
        <td><a href="/?db=XORCISM&amp;table=ASSET&amp;editCol=AssetName&amp;editVal=${encodeURIComponent(a.assetName)}">${esc(a.assetName)}</a></td>
        <td>${critTag(a.criticality)}</td>
        <td>${a.businessValue != null ? esc(a.businessValue) : '<span class="muted">—</span>'}</td>
        <td><span class="tag tag-w">no policy</span></td></tr>`).join("")
    : `<tr><td colspan="4" class="muted" style="padding:8px">✓ Every asset is governed by at least one policy.</td></tr>`;
  const noAsset = c.policiesNoAsset.length
    ? `<div class="pp-section">Published policies governing no asset (${c.policiesNoAsset.length})</div>
       <div class="breakdown">${c.policiesNoAsset.slice(0, 40).map((p) => `<a class="bd" href="/?db=XORCISM&amp;table=POLICY&amp;editCol=PolicyName&amp;editVal=${encodeURIComponent(p.policyName)}" title="Open the policy to add the assets it covers">${esc(p.policyName)}</a>`).join("")}</div>`
    : "";
  host.innerHTML = `<div class="pp-section">Policy ↔ Asset coverage</div>
    <div class="pp-cards">${cards}</div>
    <div class="muted" style="font-size:12px;margin:4px 0 6px">Assets with <b>no governing policy</b> (critical / high-value first) — open the asset, or open a policy to pick the assets it covers (POLICYFORASSET):</div>
    <table class="pp"><thead><tr><th>Asset (uncovered)</th><th>Criticality</th><th>Business value</th><th>Coverage</th></tr></thead><tbody>${uncRows}</tbody></table>
    ${noAsset}`;
}

async function load(): Promise<void> {
  ensureModal();
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
    card("Governed docs", String(s.policies), `${(s.byType && s.byType["Policy"]) || (s.policies - (s.standards || 0) - (s.procedures || 0) - (s.guidelines || 0))} policy · ${s.standards || 0} std · ${s.procedures || 0} proc · ${s.guidelines || 0} guide`),
    card("Published", String(s.published), s.policies ? `${Math.round((s.published / s.policies) * 100)}% of policies` : "—", s.published ? "#34d399" : undefined),
    card("Requiring ack", String(s.requiringAck), `${s.fullyAcknowledged} fully accepted`, s.requiringAck ? "#60a5fa" : undefined),
    card("Acceptance", s.requiringAck ? `${s.ackCoverage}%` : "—", `${s.completedAcks}/${s.requiredAcks} user acks`, s.requiringAck ? pctColor(s.ackCoverage) : undefined),
    card("Pending acks", String(s.pendingAcks), `${s.ackTarget} active user(s)`, s.pendingAcks ? "#fb923c" : "#34d399"),
    card("Legally cleared", String(s.legalCleared ?? 0), `${s.legalPendingLegal ?? 0} legal · ${s.legalPendingValidation ?? 0} validation pending${s.legalRejected ? ` · ${s.legalRejected} rejected` : ""}`, (s.legalRejected ? "#f87171" : (s.legalPendingLegal || s.legalPendingValidation) ? "#fbbf24" : s.legalCleared ? "#34d399" : undefined)),
    card("Overdue review", String(s.overdueReview), "past review date", s.overdueReview ? "#f87171" : "#34d399"),
    card("No owner", String(s.noOwner), "active · unaccountable", s.noOwner ? "#fbbf24" : "#34d399"),
    card("Avg score", String(s.avgScore), "governance gap (↓ better)", s.avgScore >= 30 ? "#f87171" : s.avgScore >= 10 ? "#fbbf24" : "#34d399"),
  ].join("");

  const chip = (k: string, n: number): string => `<span class="bd">${esc(k)} <b>${n}</b></span>`;
  const byFw = Object.entries(s.byFramework).sort((a, b) => b[1] - a[1]).map(([k, n]) => chip(k, n)).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No overdue reviews, unpublished/unowned policies, pending acknowledgements or expired documents — clean posture.</div>`;

  const policyTable = `<table class="pp"><thead><tr>
      <th>Policy</th><th>Status</th><th>Ver.</th><th>Owner</th><th>Acceptance</th><th>Gaps</th><th title="Governance score">Score</th><th>Actions</th>
    </tr></thead><tbody>${d.rows.map(policyHtml).join("")}</tbody></table>`;

  const docTable = d.documents.length ? `<div class="pp-section">Document register (${d.documents.length})</div>
    <table class="pp"><thead><tr>
      <th>Document</th><th>Status</th><th>Sensitivity</th><th>Ver.</th><th>Owner</th><th>Valid until</th><th>Gaps</th>
    </tr></thead><tbody>${d.documents.map(docHtml).join("")}</tbody></table>` : "";

  $("pp-body").innerHTML = `<div class="pp-cards">${cards}</div>
    <div id="pp-coverage"></div>
    ${myPanel(d.me)}
    <div class="pp-section">Governance worklist (${d.findings.length})</div>${findings}
    ${byFw ? `<div class="pp-section">By framework</div><div class="breakdown">${byFw}</div>` : ""}
    <div class="pp-section">Policies (${d.rows.length})</div>${policyTable}
    ${docTable}
    <div class="legend">↳ <b>Publish</b> a draft/approved policy to put it in force; require <b>acknowledgement</b> so every active user must accept it,
      tracked per user &amp; version. <b>Acceptance</b> shows accepted/target; <b>Coverage</b> lists who has and hasn't acknowledged.
      <b>Score</b> is the governance gap (higher = worse): review overdue +30, not published +15, no owner +15, low acceptance +up to 15.</div>`;
  wire();
  void loadCoverage();
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); ensureModal(); void load(); });
