/**
 * policy-management.ts — Policy & document management (/policy-management): lifecycle inventory +
 * governance worklist + controlled-document register, PLUS policy publication and per-user
 * acceptance tracking. From /api/policy-management. Publish/retire/acknowledge actions POST back.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("pp-toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2800); }

interface PolicyRow { id: number; name: string; reference: string; docType?: string; parentId?: number | null; category: string; framework: string; language: string; status: string; version: string; owner: string | null; effectiveDate: string | null; reviewDate: string | null; reviewInDays: number | null; published: boolean; retired: boolean; publishedDate: string | null; requiresAck: boolean; accepted: number; ackTarget: number; ackRate: number | null; versions: number; score: number; issues: string[]; }
interface DocumentRow { id: number; name: string; type: string; category: string; status: string; version: string; language: string; owner: string | null; reviewDate: string | null; validUntil: string | null; expired: boolean; issues: string[]; classification?: string; tlp?: string; }
interface Finding { id: number; name: string; kind: "policy" | "document"; severity: "High" | "Medium" | "Low"; reason: string; label: string; }
interface Pending { id: number; name: string; version: string; publishedDate: string | null; }
interface Inventory {
  rows: PolicyRow[]; documents: DocumentRow[]; findings: Finding[];
  summary: { policies: number; published: number; draft: number; inReview: number; approved: number; retired: number; overdueReview: number; dueSoon: number; noOwner: number; noVersion: number; notEffective: number; documents: number; expiredDocs: number; docsNoOwner: number; frameworks: number; languages: number; avgScore: number; requiringAck: number; ackTarget: number; requiredAcks: number; completedAcks: number; ackCoverage: number; pendingAcks: number; fullyAcknowledged: number; byStatus: Record<string, number>; byFramework: Record<string, number>; byCategory: Record<string, number>; byLanguage: Record<string, number>; };
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
  return a.join(" ");
}

function policyHtml(r: PolicyRow): string {
  const issues = r.issues.length
    ? r.issues.map((i) => `<span class="tag${/due in|effective|version|acceptance/.test(i) ? " tag-w" : ""}">${esc(i)}</span>`).join("")
    : (r.retired ? `<span class="muted">retired</span>` : `<span class="s-lo">✓ ok</span>`);
  const dt = r.docType && r.docType !== "Policy" ? `<span class="lang" title="document type" style="background:#3b2f63;color:#ddd6fe">${esc(r.docType)}</span>` : "";
  return `<tr>
    <td><div class="pname">${esc(r.name)}${dt}${r.language !== "—" ? `<span class="lang">${esc(r.language)}</span>` : ""}</div>
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
    <td><div class="pname">${esc(d.name)}${d.language !== "—" ? `<span class="lang">${esc(d.language)}</span>` : ""}</div>
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

function wire(): void {
  const on = (attr: string, fn: (id: number, el: HTMLElement) => void) =>
    Array.prototype.forEach.call(document.querySelectorAll(`[data-${attr}]`), (el: HTMLElement) => { el.onclick = () => fn(Number(el.getAttribute(`data-${attr}`)), el); });
  on("publish", (id, el) => publishDialog(id, el.getAttribute("data-ver") || ""));
  on("retire", (id) => { if (confirm("Retire (withdraw) this policy?")) post(`/api/policy-management/policy/${id}/retire`).then(() => { toast("Policy retired"); void load(); }).catch((e) => toast("⚠️ " + (e.message || e))); });
  on("cov", (id) => coverageDialog(id));
  on("hist", (id) => versionsDialog(id));
  on("ack", (id) => post(`/api/policy-management/policy/${id}/acknowledge`).then((j) => { toast(j.already ? "Already acknowledged" : "Acknowledged — thank you"); void load(); }).catch((e) => toast("⚠️ " + (e.message || e))));
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
    ${myPanel(d.me)}
    <div class="pp-section">Governance worklist (${d.findings.length})</div>${findings}
    ${byFw ? `<div class="pp-section">By framework</div><div class="breakdown">${byFw}</div>` : ""}
    <div class="pp-section">Policies (${d.rows.length})</div>${policyTable}
    ${docTable}
    <div class="legend">↳ <b>Publish</b> a draft/approved policy to put it in force; require <b>acknowledgement</b> so every active user must accept it,
      tracked per user &amp; version. <b>Acceptance</b> shows accepted/target; <b>Coverage</b> lists who has and hasn't acknowledged.
      <b>Score</b> is the governance gap (higher = worse): review overdue +30, not published +15, no owner +15, low acceptance +up to 15.</div>`;
  wire();
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); ensureModal(); void load(); });
