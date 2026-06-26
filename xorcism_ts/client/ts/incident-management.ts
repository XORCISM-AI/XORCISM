/**
 * incident-management.ts — Incident Management inventory + governance worklist
 * (/incident-management). Renders the incident queue with posture + derived findings,
 * from /api/incident-management.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Row {
  id: number; name: string; severity: string; status: string; open: boolean; assignee: string | null;
  classification: string; determination: string; reported: string | null; durationHours: number | null;
  ageDays: number | null; assets: number; breached: boolean; compromise: boolean; evidence: number; flags: string[]; score: number;
}
interface Evidence { id: number; incidentId: number; fileName: string; contentType: string; sha256: string; size: number; description: string; uploadedBy: string; createdDate: string; downloadUrl: string; }
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
  const badges = [r.breached ? `<span class="badge b-breach">${t("im.breach")}</span>` : "", r.compromise ? `<span class="badge b-comp">${t("im.compromise")}</span>` : ""].filter(Boolean).join(" ");
  const age = r.open && r.ageDays != null ? fmt("im.daysOpen", { n: r.ageDays }) : (r.durationHours != null ? fmt("im.hours", { n: r.durationHours }) : "—");
  return `<tr>
    <td><div class="iname">${esc(r.name)}</div>${badges ? `<div style="margin-top:3px">${badges}</div>` : ""}</td>
    <td><span class="sev ${sevClass(r.severity)}">${esc(r.severity)}</span></td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${esc(r.assignee || "—")}</td>
    <td>${esc(age)}</td>
    <td>${r.assets || `<span class="muted">0</span>`}</td>
    <td><button class="ev-btn" data-id="${r.id}" data-name="${esc(r.name)}" title="Attach / view evidence files">&#128206; ${r.evidence || 0}</button></td>
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
    $("im-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("im.empty")}</div>`;
    return;
  }

  const cards = [
    card(t("im.cIncidents"), String(s.total), fmt("im.cIncidents.foot", { n: s.open })),
    card(t("im.cCritical"), String(s.criticalOpen), t("im.cCritical.foot"), s.criticalOpen ? "#f87171" : "#34d399"),
    card(t("im.cBreached"), String(s.breached), t("im.cBreached.foot"), s.breached ? "#fb923c" : "#34d399"),
    card(t("im.cUnassigned"), String(s.unassigned), t("im.cUnassigned.foot"), s.unassigned ? "#fb923c" : "#34d399"),
    card(t("im.cStale"), String(s.stale), t("im.cStale.foot"), s.stale ? "#fbbf24" : undefined),
    card(t("im.cCompromises"), String(s.compromises), t("im.cCompromises.foot"), s.compromises ? "#f87171" : "#34d399"),
    card(t("im.cMttr"), s.mttrHours != null ? fmt("im.hours", { n: s.mttrHours }) : "—", t("im.cMttr.foot")),
  ].join("");

  const bySev = Object.entries(s.bySeverity).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="sev ${sevClass(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
  const byStat = Object.entries(s.byStatus).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("im.moreN", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("im.noFindings")}</div>`;

  const table = `<table class="im"><thead><tr>
      <th>${t("im.thIncident")}</th><th>${t("im.thSeverity")}</th><th>${t("im.thStatus")}</th><th>${t("im.thOwner")}</th><th>${t("im.thAge")}</th><th>${t("im.thAssets")}</th><th title="Attached evidence files">&#128206;</th><th>${t("im.thFindings")}</th><th title="${t("im.thPriority.title")}">${t("im.thPriority")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("im-body").innerHTML = `<div class="im-cards">${cards}</div>
    <div class="im-section">${fmt("im.secWorklist", { n: d.findings.length })}</div>${findings}
    <div class="im-section">${t("im.secBySeverity")}</div><div class="breakdown">${bySev}</div>
    <div class="im-section">${t("im.secByStatus")}</div><div class="breakdown">${byStat}</div>
    <div class="im-section">${fmt("im.secQueue", { n: d.rows.length })}</div>${table}
    <div class="legend">${t("im.legend")}</div>`;
  $("im-body").querySelectorAll<HTMLButtonElement>(".ev-btn").forEach((b) => {
    b.onclick = () => openEvidence(Number(b.dataset.id), b.dataset.name || `Incident #${b.dataset.id}`);
  });
}

// ── Evidence attachments (modal) ───────────────────────────────────────────────
let EV_CAN = false;
const humanSize = (n: number): string => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`);

function evModal(html: string): void {
  let m = document.getElementById("ev-modal");
  if (!m) { m = document.createElement("div"); m.id = "ev-modal"; m.className = "ev-modal"; document.body.appendChild(m); m.addEventListener("click", (e) => { if (e.target === m) closeEv(); }); }
  m.innerHTML = `<div class="ev-box">${html}</div>`;
  m.classList.add("on");
}
function closeEv(): void { document.getElementById("ev-modal")?.classList.remove("on"); }

function evListHtml(list: Evidence[]): string {
  if (!list.length) return `<div class="muted" style="padding:10px 0">No evidence attached yet.</div>`;
  return `<table class="ev-t"><tbody>${list.map((e) => `<tr>
    <td><a href="${esc(e.downloadUrl)}" target="_blank" rel="noopener">${esc(e.fileName)}</a>
      <div class="muted" style="font-size:11px">${esc(humanSize(e.size))} · ${esc(e.contentType)}${e.uploadedBy ? ` · ${esc(e.uploadedBy)}` : ""} · ${esc((e.createdDate || "").slice(0, 16).replace("T", " "))}${e.description ? `<br>${esc(e.description)}` : ""}</div></td>
    <td style="text-align:right;white-space:nowrap">${EV_CAN ? `<button class="ev-rm" data-id="${e.id}" title="Detach">&#10005;</button>` : ""}</td>
  </tr>`).join("")}</tbody></table>`;
}

async function openEvidence(incidentId: number, name: string): Promise<void> {
  evModal(`<div class="muted" style="padding:18px;text-align:center">Loading…</div>`);
  try {
    const r = await fetch(`/api/incident-management/incident/${incidentId}/evidence`);
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    EV_CAN = !!d.canEdit;
    render(incidentId, name, d.evidence as Evidence[]);
  } catch (e) { evModal(`<div style="padding:14px">⚠️ ${esc(e)}</div><div style="text-align:right"><button class="ev-close">Close</button></div>`); wireClose(); }
}

function render(incidentId: number, name: string, list: Evidence[]): void {
  const upload = EV_CAN ? `
    <div class="ev-up">
      <input type="file" id="ev-file">
      <input type="text" id="ev-desc" placeholder="Note (optional)" maxlength="1000">
      <button class="ev-add">Attach</button>
    </div>
    <div id="ev-err" class="muted" style="font-size:12px;color:#f87171"></div>` : "";
  evModal(`<div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
      <h3 style="margin:0;font-size:15px">Evidence — ${esc(name)}</h3><button class="ev-close" style="border:none;background:none;color:#94a3b8;font-size:18px;cursor:pointer">&times;</button></div>
    <div class="muted" style="font-size:11px;margin:4px 0 10px">Quick attachments (screenshots, logs, exports) stored in the content-addressed blob store. For chain-of-custody evidence, use CERT Operations.</div>
    <div id="ev-list">${evListHtml(list)}</div>${upload}`);
  wireClose();
  document.getElementById("ev-list")?.querySelectorAll<HTMLButtonElement>(".ev-rm").forEach((b) => b.onclick = () => removeEv(incidentId, name, Number(b.dataset.id)));
  const add = document.querySelector<HTMLButtonElement>(".ev-add");
  if (add) add.onclick = () => uploadEv(incidentId, name);
}

function wireClose(): void { document.querySelector<HTMLButtonElement>(".ev-close")?.addEventListener("click", closeEv); }

function fileToB64(f: File): Promise<string> {
  return new Promise((resolve, reject) => { const r = new FileReader(); r.onload = () => resolve(String(r.result).replace(/^data:[^;]+;base64,/, "")); r.onerror = () => reject(new Error("read failed")); r.readAsDataURL(f); });
}

async function uploadEv(incidentId: number, name: string): Promise<void> {
  const fi = document.getElementById("ev-file") as HTMLInputElement;
  const err = document.getElementById("ev-err")!;
  const f = fi.files && fi.files[0];
  if (!f) { err.textContent = "Pick a file first."; return; }
  if (f.size > 15 * 1024 * 1024) { err.textContent = "File too large (max 15 MB)."; return; }
  const btn = document.querySelector<HTMLButtonElement>(".ev-add")!; btn.disabled = true; btn.textContent = "Uploading…";
  try {
    const dataBase64 = await fileToB64(f);
    const desc = (document.getElementById("ev-desc") as HTMLInputElement).value;
    const r = await fetch(`/api/incident-management/incident/${incidentId}/evidence`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fileName: f.name, contentType: f.type || "application/octet-stream", dataBase64, description: desc }),
    });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    render(incidentId, name, d.evidence as Evidence[]);
    void load(); // refresh the queue count
  } catch (e) { err.textContent = `⚠️ ${e}`; btn.disabled = false; btn.textContent = "Attach"; }
}

async function removeEv(incidentId: number, name: string, evidenceId: number): Promise<void> {
  if (!confirm("Detach this evidence file from the incident?")) return;
  try {
    const r = await fetch(`/api/incident-management/evidence/${evidenceId}`, { method: "DELETE" });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    render(incidentId, name, d.evidence as Evidence[]);
    void load();
  } catch (e) { alert(`⚠️ ${e}`); }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
