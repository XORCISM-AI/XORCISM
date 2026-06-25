/**
 * reg-calendar.ts — client for the Regulatory obligations & compliance calendar (/reg-calendar).
 * Renders KPI cards, an upcoming-deadline countdown calendar, per-regulation posture and the full
 * obligations table from /api/reg-calendar, with add-obligation + inline status editing.
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Obl {
  id: number; regulation: string; reference: string; title: string; description: string; category: string;
  dueDate: string | null; recurrenceMonths: number | null; status: string; owner: string; controlRef: string;
  jurisdiction: string; priority: string; evidenceUrl: string; tenant: number | null;
  effectiveStatus: string; daysUntil: number | null;
}
interface Data {
  summary: { total: number; regulations: number; overdue: number; dueSoon: number; upcoming: number; met: number; open: number };
  byRegulation: { regulation: string; total: number; overdue: number; dueSoon: number; met: number; nextDue: string | null }[];
  calendar: Obl[]; obligations: Obl[]; canEdit: boolean;
}
let DATA: Data | null = null;

const stClass = (s: string): string => `st-${(s || "").replace(/[^a-z]/gi, "")}`;
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}

function countdown(o: Obl): string {
  if (o.daysUntil == null) return o.recurrenceMonths ? `<span class="muted">every ${o.recurrenceMonths}mo</span>` : `<span class="muted">—</span>`;
  const d = o.daysUntil;
  if (d < 0) return `<span class="countdown" style="color:#f87171">${-d}d overdue</span>`;
  if (d === 0) return `<span class="countdown" style="color:#fbbf24">today</span>`;
  const col = d <= 30 ? "#fbbf24" : d <= 90 ? "#60a5fa" : "#94a3b8";
  return `<span class="countdown" style="color:${col}">in ${d}d</span>`;
}
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
function statusSelect(o: Obl): string {
  if (!DATA?.canEdit) return `<span class="st ${stClass(o.effectiveStatus)}">${esc(o.effectiveStatus)}</span>`;
  const opts = ["Not started", "In progress", "Met", "N/A"];
  const cur = ["Met", "N/A"].includes(o.status) ? o.status : "";
  return `<select class="act" data-status="${o.id}"><option value="">${esc(o.effectiveStatus)}</option>${opts.map((s) => `<option ${s === cur ? "selected" : ""}>${s}</option>`).join("")}</select>`;
}

function oblRow(o: Obl): string {
  return `<tr>
    <td><span class="reg">${esc(o.regulation)}</span><div class="mono" style="margin-top:3px">${esc(o.reference)}</div></td>
    <td><span class="nm">${esc(o.title)}</span><div class="muted" style="font-size:11.5px;max-width:420px">${esc(o.description)}</div>${o.controlRef ? `<div class="muted" style="font-size:11px;margin-top:2px">↳ ${esc(o.controlRef)}</div>` : ""}</td>
    <td>${o.dueDate ? esc(o.dueDate) : `<span class="muted">ongoing</span>`}<div style="margin-top:3px">${countdown(o)}</div></td>
    <td><span class="st ${stClass(o.effectiveStatus)}">${esc(o.effectiveStatus)}</span></td>
    <td>${o.owner ? esc(o.owner) : `<span class="muted">—</span>`}</td>
    <td>${statusSelect(o)}</td>
  </tr>`;
}

function render(d: Data): void {
  DATA = d; const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card("Obligations", s.total, `${s.regulations} regulations`),
    card("Overdue", s.overdue, "past due date", s.overdue ? "#f87171" : "#34d399"),
    card("Due ≤ 30d", s.dueSoon, "act now", s.dueSoon ? "#fbbf24" : "#34d399"),
    card("Due ≤ 90d", s.upcoming, "plan ahead", s.upcoming ? "#60a5fa" : undefined),
    card("Met", s.met, "tracked complete", "#34d399"),
    card("Open", s.open, "need attention", s.open ? "#fbbf24" : "#34d399"),
  ].join("");

  const reg = d.byRegulation.map((r) => `<span class="bd"><b>${esc(r.regulation)}</b> ${r.total}${r.overdue ? ` · <span style="color:#f87171">${r.overdue} overdue</span>` : ""}${r.dueSoon ? ` · <span style="color:#fbbf24">${r.dueSoon} soon</span>` : ""}${r.nextDue ? ` · next ${esc(r.nextDue)}` : ""}</span>`).join("");

  const calRows = d.calendar.map((o) => `<tr>
      <td style="white-space:nowrap"><span class="nm">${esc(o.dueDate)}</span><div>${countdown(o)}</div></td>
      <td><span class="reg">${esc(o.regulation)}</span> <span class="mono">${esc(o.reference)}</span><div class="nm" style="margin-top:2px">${esc(o.title)}</div></td>
      <td><span class="st ${stClass(o.effectiveStatus)}">${esc(o.effectiveStatus)}</span></td>
    </tr>`).join("");
  const calendar = d.calendar.length
    ? `<table class="t"><thead><tr><th>Deadline</th><th>Obligation</th><th>Status</th></tr></thead><tbody>${calRows}</tbody></table>`
    : `<div class="muted">No dated deadlines — all tracked obligations are ongoing.</div>`;

  const table = `<table class="t"><thead><tr><th>Regulation</th><th>Obligation</th><th>Due</th><th>Status</th><th>Owner</th><th>Set</th></tr></thead>
     <tbody>${d.obligations.map(oblRow).join("")}</tbody></table>`;

  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">Upcoming deadlines</div>${calendar}
    <div class="sec">By regulation</div><div>${reg || "<span class='muted'>—</span>"}</div>
    <div class="sec">All obligations (${d.obligations.length})</div>${table}`;

  body.querySelectorAll<HTMLSelectElement>("select[data-status]").forEach((sel) => {
    sel.addEventListener("change", () => void setStatus(Number(sel.dataset.status), sel.value));
  });
  const nb = $("r-new") as HTMLButtonElement | null;
  if (nb && !d.canEdit) { nb.disabled = true; nb.style.opacity = "0.5"; }
}

async function load(): Promise<void> {
  try { render(await getJson("/api/reg-calendar")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}

async function setStatus(id: number, status: string): Promise<void> {
  if (!status) return;
  try { render(await getJson(`/api/reg-calendar/obligation/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) })); toast(`Status → ${status}`); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

function openModal(): void { $("m-modal")?.classList.add("open"); ($("f-title") as HTMLInputElement)?.focus(); }
function closeModal(): void { $("m-modal")?.classList.remove("open"); const e = $("f-err"); if (e) e.textContent = ""; }
async function save(): Promise<void> {
  const v = (id: string): string => ($(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement)?.value || "";
  const title = v("f-title").trim(); const err = $("f-err");
  if (!title) { if (err) err.textContent = "Title is required."; return; }
  const body = { regulation: v("f-reg") || "Custom", reference: v("f-ref"), title, description: v("f-desc"), dueDate: v("f-due") || null, owner: v("f-owner"), priority: v("f-prio"), status: v("f-status"), controlRef: v("f-ctrl") };
  try {
    render(await getJson("/api/reg-calendar/obligation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }));
    closeModal(); toast("Obligation added");
  } catch (e) { if (err) err.textContent = `⚠️ ${(e as Error).message}`; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("r-new")?.addEventListener("click", openModal);
  $("m-cancel")?.addEventListener("click", closeModal);
  $("m-save")?.addEventListener("click", () => void save());
  $("m-modal")?.addEventListener("click", (e) => { if (e.target === $("m-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Escape") closeModal(); });
  void load();
});
