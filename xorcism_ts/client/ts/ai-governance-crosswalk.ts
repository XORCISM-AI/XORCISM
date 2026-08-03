/**
 * ai-governance-crosswalk.ts — AI Governance Crosswalk cockpit (/ai-governance-crosswalk).
 * Renders the Crosswalk Matrix (governance capability × EU AI Act / NIST AI RMF / ISO 42001 / Singapore
 * + evidence / owner / priority), per-instrument coverage, the EU application timeline, the Navigator and
 * the roadmap — with inline per-capability status tracking.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string, ok = true): void { const el = $("toast"); el.textContent = msg; el.className = ok ? "toast-ok" : "toast-err"; el.style.opacity = "1"; setTimeout(() => (el.style.opacity = "0"), 2400); }
const pctColor = (p: number): string => (p >= 70 ? "#22c55e" : p >= 40 ? "#f59e0b" : "#ef4444");

interface RefLink { count: number; items: { id: number; ref: string | null; name: string }[] }
interface Cap {
  id: string; domain: string; capability: string; eu: string; nist: string; iso: string; sg: string;
  evidence: string; owner: string; priority: "P1" | "P2" | "P3"; status: string;
  evidenceRef: string | null; ownerOverride: string | null;
  links?: { eu: RefLink; nist: RefLink; iso: RefLink; sg: RefLink };
}
// A ref cell: the textual reference + a badge counting the imported CONTROL rows it resolves to.
function refCell(text: string, link: RefLink | undefined): string {
  if (!link || !link.count) return `<td class="ref">${esc(text)}</td>`;
  const title = link.items.map((i) => `${i.ref || ""} ${i.name}`).join("\n") + (link.count > link.items.length ? `\n…+${link.count - link.items.length}` : "");
  return `<td class="ref">${esc(text)} <span class="lk" title="${esc(title)}">🔗${link.count}</span></td>`;
}
interface Matrix {
  instruments: { key: string; label: string; sub: string }[];
  domains: { domain: string; rows: Cap[]; met: number; total: number }[];
  capabilities: Cap[];
  summary: {
    totalCapabilities: number; assessable: number; met: number; coveragePct: number;
    statusCounts: Record<string, number>;
    perInstrument: { key: string; label: string; met: number; total: number; pct: number }[];
    perPriority: { priority: string; met: number; total: number; pct: number }[];
    p1Open: number;
  };
  timeline: { date: string; item: string; status: string }[];
  navigator: string[];
  roadmap: { phase: string; window: string; items: string[] }[];
}

const STATUSES = ["not-started", "in-progress", "met", "na"];
const stClass = (s: string): string => (s === "met" ? "met" : s === "in-progress" ? "inprog" : s === "na" ? "na" : "");

async function setStatus(capId: string, status: string): Promise<void> {
  try {
    const r = await fetch("/api/ai-governance-crosswalk/status", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ capId, status }) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    toast(t("cw.saved"));
    await load();
  } catch (e) { toast(t("cw.saveFail") + ": " + esc(e), false); }
}

async function load(): Promise<void> {
  let d: Matrix;
  try { const r = await fetch("/api/ai-governance-crosswalk"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cw-matrix").innerHTML = `<div style="color:#64748b">${t("cw.loadFail")}: ${esc(e)}</div>`; return; }
  const s = d.summary;
  const linked = d.capabilities.reduce((n, c) => n + (c.links ? c.links.eu.count + c.links.nist.count + c.links.iso.count + c.links.sg.count : 0), 0);

  $("cw-kpis").innerHTML = [
    `<div class="kpi"><div class="v" style="color:${pctColor(s.coveragePct)}">${s.coveragePct}%</div><div class="l">${t("cw.kpi.coverage")}</div></div>`,
    `<div class="kpi"><div class="v">${s.met}/${s.assessable}</div><div class="l">${t("cw.kpi.met")}</div></div>`,
    `<div class="kpi"><div class="v" style="color:${s.p1Open ? "#fca5a5" : "#6ee7b7"}">${s.p1Open}</div><div class="l">${t("cw.kpi.p1open")}</div></div>`,
    `<div class="kpi"><div class="v">${s.totalCapabilities}</div><div class="l">${t("cw.kpi.caps")}</div></div>`,
    `<div class="kpi"><div class="v">${d.domains.length}</div><div class="l">${t("cw.kpi.domains")}</div></div>`,
    `<div class="kpi"><div class="v">4</div><div class="l">${t("cw.kpi.instruments")}</div></div>`,
    `<div class="kpi"><div class="v" style="color:#6ee7b7">${linked}</div><div class="l">${t("cw.kpi.linked")}</div></div>`,
  ].join("");

  $("cw-inst").innerHTML = s.perInstrument.map((i) =>
    `<div class="instc"><div class="n">${esc(i.label)}</div><div class="s">${i.met}/${i.total} · ${i.pct}%</div>` +
    `<span class="bar"><i style="width:${i.pct}%;background:${pctColor(i.pct)}"></i></span></div>`).join("");

  $("cw-timeline").innerHTML = d.timeline.map((tl) =>
    `<div class="tlc ${esc(tl.status)}"><b>${esc(tl.date)}</b> — ${esc(tl.item)}</div>`).join("");

  // Matrix grouped by domain
  const head = `<tr><th>${t("cw.col.cap")}</th><th>EU AI Act</th><th>NIST AI RMF</th><th>ISO/IEC 42001</th><th>Singapore</th>` +
    `<th>${t("cw.col.evidence")}</th><th>${t("cw.col.owner")}</th><th>${t("cw.col.pri")}</th><th>${t("cw.col.status")}</th></tr>`;
  const body = d.domains.map((dom) => {
    const dh = `<tr class="dh"><td colspan="9">${esc(dom.domain)} · <span style="color:#94a3b8;font-weight:600">${dom.met}/${dom.total}</span></td></tr>`;
    const rows = dom.rows.map((c) => {
      const opts = STATUSES.map((o) => `<option value="${o}"${o === c.status ? " selected" : ""}>${t("cw.st." + o)}</option>`).join("");
      return `<tr>` +
        `<td class="cap">${esc(c.capability)}</td>` +
        refCell(c.eu, c.links?.eu) + refCell(c.nist, c.links?.nist) + refCell(c.iso, c.links?.iso) + refCell(c.sg, c.links?.sg) +
        `<td class="evid">${esc(c.evidence)}</td>` +
        `<td class="own">${esc(c.ownerOverride || c.owner)}</td>` +
        `<td><span class="pri ${c.priority}">${c.priority}</span></td>` +
        `<td><select class="st ${stClass(c.status)}" data-cap="${esc(c.id)}">${opts}</select></td>` +
        `</tr>`;
    }).join("");
    return dh + rows;
  }).join("");
  $("cw-matrix").innerHTML = `<table class="cw"><thead>${head}</thead><tbody>${body}</tbody></table>`;
  $("cw-matrix").querySelectorAll<HTMLSelectElement>("select.st").forEach((sel) => {
    sel.addEventListener("change", () => setStatus(sel.dataset.cap!, sel.value));
  });

  $("cw-nav").innerHTML = d.navigator.map((q) => `<li>${esc(q)}</li>`).join("");
  $("cw-roadmap").innerHTML = d.roadmap.map((p) =>
    `<div class="rmp"><div class="ph">${esc(p.phase)}</div><div class="wd">${esc(p.window)}</div>` +
    `<ul>${p.items.map((it) => `<li>${esc(it)}</li>`).join("")}</ul></div>`).join("");
}

async function syncMappings(): Promise<void> {
  const btn = document.getElementById("cw-sync") as HTMLButtonElement | null;
  if (btn) btn.disabled = true;
  try {
    const r = await fetch("/api/ai-governance-crosswalk/sync-mappings", { method: "POST" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    toast(`${t("cw.synced")}: ${j.mapped} (${j.anchored} caps)`);
  } catch (e) { toast(t("cw.saveFail") + ": " + esc(e), false); }
  finally { if (btn) btn.disabled = false; }
}

initI18n().then(() => {
  document.getElementById("cw-sync")?.addEventListener("click", syncMappings);
  return load();
});
