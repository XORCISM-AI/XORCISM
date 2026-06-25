/**
 * pir.ts — Priority Intelligence Requirements coverage register (/pir).
 * Renders each PIR with collection coverage (matching reporting) + gap flags, from /api/pir.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface PirRow {
  pirId: number; name: string; description: string; priority: string; status: string;
  keywords: string[]; owner: string | null; measurable: boolean;
  matches: number; recent: { id: number; name: string; date: string }[]; gap: boolean;
}
interface PirRegister {
  rows: PirRow[];
  summary: { total: number; active: number; covered: number; gaps: number; unmeasured: number; byPriority: Record<string, number> };
}

const prioClass = (p: string): string => `p-${(p || "medium").toLowerCase()}`;

function coverageCell(r: PirRow): string {
  if (!r.measurable) return `<span class="cov-na">— <span class="muted">${t("pir.addKeywords")}</span></span>`;
  if (r.matches === 0) return `<span class="cov-gap">${t("pir.gapZero")}</span>`;
  const recent = r.recent.map((x) => `<a href="/?db=XTHREAT&table=THREATREPORT">${esc(x.name)}</a>${x.date ? ` <span class="muted">(${esc(x.date)})</span>` : ""}`).join("<br>");
  return `<span class="cov-ok">${fmt("pir.nReports", { n: r.matches })}</span><div class="recent">${recent}</div>`;
}

function rowHtml(r: PirRow): string {
  const kws = r.keywords.length ? r.keywords.map((k) => `<span class="kw">${esc(k)}</span>`).join("") : `<span class="muted">${t("pir.none")}</span>`;
  return `<tr class="${r.gap ? "gap-row" : ""}">
    <td><span class="prio ${prioClass(r.priority)}">${esc(r.priority)}</span></td>
    <td><div class="pirname">${esc(r.name)}</div>${r.description ? `<div class="qn">${esc(r.description)}</div>` : ""}</td>
    <td>${esc(r.owner || "—")}</td>
    <td><span class="st">${esc(r.status)}</span></td>
    <td>${kws}</td>
    <td>${coverageCell(r)}</td>
  </tr>`;
}

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="pir-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

async function load(): Promise<void> {
  let d: PirRegister;
  try { const r = await fetch("/api/pir"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("pir-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("pir-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("pir.empty")}</div>`;
    return;
  }

  const cards = [
    card(t("pir.cRequirements"), String(s.total), fmt("pir.cRequirements.foot", { n: s.active })),
    card(t("pir.cCovered"), String(s.covered), t("pir.cCovered.foot"), s.covered ? "#34d399" : undefined),
    card(t("pir.cGaps"), String(s.gaps), t("pir.cGaps.foot"), s.gaps ? "#f87171" : "#34d399"),
    card(t("pir.cUnmeasured"), String(s.unmeasured), t("pir.cUnmeasured.foot"), s.unmeasured ? "#fbbf24" : undefined),
  ].join("");

  const body = `<table class="pir"><thead><tr>
      <th>${t("pir.thPriority")}</th><th>${t("pir.thRequirement")}</th><th>${t("pir.thOwner")}</th><th>${t("pir.thStatus")}</th><th>${t("pir.thKeywords")}</th><th>${t("pir.thCoverage")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("pir-body").innerHTML = `<div class="pir-cards">${cards}</div>${body}
    <div class="legend">${t("pir.legend")}</div>`;
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
