/**
 * pir.ts — Priority Intelligence Requirements coverage register (/pir).
 * Renders each PIR with collection coverage (matching reporting) + gap flags, from /api/pir.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

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
  if (!r.measurable) return `<span class="cov-na">— <span class="muted">add keywords</span></span>`;
  if (r.matches === 0) return `<span class="cov-gap">⚠ gap — 0 reports</span>`;
  const recent = r.recent.map((x) => `<a href="/?db=XTHREAT&table=THREATREPORT">${esc(x.name)}</a>${x.date ? ` <span class="muted">(${esc(x.date)})</span>` : ""}`).join("<br>");
  return `<span class="cov-ok">${r.matches} report${r.matches > 1 ? "s" : ""}</span><div class="recent">${recent}</div>`;
}

function rowHtml(r: PirRow): string {
  const kws = r.keywords.length ? r.keywords.map((k) => `<span class="kw">${esc(k)}</span>`).join("") : `<span class="muted">none</span>`;
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
    $("pir-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No Priority Intelligence Requirements yet.
      <a href="/?db=XTHREAT&table=PIR">Create your first PIR</a> — give it a name, a priority, and keywords to track.</div>`;
    return;
  }

  const cards = [
    card("Requirements", String(s.total), `${s.active} active`),
    card("Covered", String(s.covered), "have matching reporting", s.covered ? "#34d399" : undefined),
    card("Collection gaps", String(s.gaps), "active · keyworded · 0 reports", s.gaps ? "#f87171" : "#34d399"),
    card("Need keywords", String(s.unmeasured), "active but not measurable", s.unmeasured ? "#fbbf24" : undefined),
  ].join("");

  const body = `<table class="pir"><thead><tr>
      <th>Priority</th><th>Requirement</th><th>Owner</th><th>Status</th><th>Keywords</th><th>Coverage</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("pir-body").innerHTML = `<div class="pir-cards">${cards}</div>${body}
    <div class="legend">↳ Coverage matches each PIR's keywords against <code>THREATREPORT</code> text
      (name, description, AI summary, CVE tags). A <span class="cov-gap">gap</span> is an active, keyworded
      requirement with no reporting against it — a candidate for tasking new collection.</div>`;
}

document.addEventListener("DOMContentLoaded", () => void load());
