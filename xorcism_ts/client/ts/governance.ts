/** governance.ts — NIST CSF 2.0 Govern (GV) posture (/governance). Reads /api/governance. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2200); }

const STATUSES = ["Implemented", "Partially implemented", "Planned", "Not implemented", "Not applicable"];
const stCls = (s: string): string => s === "Implemented" ? "s-impl" : s === "Partially implemented" ? "s-part" : s === "Planned" ? "s-plan" : s === "Not applicable" ? "s-na" : "s-no";
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const pctColor = (p: number): string => (p >= 75 ? "#4ade80" : p >= 50 ? "#fbbf24" : "#f87171");

function load(): void {
  fetch("/api/governance").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    const s = d.summary;
    const cards = [
      card("Governance posture", `${s.score}%`, "GV implementation", pctColor(s.score)),
      card("Implemented", String(s.implemented), `of ${s.items} subcategories`, "#4ade80"),
      card("Partial / planned", String(s.partial), "in progress", "#fbbf24"),
      card("Not implemented", String(s.notImplemented), "gaps", s.notImplemented ? "#f87171" : "#4ade80"),
      card("No owner", String(s.noOwner), "needs accountability", s.noOwner ? "#fbbf24" : "#4ade80"),
    ].join("");
    const sig = `<div class="sig"><span class="bd">📜 <b>${d.signals.policies}</b> policies${d.signals.approvedPolicies != null ? ` (${d.signals.approvedPolicies} approved)` : ""}</span><span class="bd">⚠️ <b>${d.signals.risks}</b> risk-register entries</span><span class="bd">👥 <b>${d.signals.rolesDefined}</b> roles defined (reporting lines)</span></div>`;
    const cats = d.byCategory.map((c: any) => `<div class="catrow"><span class="nm">${esc(c.category)} <span class="code">${esc(c.code)}</span></span><div class="bar"><i style="width:${c.pct}%;background:${pctColor(c.pct)}"></i></div><span style="min-width:90px;text-align:right;color:${pctColor(c.pct)};font-weight:700">${c.pct}% <span class="muted" style="font-weight:400">(${c.implemented}/${c.items})</span></span></div>`).join("");
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.map((w: any) => `<li><span class="scode">${esc(w.sub)}</span> <b style="color:#e2e8f0">${esc(w.title)}</b> <span class="muted">${esc(w.category)}</span> <span class="st ${stCls(w.status)}" style="margin-left:auto">${esc(w.status)}</span></li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">✓ All Govern subcategories addressed.</div>`;
    const cnames = [...new Set(d.rows.map((r: any) => r.category))];
    const tables = cnames.map((cn) => {
      const rows = d.rows.filter((r: any) => r.category === cn).map((r: any) => `<tr>
        <td class="scode">${esc(r.sub)}</td>
        <td><span style="color:#e2e8f0;font-weight:600">${esc(r.title)}</span><div class="muted" style="font-size:11px">${esc(r.description)}</div></td>
        <td>${statusSel(r.id, r.status)}</td></tr>`).join("");
      return `<div class="sec">${esc(cn)}</div><table class="t"><thead><tr><th style="width:90px">Sub</th><th>Subcategory</th><th style="width:200px">Status</th></tr></thead><tbody>${rows}</tbody></table>`;
    }).join("");
    $("body").innerHTML = `<div class="cards">${cards}</div>${sig}
      <div class="sec">Govern (GV) categories</div>${cats}
      <div class="sec">Governance worklist (${d.worklist.length})</div>${work}
      ${tables}`;
    wire();
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
function statusSel(id: number, cur: string): string {
  return `<select class="st-sel" data-id="${id}">${STATUSES.map((v) => `<option value="${v}"${v === cur ? " selected" : ""}>${v}</option>`).join("")}</select>`;
}
function wire(): void {
  Array.prototype.forEach.call(document.querySelectorAll(".st-sel"), (sel: HTMLSelectElement) => { sel.onchange = () => {
    fetch(`/api/governance/item/${sel.getAttribute("data-id")}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: sel.value }) })
      .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then(() => { toast("Saved"); load(); }).catch((e) => toast("⚠️ " + e));
  }; });
}
document.addEventListener("DOMContentLoaded", load);
