/** soc-cmm.ts — SOC-CMM maturity self-assessment (/soc-cmm). Reads /api/soc-cmm. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2200); }

let LEVELS: string[] = [];
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const matColor = (m: number | null): string => (m == null ? "#64748b" : m >= 4 ? "#4ade80" : m >= 3 ? "#a3e635" : m >= 2 ? "#fbbf24" : "#f87171");

function load(): void {
  fetch("/api/soc-cmm").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    LEVELS = d.levels;
    const s = d.summary;
    const cards = [
      card("Overall maturity", s.overall == null ? "—" : `${s.overall}/5`, `target ${s.target}`, matColor(s.overall)),
      card("Coverage", `${s.coverage}%`, `${s.scored}/${s.aspects} aspects`),
      card("Below target", String(s.belowTarget), "aspects under maturity 3", s.belowTarget ? "#fbbf24" : "#4ade80"),
      card("Domains", String(d.domains.length), "SOC-CMM domains"),
    ].join("");
    const doms = d.domains.map((dm: any) => `<div class="dom"><span class="nm">${esc(dm.domain)}</span><div class="bar"><i style="width:${((dm.maturity || 0) / 5) * 100}%;background:${matColor(dm.maturity)}"></i></div><span style="min-width:60px;text-align:right;color:${matColor(dm.maturity)};font-weight:700">${dm.maturity == null ? "—" : dm.maturity + "/5"}</span></div>`).join("");
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.map((w: any) => `<li><span class="dchip">${esc(w.domain)}</span> <b style="color:#e2e8f0">${esc(w.aspect)}</b> — maturity ${w.maturity}/5 · importance ${w.importance}/5 <span class="muted" style="margin-left:auto">gap +${w.gap}</span></li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">✓ No high-importance low-maturity gaps.</div>`;
    const domNames = [...new Set(d.rows.map((r: any) => r.domain))];
    const tables = domNames.map((dn) => {
      const rows = d.rows.filter((r: any) => r.domain === dn).map((r: any) => `<tr>
        <td><span class="nm" style="color:#e2e8f0">${esc(r.aspect)}</span><div class="muted" style="font-size:11px">${esc(r.description)}</div></td>
        <td>${matSel(r.id, r.maturity)}</td>
        <td>${impSel(r.id, r.importance)}</td></tr>`).join("");
      return `<div class="sec">${esc(dn)}</div><table class="t"><thead><tr><th>Aspect</th><th style="width:200px">Maturity</th><th style="width:130px">Importance</th></tr></thead><tbody>${rows}</tbody></table>`;
    }).join("");
    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">Maturity by domain</div>${doms}
      <div class="sec">Improvement worklist (${d.worklist.length})</div>${work}
      ${tables}`;
    wire();
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function matSel(id: number, cur: number | null): string {
  const opts = ["", "0", "1", "2", "3", "4", "5"].map((v) => `<option value="${v}"${String(cur ?? "") === v ? " selected" : ""}>${v === "" ? "—" : v + " · " + (LEVELS[Number(v)] || "")}</option>`).join("");
  return `<select class="mat" data-id="${id}">${opts}</select>`;
}
function impSel(id: number, cur: number): string {
  const opts = [1, 2, 3, 4, 5].map((v) => `<option value="${v}"${cur === v ? " selected" : ""}>${v}</option>`).join("");
  return `<select class="imp" data-id="${id}">${opts}</select>`;
}

function save(id: number, body: Record<string, unknown>): void {
  fetch(`/api/soc-cmm/score/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then(() => { toast("Saved"); load(); }).catch((e) => toast("⚠️ " + e));
}
function wire(): void {
  Array.prototype.forEach.call(document.querySelectorAll(".mat"), (sel: HTMLSelectElement) => { sel.onchange = () => { if (sel.value !== "") save(Number(sel.getAttribute("data-id")), { maturity: Number(sel.value) }); }; });
  Array.prototype.forEach.call(document.querySelectorAll(".imp"), (sel: HTMLSelectElement) => { sel.onchange = () => save(Number(sel.getAttribute("data-id")), { importance: Number(sel.value) }); });
}
document.addEventListener("DOMContentLoaded", load);
