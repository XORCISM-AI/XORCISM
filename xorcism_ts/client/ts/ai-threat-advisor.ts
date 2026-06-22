/** ai-threat-advisor.ts — OWASP AI Exchange agent threat advisor (/ai-threat-advisor). */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2400); }

const SHAPES: [string, string][] = [["llm", "LLM application"], ["agent", "Autonomous agent"], ["ml", "ML model"], ["tools", "Uses tools / functions"], ["memory", "Has persistent memory"], ["autonomous", "Acts autonomously"], ["external", "Ingests external content"], ["sensitive", "Handles sensitive data"]];
const icls = (i: string): string => `i-${["High", "Medium", "Low"].includes(i) ? i : "Low"}`;
const selected = new Set<string>(["agent", "tools", "external"]);

function threatCard(th: any): string {
  return `<div class="th ${th.impact.toLowerCase()}">
    <div class="top"><span class="ref">${esc(th.ref)}</span><span class="nm">${esc(th.name)}</span><span class="cat">${esc(th.category)}</span><span class="imp ${icls(th.impact)}">${esc(th.impact)}</span><span class="muted" style="font-size:11px;margin-left:auto">${esc(th.lifecycle)}</span></div>
    <div class="desc">${esc(th.description)}</div>
    <div class="ctrl"><b>Controls:</b> ${esc(th.controls)}</div>
  </div>`;
}

function renderShapes(): void {
  $("shapes").innerHTML = SHAPES.map(([k, l]) => `<label class="shape${selected.has(k) ? " on" : ""}" data-k="${k}"><input type="checkbox" ${selected.has(k) ? "checked" : ""}> ${esc(l)}</label>`).join("");
  Array.prototype.forEach.call(document.querySelectorAll(".shape"), (el: HTMLElement) => {
    el.onclick = (e) => { if ((e.target as HTMLElement).tagName !== "INPUT") (el.querySelector("input") as HTMLInputElement).checked = !(el.querySelector("input") as HTMLInputElement).checked;
      const k = el.getAttribute("data-k")!; if ((el.querySelector("input") as HTMLInputElement).checked) { selected.add(k); el.classList.add("on"); } else { selected.delete(k); el.classList.remove("on"); } };
  });
}

function advise(): void {
  if (!selected.size) { toast("Select at least one characteristic"); return; }
  fetch("/api/ai-threats/advise", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ shapes: [...selected] }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d) => {
      const cards = `<div class="cards"><div class="card"><div class="lbl">Applicable threats</div><div class="val">${d.summary.applicable}</div><div class="foot">for this system</div></div>
        <div class="card"><div class="lbl">High impact</div><div class="val" style="color:#f87171">${d.summary.high}</div><div class="foot">prioritize</div></div>
        <div class="card"><div class="lbl">Categories</div><div class="val">${d.summary.categories}</div><div class="foot">threat families</div></div></div>`;
      $("result").innerHTML = `<div class="sec">Applicable threats (${d.threats.length})</div>${cards}${d.threats.map(threatCard).join("")}`;
      $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function loadCatalogue(): void {
  fetch("/api/ai-threats").then((r) => r.json()).then((d) => {
    $("catalogue").innerHTML = `<div class="muted" style="font-size:12px;margin-bottom:8px">${d.total} threats · source: ${esc(d.source)}</div>` +
      d.categories.map((c: any) => `<div class="sec" style="font-size:12px;color:#a5b4fc">${esc(c.category)}</div>${c.threats.map((t: any) => threatCard({ ...t, category: c.category })).join("")}`).join("");
  }).catch((e) => { $("catalogue").innerHTML = `<div class="muted">⚠️ ${esc(e)}</div>`; });
}

document.addEventListener("DOMContentLoaded", () => { renderShapes(); $("advise").onclick = advise; advise(); loadCatalogue(); });
