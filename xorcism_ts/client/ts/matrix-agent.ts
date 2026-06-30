/**
 * matrix-agent.ts — Matrix Knowledge-Base Agent (/matrix-agent).
 * Matrix coverage picker (filter the question to a matrix), an ask box, and a cited answer
 * (cited matrix techniques with links). All from /api/matrix-agent*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }

let SELECTED = ""; // "" = all matrices
const EXAMPLES = [
  "Which ATLAS techniques relate to prompt injection?",
  "How do adversaries poison an ML model?",
  "What D3FEND defenses counter credential access?",
  "Show A3M techniques for autonomous agents",
  "What is model evasion and how is it detected?",
];

async function init(): Promise<void> {
  let cov: any;
  try { cov = await getJSON("/api/matrix-agent"); } catch (e) { $("mx-out").innerHTML = `<div class="muted">Failed to load: ${esc(String(e))}</div>`; return; }
  const mats: any[] = cov.matrices || [];
  const all = `<div class="mxc ${SELECTED === "" ? "on" : ""}" data-k=""><span class="n">All matrices</span><span class="c">${cov.total ?? 0}</span></div>`;
  $("mx-cov").innerHTML = all + mats.map((m) => `<div class="mxc ${m.imported ? "" : "off"} ${SELECTED === m.key ? "on" : ""}" data-k="${esc(m.key)}" title="${esc(m.scope)}">
    <span class="n scope-${esc(m.scope)}">${esc(m.label)}</span><span class="c">${m.count}</span></div>`).join("");
  document.querySelectorAll<HTMLElement>(".mxc").forEach((el) => { el.onclick = () => { SELECTED = el.dataset.k || ""; init(); }; });
  if (cov.provider) $("mx-out").dataset.prov = `${cov.provider.provider} · ${cov.provider.model}${cov.provider.local ? " (local)" : ""}`;
  $("ex").innerHTML = EXAMPLES.map((e) => `<span class="chip">${esc(e)}</span>`).join("");
  document.querySelectorAll<HTMLElement>("#ex .chip").forEach((c) => { c.onclick = () => { (document.getElementById("q") as HTMLInputElement).value = c.textContent || ""; ask(); }; });
}

async function ask(): Promise<void> {
  const q = (document.getElementById("q") as HTMLInputElement).value.trim();
  if (!q) return;
  const btn = document.getElementById("ask") as HTMLButtonElement;
  btn.disabled = true;
  $("mx-out").innerHTML = `<div class="spin">${esc(t("mx.thinking", "Retrieving techniques and composing an answer…"))}</div>`;
  let d: any;
  try { d = await postJSON("/api/matrix-agent/ask", { question: q, matrix: SELECTED || undefined }); }
  catch (e) { $("mx-out").innerHTML = `<div class="muted">Error: ${esc(String(e))}</div>`; btn.disabled = false; return; }
  btn.disabled = false;
  const prov = $("mx-out").dataset.prov || "";
  const sources = (d.sources || []).map((s: any) => `<div class="src">
    <a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.id)} — ${esc(s.name)}</a><span class="mtag scope-${esc(s.scope)}">${esc(s.matrixLabel)}</span>
    <p>${esc(s.snippet)}</p></div>`).join("");
  $("mx-out").innerHTML = `
    <div class="prov">${d.offline ? "⚠︎ " + esc(t("mx.offline", "Local AI unavailable — retrieval-only digest")) : "🤖 " + esc(prov)}</div>
    <div class="answer">${esc(d.answer)}</div>
    ${sources ? `<div class="sec-h">${esc(t("mx.cited", "Cited techniques"))} (${(d.sources || []).length})</div>${sources}` : ""}`;
}

(document.getElementById("ask") as HTMLButtonElement).onclick = ask;
(document.getElementById("q") as HTMLInputElement).addEventListener("keydown", (e) => { if (e.key === "Enter") ask(); });
init();
