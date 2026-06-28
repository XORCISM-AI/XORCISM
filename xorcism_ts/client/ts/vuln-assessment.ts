/**
 * vuln-assessment.ts — Vulnerability Assessment cockpit (/vuln-assessment). Paste a software inventory →
 * POST /api/vuln-assessment → enriched, ranked report (CVSS/EPSS/KEV/SSVC/exploit, Act/Prioritise/Track).
 */
export {}; // module scope
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Finding { cve: string; cvss: number | null; epss: number | null; kev: boolean; ssvc: string | null; exploit: number; score: number; decision: "Act" | "Prioritise" | "Track"; title: string }
interface Comp { input: string; product: string; version?: string; ecosystem?: string; matched: boolean; cves: Finding[]; topScore: number }
interface Result { components: Comp[]; summary: { components: number; matched: number; vulnerable: number; totalCves: number; kev: number; exploitable: number; act: number; prioritise: number; track: number; maxScore: number }; note: string }

const SAMPLE = `openssl 1.0.1
log4j 2.14.1
apache http_server 2.4.49
pkg:npm/lodash@4.17.4
curl 7.68.0
cpe:2.3:a:samba:samba:4.13.0`;

const pct = (e: number | null): string => (e == null ? "—" : `${(e * 100).toFixed(0)}%`);

function render(d: Result): void {
  const s = d.summary;
  const card = (n: number | string, l: string, color?: string): string =>
    `<div class="va-card"><div class="n"${color ? ` style="color:${color}"` : ""}>${n}</div><div class="l">${esc(l)}</div></div>`;
  const cards =
    card(s.components, "components") +
    card(s.vulnerable, "vulnerable", s.vulnerable ? "#fbbf24" : "#34d399") +
    card(s.totalCves, "CVEs") +
    card(s.act, "Act now", s.act ? "#f87171" : "#34d399") +
    card(s.prioritise, "Prioritise", "#fbbf24") +
    card(s.kev, "KEV", s.kev ? "#f87171" : "#94a3b8") +
    card(s.exploitable, "exploitable", s.exploitable ? "#fb923c" : "#94a3b8");

  const rowsFor = (c: Comp): string => c.cves.slice(0, 60).map((f) => `<tr>
      <td><span class="cve">${esc(f.cve)}</span>${f.kev ? ' <span class="kev" title="CISA KEV">KEV</span>' : ""}${f.exploit ? ` <span class="expl" title="${f.exploit} Exploit-DB entr${f.exploit > 1 ? "ies" : "y"}">⚑${f.exploit}</span>` : ""}<div class="muted" style="font-size:10.5px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.title)}</div></td>
      <td><span class="pill ${f.decision}">${f.decision}</span></td>
      <td class="num">${f.cvss == null ? "—" : esc(f.cvss)}</td>
      <td class="num">${pct(f.epss)}</td>
      <td class="num">${f.score}<span class="scorebar" style="width:${Math.round(f.score / 2.2)}px;margin-left:6px"></span></td>
    </tr>`).join("");

  const comps = d.components.map((c, i) => {
    if (!c.cves.length) return "";
    return `<div class="comp">
      <div class="comp-head" data-i="${i}">
        <span class="prod">${esc(c.product)}</span>${c.version ? `<span class="ver">${esc(c.version)}</span>` : ""}${c.ecosystem ? `<span class="muted" style="font-size:10.5px">${esc(c.ecosystem)}</span>` : ""}
        <span class="cnt">${c.cves.length} CVE${c.cves.length > 1 ? "s" : ""} · top ${c.topScore}</span>
      </div>
      <table class="va"><thead><tr><th>CVE</th><th>Decision</th><th class="num">CVSS</th><th class="num">EPSS</th><th class="num">Score</th></tr></thead><tbody>${rowsFor(c)}</tbody></table>
    </div>`;
  }).join("");

  const clean = d.components.filter((c) => !c.cves.length);
  const cleanLine = clean.length ? `<div class="muted" style="font-size:11.5px;margin-top:10px">No local CVEs for ${clean.length} component(s): ${clean.slice(0, 20).map((c) => esc(c.product)).join(", ")}${clean.length > 20 ? "…" : ""}. Configure the Vulners connector for broader coverage.</div>` : "";

  $("va-out").innerHTML = `<div class="va-cards">${cards}</div>${comps || `<div class="muted" style="padding:16px">No vulnerabilities matched in the local store.</div>`}${cleanLine}<div class="muted" style="font-size:11px;margin-top:12px">${esc(d.note)}</div>`;
}

async function run(): Promise<void> {
  const inventory = ($("va-input") as HTMLTextAreaElement).value.trim();
  if (!inventory) { $("va-status").textContent = "Paste an inventory first."; return; }
  const btn = $("va-run") as HTMLButtonElement; btn.disabled = true; $("va-status").textContent = "Assessing…";
  try {
    const r = await fetch("/api/vuln-assessment", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ inventory }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    render(d as Result);
    $("va-status").textContent = "";
  } catch (e) { $("va-status").textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("va-run").addEventListener("click", () => void run());
  $("va-sample").addEventListener("click", () => { ($("va-input") as HTMLTextAreaElement).value = SAMPLE; });
  ($("va-input") as HTMLTextAreaElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter" && (e as KeyboardEvent).ctrlKey) void run(); });
});
