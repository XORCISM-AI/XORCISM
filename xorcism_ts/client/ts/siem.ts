/**
 * siem.ts — client for SIEM-lite (/siem). KPI cards, severity breakdown, recent SIEM alerts and
 * top-matched rules from /api/siem; a log-ingest box that posts events → Sigma detection → alerts.
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Alert { id: number; name: string; severity: string; attack: string | null; status: string; created: string }
interface Data {
  summary: { rulesLoaded: number; builtinRules: number; events24h: number; eventsTotal: number; alerts: number; critical: number; high: number };
  bySev: Record<string, number>; alerts: Alert[]; topRules: { name: string; n: number }[]; canIngest: boolean;
}
const sevc = (s: string): string => `sv-${s}`;
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

function render(d: Data): void {
  const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card("Detection rules", s.rulesLoaded, `${s.builtinRules} built-in + Sigma lib`),
    card("Events (24h)", s.events24h, `${s.eventsTotal} total`),
    card("Alerts raised", s.alerts, "by SIEM-lite", s.alerts ? "#fbbf24" : "#34d399"),
    card("Critical", s.critical, "needs response", s.critical ? "#f87171" : "#34d399"),
    card("High", s.high, "prioritise", s.high ? "#fbbf24" : undefined),
  ].join("");
  const alerts = d.alerts.length
    ? `<table class="t"><thead><tr><th>Severity</th><th>Detection</th><th>ATT&CK</th><th>Status</th><th>When</th></tr></thead><tbody>${d.alerts.map((a) => `<tr><td><span class="sev ${sevc(a.severity)}">${esc(a.severity)}</span></td><td class="nm">${esc(a.name)}</td><td>${(a.attack || "").split(",").map((t) => t.trim()).filter(Boolean).map((t) => `<span class="chip">${esc(t)}</span>`).join("") || "<span class='muted'>—</span>"}</td><td>${esc(a.status)}</td><td class="muted" style="font-size:11px">${esc((a.created || "").slice(0, 16).replace("T", " "))}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">No alerts yet — ingest some logs below (or click “Try sample logs”).</div>`;
  const top = d.topRules.length ? `<div style="margin-top:6px">${d.topRules.map((r) => `<span class="chip"><b>${r.n}</b> ${esc(r.name)}</span>`).join(" ")}</div>` : "";

  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">Alerts raised (${d.alerts.length})</div>${alerts}
    ${top ? `<div class="sec">Top detections</div>${top}` : ""}`;
  if (!d.canIngest) for (const id of ["ing", "samp"]) { const b = $(id) as HTMLButtonElement | null; if (b) { b.disabled = true; b.style.opacity = "0.5"; } }
}

async function load(): Promise<void> {
  try { render(await getJson("/api/siem")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
function status(msg: string): void { const s = $("stat"); if (s) s.textContent = msg; }

async function ingest(): Promise<void> {
  const txt = ($("logs") as HTMLTextAreaElement).value.trim();
  if (!txt) { status("Paste some JSON log records first."); return; }
  let events: any;
  try { events = JSON.parse(txt); if (!Array.isArray(events)) events = [events]; } catch { status("⚠️ Invalid JSON."); return; }
  try {
    const d = await getJson("/api/siem/ingest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ events }) });
    render(d); status(`Ingested ${d.ingested} events → ${d.matched} detection(s)`);
    toast(d.matched ? `${d.matched} detection(s) raised` : "No detections");
  } catch (e) { status(`⚠️ ${(e as Error).message}`); }
}
async function sample(): Promise<void> {
  try { const d = await getJson("/api/siem/sample", { method: "POST" }); render(d); status(`Sample: ${d.ingested} events → ${d.matched} detection(s)`); toast(`${d.matched} detection(s) raised`); }
  catch (e) { status(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  $("ing")?.addEventListener("click", () => void ingest());
  $("samp")?.addEventListener("click", () => void sample());
  void load();
});
