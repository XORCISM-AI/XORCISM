/**
 * attack-flow.ts — MITRE CTID Attack Flow cockpit (/attack-flow).
 * Import Attack Flow STIX 2.1 bundles (paste JSON or https URL, incl. the published corpus), list
 * imported flows, and render each as an ATT&CK-mapped directed graph (layered by longest path) plus a
 * per-flow technique coverage list.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }

let SEL: number | null = null;

// a handful of well-known corpus flows for one-click import
const CORPUS_BASE = "https://center-for-threat-informed-defense.github.io/attack-flow/corpus/";
const CORPUS = ["SolarWinds", "NotPetya", "Conti Ransomware", "Equifax Breach", "REvil", "Target Breach", "Uber Breach", "SearchAwesome Adware"];

async function api(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `Error ${r.status}`);
  return d;
}
const post = (u: string, b?: unknown): Promise<any> => api(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) });

// node fill by kind
const KIND_FILL: Record<string, string> = {
  "attack-action": "#1e3a5f", "attack-asset": "#3b2f14", "attack-condition": "#3a1f3a", "attack-operator": "#243b2a",
};
const KIND_STROKE: Record<string, string> = {
  "attack-action": "#38bdf8", "attack-asset": "#fbbf24", "attack-condition": "#e879f9", "attack-operator": "#4ade80",
};
const EDGE_COLOR: Record<string, string> = { effect: "#64748b", on_true: "#4ade80", on_false: "#f87171", asset: "#a16207" };

function graph(nodes: any[], edges: any[]): string {
  if (!nodes.length) return `<div class="af-empty">No nodes in this flow.</div>`;
  // group by depth (column), order within column by input order
  const cols = new Map<number, any[]>();
  for (const n of nodes) { const d = n.depth || 0; if (!cols.has(d)) cols.set(d, []); cols.get(d)!.push(n); }
  const maxDepth = Math.max(...nodes.map((n) => n.depth || 0));
  const NW = 168, NH = 54, GX = 74, GY = 26;
  const colX = (d: number): number => 20 + d * (NW + GX);
  const rowY = (i: number): number => 20 + i * (NH + GY);
  const pos = new Map<string, { x: number; y: number }>();
  let maxRows = 0;
  for (let d = 0; d <= maxDepth; d++) {
    const list = cols.get(d) || [];
    maxRows = Math.max(maxRows, list.length);
    list.forEach((n, i) => pos.set(n.stixId, { x: colX(d), y: rowY(i) }));
  }
  const W = colX(maxDepth) + NW + 20, H = 40 + maxRows * (NH + GY);

  const eSvg = edges.map((e) => {
    const a = pos.get(e.src), b = pos.get(e.dst); if (!a || !b) return "";
    const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2;
    const mx = (x1 + x2) / 2, col = EDGE_COLOR[e.kind] || "#64748b";
    const dash = e.kind === "asset" ? ' stroke-dasharray="3 3"' : "";
    return `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none" stroke="${col}" stroke-width="1.6"${dash} marker-end="url(#af-ar-${e.kind})"/>`;
  }).join("");

  const nSvg = nodes.map((n) => {
    const p = pos.get(n.stixId)!; const fill = KIND_FILL[n.kind] || "#1b2036", stroke = KIND_STROKE[n.kind] || "#334155";
    const tech = /^T\d/.test(n.techniqueId || "") ? n.techniqueId : "";
    const title = (n.name || "").length > 26 ? n.name.slice(0, 25) + "…" : (n.name || "");
    const startBadge = n.isStart ? `<circle cx="${p.x + NW - 11}" cy="${p.y + 11}" r="5" fill="#22d3ee"><title>start</title></circle>` : "";
    const techLine = tech ? `<text x="${p.x + 10}" y="${p.y + 44}" font-size="10" fill="${n.mapped ? "#7dd3fc" : "#fbbf24"}" font-family="ui-monospace,monospace">${esc(tech)}${n.mapped ? "" : " ⚠"}</text>` : "";
    const op = n.kind === "attack-operator" ? ` [${esc(n.operator || "OP")}]` : "";
    return `<g><rect x="${p.x}" y="${p.y}" width="${NW}" height="${NH}" rx="8" fill="${fill}" stroke="${stroke}" stroke-width="1.4"/>
      ${startBadge}
      <text x="${p.x + 10}" y="${p.y + 20}" font-size="11.5" fill="#e2e8f0" font-weight="600">${esc(title)}${op}</text>
      <text x="${p.x + 10}" y="${p.y + 33}" font-size="9.5" fill="#94a3b8">${esc(n.kind.replace("attack-", ""))}</text>
      ${techLine}</g>`;
  }).join("");

  const markers = Object.entries(EDGE_COLOR).map(([k, c]) =>
    `<marker id="af-ar-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="${c}"/></marker>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="min-width:${Math.min(W, 1400)}px"><defs>${markers}</defs>${eSvg}${nSvg}</svg>`;
}

function renderDash(d: any): void {
  const s = d.summary;
  $("af-ver").textContent = s.catalogueLoaded ? "· ATT&CK catalogue loaded" : "· ATT&CK catalogue not imported (technique names unavailable)";
  $("af-kpis").innerHTML = [
    ["Flows", s.flows], ["Actions", s.actions], ["Techniques", s.techniques], ["Mapped to ATT&CK", `${s.mapped}/${s.techniques}`],
  ].map(([l, v]) => `<div class="af-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
  $("af-body").innerHTML = d.flows.length ? d.flows.map((f: any) => `
    <tr class="af-row ${f.id === SEL ? "sel" : ""}" data-id="${f.id}">
      <td><b>${esc(f.name)}</b>${f.author ? `<div class="muted" style="font-size:11px">${esc(f.author)}</div>` : ""}</td>
      <td><span class="af-scope">${esc(f.scope)}</span></td>
      <td>${f.actions}</td>
      <td><span class="af-chip">${f.mappedTechniques}/${f.techniques} mapped</span></td>
      <td><button class="af-btn ghost danger af-del" data-id="${f.id}">Del</button></td></tr>`).join("")
    : `<tr><td colspan="5" class="af-empty">No flows yet — import an Attack Flow STIX bundle above.</td></tr>`;

  $("af-corpus").innerHTML = CORPUS.map((c) => `<a class="af-corpus-lnk" data-name="${esc(c)}">${esc(c)}</a>`).join(" · ");
}

function renderDetail(d: any): void {
  SEL = d.flow.id;
  const f = d.flow, st = d.stats;
  $("af-detail").style.display = "";
  const refs = (f.externalRefs || []).filter((r: any) => r && (r.url || r.source_name)).slice(0, 6)
    .map((r: any) => r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener" class="af-corpus-lnk" style="color:#7dd3fc">${esc(r.source_name || r.url)}</a>` : esc(r.source_name)).join(" · ");
  $("af-detail").innerHTML = `
    <div class="af-dh"><span style="font-size:18px">🕸️</span><b>${esc(f.name)}</b>
      <span class="af-scope">${esc(f.scope)}</span>
      <span style="margin-left:auto"></span>
      <span class="af-chip">${st.actions} actions</span><span class="af-chip">${st.mapped}/${st.techniques} mapped</span>
      <a class="af-btn ghost" href="/api/attack-flow/${f.id}/navigator" title="Download an ATT&CK Navigator layer for this flow">⬇ Navigator layer</a>
      <button class="af-btn ghost" id="af-close">Close</button></div>
    ${f.description ? `<p class="muted" style="font-size:12.5px;margin:0 0 8px;line-height:1.5">${esc(f.description)}</p>` : ""}
    ${f.author || refs ? `<p class="muted" style="font-size:11.5px;margin:0 0 10px">${f.author ? "By " + esc(f.author) : ""}${refs ? " · " + refs : ""}</p>` : ""}
    <div class="af-legend">
      <span><i style="background:#1e3a5f;border:1px solid #38bdf8"></i>action</span>
      <span><i style="background:#3b2f14;border:1px solid #fbbf24"></i>asset</span>
      <span><i style="background:#3a1f3a;border:1px solid #e879f9"></i>condition</span>
      <span><i style="background:#243b2a;border:1px solid #4ade80"></i>operator</span>
      <span style="color:#4ade80">— on&nbsp;true</span><span style="color:#f87171">— on&nbsp;false</span><span style="color:#a16207">– asset</span>
    </div>
    <div class="af-graph">${graph(d.nodes, d.edges)}</div>
    <div class="af-grid" style="margin-top:14px">
      <div>
        <h3 style="font-size:12.5px;color:#cbd5e1;margin:0 0 6px">ATT&CK technique coverage (${st.mapped}/${st.techniques} known to XORCISM)</h3>
        <ul class="af-cov" style="list-style:none;padding:0;margin:0">
          ${d.coverage.length ? d.coverage.map((c: any) => `<li><span class="tid">${esc(c.id)}</span><span class="nm">${esc(c.name || (c.mapped ? "" : "unknown to XORCISM ATT&CK catalogue"))}</span>${c.count > 1 ? `<span class="af-chip">×${c.count}</span>` : ""}${c.mapped ? "" : `<span class="un">not imported</span>`}</li>`).join("") : `<li class="muted">No ATT&CK techniques referenced.</li>`}
        </ul>
      </div>
      <div>
        <h3 style="font-size:12.5px;color:#cbd5e1;margin:0 0 6px">Actions (${st.actions})</h3>
        <ul class="af-cov" style="list-style:none;padding:0;margin:0;max-height:340px;overflow:auto">
          ${d.nodes.filter((n: any) => n.kind === "attack-action").map((n: any) => `<li><span class="tid">${esc(n.techniqueId || "—")}</span><span class="nm"><b>${esc(n.name)}</b>${n.description ? `<div class="muted" style="font-size:11px">${esc(n.description)}</div>` : ""}</span></li>`).join("")}
        </ul>
      </div>
    </div>`;
}

async function load(): Promise<void> { try { renderDash(await api("/api/attack-flow")); } catch (e) { toast((e as Error).message); } }
async function open(id: number): Promise<void> { try { renderDetail(await api(`/api/attack-flow/${id}`)); renderDash(await api("/api/attack-flow")); } catch (e) { toast((e as Error).message); } }

async function importUrl(url: string, name = ""): Promise<void> {
  const status = $("af-imp-status"); status.textContent = `Importing ${name || url}…`;
  try {
    const r = await post("/api/attack-flow/import", { url });
    status.textContent = `Imported "${r.name}" (${r.actions} actions, ${r.techniques} techniques).`;
    await load(); await open(r.id); $("af-detail").scrollIntoView({ behavior: "smooth" });
  } catch (e) { status.textContent = ""; toast((e as Error).message); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("af-url-btn").addEventListener("click", () => {
    const url = ($("af-url") as HTMLInputElement).value.trim();
    if (!/^https:\/\//i.test(url)) { toast("enter an https URL to a STIX bundle"); return; }
    void importUrl(url);
  });

  $("af-json-btn").addEventListener("click", async () => {
    const raw = ($("af-json") as HTMLTextAreaElement).value.trim();
    if (!raw) { toast("paste a STIX bundle JSON"); return; }
    let bundle: unknown;
    try { bundle = JSON.parse(raw); } catch { toast("invalid JSON"); return; }
    const status = $("af-imp-status"); status.textContent = "Importing…";
    try {
      const r = await post("/api/attack-flow/import", { bundle, source: "pasted" });
      status.textContent = `Imported "${r.name}" (${r.actions} actions, ${r.techniques} techniques).`;
      ($("af-json") as HTMLTextAreaElement).value = "";
      await load(); await open(r.id); $("af-detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { status.textContent = ""; toast((e as Error).message); }
  });

  $("af-corpus").addEventListener("click", (ev) => {
    const a = (ev.target as HTMLElement).closest(".af-corpus-lnk") as HTMLElement | null;
    if (!a || !a.dataset.name) return;
    void importUrl(CORPUS_BASE + encodeURIComponent(a.dataset.name) + ".json", a.dataset.name);
  });

  $("af-body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".af-del") as HTMLElement | null;
    if (del) { ev.stopPropagation(); if (!confirm("Delete this attack flow?")) return;
      try { await api(`/api/attack-flow/${del.dataset.id}`, { method: "DELETE" }); if (SEL === Number(del.dataset.id)) { SEL = null; $("af-detail").style.display = "none"; } await load(); } catch (e) { toast((e as Error).message); } return; }
    const row = t.closest(".af-row") as HTMLElement | null;
    if (row) void open(Number(row.dataset.id));
  });

  $("af-detail").addEventListener("click", (ev) => {
    if ((ev.target as HTMLElement).id === "af-close") { SEL = null; $("af-detail").style.display = "none"; void load(); }
  });
});
