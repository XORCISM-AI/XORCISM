/**
 * threat-model-graph.ts — Graphical view of a THREATMODEL (/threat-model-graph?id=<id>).
 * A deterministic layered SVG diagram: in-scope assets → the model → its STRIDE threats
 * (coloured by category, bordered by risk, marked by status) → the controls that mitigate them.
 * Data from /api/threat-model/:id/graph; model picker from /api/threat-model/dashboard.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)); }
// i18n: session-ui exposes the translator as window.t; fall back to the English default.
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
function translateChrome(): void { document.querySelectorAll<HTMLElement>("[data-t]").forEach((el) => { el.textContent = t(el.getAttribute("data-t")!, (el.textContent || "").trim()); }); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }

interface Ctl { id: number; name: string; status: string }
interface Threat { id: number; title: string; stride: string; likelihood: string; impact: string; risk: string; status: string; controls: Ctl[] }
interface Graph { model: Record<string, any>; assets: { id: number; name: string }[]; threats: Threat[] }

let CURRENT = 0;

// STRIDE category → colour (match on keyword; falls back to grey).
function strideColor(cat: string): string {
  const c = (cat || "").toLowerCase();
  if (/spoof/.test(c)) return "#60a5fa";
  if (/tamper/.test(c)) return "#fbbf24";
  if (/repudiat/.test(c)) return "#a78bfa";
  if (/disclos|information/.test(c)) return "#22d3ee";
  if (/denial|dos|availab/.test(c)) return "#fb923c";
  if (/elevat|privilege/.test(c)) return "#f87171";
  return "#94a3b8";
}
const strideAbbr = (cat: string): string => {
  const c = (cat || "").toLowerCase();
  if (/spoof/.test(c)) return "S"; if (/tamper/.test(c)) return "T"; if (/repudiat/.test(c)) return "R";
  if (/disclos|information/.test(c)) return "I"; if (/denial|dos|availab/.test(c)) return "D"; if (/elevat|privilege/.test(c)) return "E";
  return "?";
};
function riskColor(risk: string): string {
  const r = (risk || "").toLowerCase();
  if (/crit/.test(r)) return "#ef4444"; if (/high|élev|elev/.test(r)) return "#fb923c";
  if (/med|moy/.test(r)) return "#fbbf24"; if (/low|faible/.test(r)) return "#22c55e";
  return "#475569";
}
const mitigated = (s: string): boolean => /mitigat|closed|implement|resolved|clos|trait/i.test(s || "");
const trunc = (s: string, n: number): string => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

async function loadPicker(): Promise<{ id: number; name: string }[]> {
  try { const d = await getJSON("/api/threat-model/dashboard"); return (d.models || []).map((m: any) => ({ id: m.id, name: m.name })); }
  catch { return []; }
}

async function render(): Promise<void> {
  let g: Graph;
  try { g = await getJSON(`/api/threat-model/${CURRENT}/graph`); }
  catch (e) { $("tmg-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(String(e))}</div>`; return; }
  ($("tmg-open") as HTMLButtonElement).onclick = () => window.open(`/?db=XORCISM&table=THREATMODEL&editCol=ThreatModelID&editVal=${CURRENT}`, "_blank");
  $("tmg-body").innerHTML = svgFor(g);
}

// ── Deterministic layered layout ────────────────────────────────────────────────
function svgFor(g: Graph): string {
  const M = 24;                      // outer margin
  const aX = M, aW = 190, aH = 42, aGap = 12;
  const mX = aX + aW + 90, mW = 210, mH = 92;
  const tX = mX + mW + 90, tW = 250;
  const cX = tX + tW + 70, cW = 190, cH = 30, cGap = 6;

  // Threat blocks: each block tall enough for its controls.
  let ty = M; const tPos: { top: number; h: number; cy: number }[] = [];
  for (const th of g.threats) {
    const h = Math.max(60, th.controls.length * (cH + cGap) + 6);
    tPos.push({ top: ty, h, cy: ty + h / 2 });
    ty += h + 16;
  }
  const threatsBottom = g.threats.length ? ty : M;
  const assetsBottom = M + g.assets.length * (aH + aGap);
  const H = Math.max(threatsBottom, assetsBottom, mX ? 200 : 200) + M;
  const W = cX + cW + M;
  const midY = (Math.max(threatsBottom, assetsBottom) + M) / 2;
  const modelTop = Math.max(M, midY - mH / 2);
  const modelCy = modelTop + mH / 2;

  const parts: string[] = [];
  const line = (x1: number, y1: number, x2: number, y2: number, stroke: string, dash = "", w = 1.5): string =>
    `<path d="M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}" fill="none" stroke="${stroke}" stroke-width="${w}"${dash ? ` stroke-dasharray="${dash}"` : ""}/>`;

  // Edges first (under the nodes).
  g.assets.forEach((_, i) => { const y = M + i * (aH + aGap) + aH / 2; parts.push(line(aX + aW, y, mX, modelCy, "#3b4663")); });
  g.threats.forEach((th, i) => parts.push(line(mX + mW, modelCy, tX, tPos[i].cy, strideColor(th.stride) + "88")));
  g.threats.forEach((th, i) => {
    th.controls.forEach((_, ci) => { const cy = tPos[i].top + 6 + ci * (cH + cGap) + cH / 2; parts.push(line(tX + tW, tPos[i].cy, cX, cy, "#16a34a", "4,3", 1.3)); });
  });

  // Column headers.
  const hdr = (x: number, txt: string): string => `<text x="${x}" y="16" fill="#64748b" font-size="11" font-weight="700" letter-spacing=".4">${esc(txt)}</text>`;
  parts.push(hdr(aX, t("tmg.hAssets", "IN SCOPE")));
  parts.push(hdr(mX, t("tmg.hModel", "MODEL")));
  parts.push(hdr(tX, t("tmg.hThreats", "STRIDE THREATS")));
  if (g.threats.some((th) => th.controls.length)) parts.push(hdr(cX, t("tmg.hControls", "MITIGATIONS")));

  // Assets.
  g.assets.forEach((a, i) => {
    const y = M + i * (aH + aGap);
    parts.push(`<a class="tmg-node" href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${a.id}" target="_blank">
      <rect x="${aX}" y="${y}" width="${aW}" height="${aH}" rx="8" fill="#13162a" stroke="#2d3250"/>
      <text x="${aX + 12}" y="${y + 18}" fill="#e2e8f0" font-size="12" font-weight="600">${esc(trunc(a.name, 24))}</text>
      <text x="${aX + 12}" y="${y + 33}" fill="#64748b" font-size="10">${t("tmg.asset", "asset")} #${a.id}</text></a>`);
  });
  if (!g.assets.length) parts.push(`<text x="${aX}" y="${M + 26}" fill="#64748b" font-size="12">${esc(t("tmg.noAssets", "No assets in scope"))}</text>`);

  // Model.
  const risk = String(g.model.risk || "");
  parts.push(`<a class="tmg-node" href="/?db=XORCISM&table=THREATMODEL&editCol=ThreatModelID&editVal=${g.model.id}" target="_blank">
    <rect x="${mX}" y="${modelTop}" width="${mW}" height="${mH}" rx="12" fill="#161a2e" stroke="#7c83fd" stroke-width="1.5"/>
    <text x="${mX + 14}" y="${modelTop + 26}" fill="#e7ebf3" font-size="14" font-weight="700">${esc(trunc(String(g.model.name || "Model"), 24))}</text>
    <text x="${mX + 14}" y="${modelTop + 45}" fill="#a5b4fc" font-size="11">${esc(trunc(String(g.model.methodology || "STRIDE"), 30))}</text>
    <text x="${mX + 14}" y="${modelTop + 63}" fill="#94a3b8" font-size="10.5">${esc(trunc(String(g.model.owner || ""), 30))}</text>
    ${risk ? `<rect x="${mX + 14}" y="${modelTop + mH - 24}" width="${8 + risk.length * 6.4}" height="16" rx="8" fill="${riskColor(risk)}22" stroke="${riskColor(risk)}"/><text x="${mX + 20}" y="${modelTop + mH - 12}" fill="${riskColor(risk)}" font-size="10" font-weight="700">${esc(risk)}</text>` : ""}
  </a>`);

  // Threats + their controls.
  g.threats.forEach((th, i) => {
    const p = tPos[i]; const sc = strideColor(th.stride); const rc = riskColor(th.risk);
    const boxH = 56; const boxTop = p.cy - boxH / 2;
    const mit = mitigated(th.status);
    parts.push(`<a class="tmg-node" href="/?db=XORCISM&table=THREATMODELTHREAT&editCol=ThreatModelThreatID&editVal=${th.id}" target="_blank">
      <rect x="${tX}" y="${boxTop}" width="${tW}" height="${boxH}" rx="9" fill="#13162a" stroke="${rc}" stroke-width="1.6"/>
      <rect x="${tX}" y="${boxTop}" width="6" height="${boxH}" rx="3" fill="${sc}"/>
      <circle cx="${tX + 22}" cy="${boxTop + 20}" r="9" fill="${sc}22" stroke="${sc}"/>
      <text x="${tX + 22}" y="${boxTop + 24}" fill="${sc}" font-size="11" font-weight="800" text-anchor="middle">${strideAbbr(th.stride)}</text>
      <text x="${tX + 38}" y="${boxTop + 20}" fill="#e2e8f0" font-size="12" font-weight="600">${esc(trunc(th.title, 26))}</text>
      <text x="${tX + 38}" y="${boxTop + 36}" fill="#94a3b8" font-size="10">${esc(trunc(th.stride || "—", 22))}</text>
      <text x="${tX + tW - 10}" y="${boxTop + 20}" fill="${rc}" font-size="10" font-weight="700" text-anchor="end">${esc(th.risk || "")}</text>
      <text x="${tX + tW - 10}" y="${boxTop + 36}" fill="${mit ? "#34d399" : "#fbbf24"}" font-size="10" text-anchor="end">${mit ? "✓ " + esc(trunc(th.status, 14)) : esc(trunc(th.status || t("tmg.open", "open"), 14))}</text>
    </a>`);
    th.controls.forEach((c, ci) => {
      const cy = p.top + 6 + ci * (cH + cGap);
      parts.push(`<a class="tmg-node" href="/?db=XORCISM&table=CONTROL&editCol=ControlID&editVal=${c.id}" target="_blank">
        <rect x="${cX}" y="${cy}" width="${cW}" height="${cH}" rx="7" fill="#0f1f17" stroke="#16a34a"/>
        <text x="${cX + 10}" y="${cy + 19}" fill="#bbf7d0" font-size="11">${esc(trunc(c.name, 24))}</text></a>`);
    });
  });
  if (!g.threats.length) parts.push(`<text x="${tX}" y="${M + 26}" fill="#64748b" font-size="12">${esc(t("tmg.noThreats", "No threats recorded"))}</text>`);

  const legend = `<div class="legend">
    <span class="lg"><span class="sw" style="background:#60a5fa"></span>Spoofing</span>
    <span class="lg"><span class="sw" style="background:#fbbf24"></span>Tampering</span>
    <span class="lg"><span class="sw" style="background:#a78bfa"></span>Repudiation</span>
    <span class="lg"><span class="sw" style="background:#22d3ee"></span>Info disclosure</span>
    <span class="lg"><span class="sw" style="background:#fb923c"></span>DoS</span>
    <span class="lg"><span class="sw" style="background:#f87171"></span>Elevation</span>
    <span class="lg" style="margin-left:8px"><span class="sw" style="border:2px solid #ef4444;background:transparent"></span>${t("tmg.risk", "risk = border")}</span>
    <span class="lg"><span class="sw" style="border:1px dashed #16a34a;background:transparent"></span>${t("tmg.mitig", "mitigation")}</span>
  </div>`;
  return `${legend}<div id="tmg-canvas"><svg viewBox="0 0 ${W} ${H}" style="width:100%;min-width:${Math.min(W, 1180)}px;height:auto;display:block;padding:8px">${parts.join("")}</svg></div>`;
}

document.addEventListener("DOMContentLoaded", async () => {
  translateChrome();
  const models = await loadPicker();
  const sel = $("tmg-pick") as HTMLSelectElement;
  sel.innerHTML = models.map((m) => `<option value="${m.id}">${esc(m.name)} (#${m.id})</option>`).join("") || `<option value="">${esc(t("tmg.none", "no models"))}</option>`;
  const urlId = Number(new URLSearchParams(location.search).get("id"));
  CURRENT = urlId && models.some((m) => m.id === urlId) ? urlId : (models[0]?.id || urlId || 0);
  if (CURRENT) sel.value = String(CURRENT);
  sel.onchange = () => { CURRENT = Number(sel.value); history.replaceState(null, "", `?id=${CURRENT}`); void render(); };
  if (CURRENT) void render();
  else $("tmg-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${esc(t("tmg.empty", "No threat model to display. Create one from Threat Models."))}</div>`;
});
