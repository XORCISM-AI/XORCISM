/**
 * threat-model-builder.ts — Visual (graph) tool to CREATE a THREATMODEL (/threat-model-builder).
 * Assemble a model on a live layered canvas — its in-scope assets, STRIDE threats (coloured by
 * category) and the controls that mitigate them — then persist it in one click via the existing
 * threat-model API: POST /api/threat-model, PUT /api/threatmodel-assets,
 * POST /api/threatmodel-threats (one per threat), PUT /api/threat-controls (per threat).
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)); }
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
function translateChrome(): void { document.querySelectorAll<HTMLElement>("[data-t]").forEach((el) => { el.textContent = t(el.getAttribute("data-t")!, (el.textContent || "").trim()); }); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function sendJSON(u: string, body: unknown, method = "POST"): Promise<any> {
  const r = await fetch(u, { method, credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`${method} ${u} → ${r.status}`);
  return r.json();
}

// ── STRIDE palette (category → letter + colour) ──────────────────────────────────
interface Stride { key: string; abbr: string; color: string; }
const STRIDE: Stride[] = [
  { key: "Spoofing", abbr: "S", color: "#60a5fa" },
  { key: "Tampering", abbr: "T", color: "#fbbf24" },
  { key: "Repudiation", abbr: "R", color: "#a78bfa" },
  { key: "Information disclosure", abbr: "I", color: "#22d3ee" },
  { key: "Denial of service", abbr: "D", color: "#fb923c" },
  { key: "Elevation of privilege", abbr: "E", color: "#f87171" },
];
const strideOf = (key: string): Stride => STRIDE.find((s) => s.key === key) ?? { key, abbr: "?", color: "#94a3b8" };
const riskColor = (r: string): string => (/crit/i.test(r) ? "#ef4444" : /high/i.test(r) ? "#fb923c" : /med/i.test(r) ? "#fbbf24" : /low/i.test(r) ? "#22c55e" : "#475569");
const LEVELS = ["Very Low", "Low", "Medium", "High", "Very High"];
const trunc = (s: string, n: number): string => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

// ── model-in-progress state ──────────────────────────────────────────────────────
interface CtlRef { id: number; name: string; }
interface ThreatNode { id: number; title: string; stride: string; likelihood: string; impact: string; controls: CtlRef[]; }
interface AssetRef { id: number; name: string; }
let SEQ = 1;
const state: { threats: ThreatNode[]; assets: AssetRef[] } = { threats: [], assets: [] };
let CONTROLS: { id: number; label: string }[] = [];
let ASSETS: { id: number; label: string }[] = [];

// ── data lookups (existing CONTROL / ASSET names) ────────────────────────────────
async function loadLookups(): Promise<void> {
  try { CONTROLS = (await getJSON("/api/lookup?db=XORCISM&table=CONTROL&idCol=ControlID&labelCol=ControlName")).map((o: any) => ({ id: Number(o.id), label: String(o.label ?? "") })); } catch { /* rights */ }
  try { ASSETS = (await getJSON("/api/lookup?db=XORCISM&table=ASSET&idCol=AssetID&labelCol=AssetName")).map((o: any) => ({ id: Number(o.id), label: String(o.label ?? "") })); } catch { /* rights */ }
  const dl = $("ml-asset-dl"); dl.innerHTML = ASSETS.map((a) => `<option value="${esc(a.label)}">`).join("");
}

// ── mutations ──────────────────────────────────────────────────────────────────
function addThreat(strideKey: string): void {
  state.threats.push({ id: SEQ++, title: `New ${strideKey} threat`, stride: strideKey, likelihood: "Medium", impact: "Medium", controls: [] });
  renderList(); renderGraph();
}
function delThreat(id: number): void { state.threats = state.threats.filter((x) => x.id !== id); renderList(); renderGraph(); }
function addControl(threatId: number, name: string): void {
  const m = CONTROLS.find((c) => c.label.toLowerCase() === name.trim().toLowerCase());
  if (!m) return;
  const th = state.threats.find((x) => x.id === threatId); if (!th) return;
  if (!th.controls.some((c) => c.id === m.id)) th.controls.push({ id: m.id, name: m.label });
  renderList(); renderGraph();
}
function delControl(threatId: number, ctlId: number): void {
  const th = state.threats.find((x) => x.id === threatId); if (!th) return;
  th.controls = th.controls.filter((c) => c.id !== ctlId); renderList(); renderGraph();
}
function addAsset(name: string): void {
  const m = ASSETS.find((a) => a.label.toLowerCase() === name.trim().toLowerCase());
  if (!m || state.assets.some((a) => a.id === m.id)) return;
  state.assets.push({ id: m.id, name: m.label }); renderList(); renderGraph();
}
function delAsset(id: number): void { state.assets = state.assets.filter((a) => a.id !== id); renderList(); renderGraph(); }

// ── left control panel ───────────────────────────────────────────────────────────
function renderPalette(): void {
  $("ml-palette").innerHTML = STRIDE.map((s) =>
    `<button class="sbtn" data-stride="${esc(s.key)}" style="border-color:${s.color};color:${s.color}"><span class="dot" style="background:${s.color}">${s.abbr}</span>${esc(s.key)}</button>`
  ).join("");
  $("ml-palette").querySelectorAll<HTMLButtonElement>("button[data-stride]").forEach((b) => { b.onclick = () => addThreat(b.dataset.stride!); });
  $("ml-legend").innerHTML = STRIDE.map((s) => `<span class="lg"><span class="sw" style="background:${s.color}"></span>${s.abbr} · ${esc(s.key)}</span>`).join("") +
    `<span class="lg"><span class="sw" style="background:#34d399"></span>${t("tmb.lg.asset", "Asset")}</span><span class="lg"><span class="sw" style="background:#7c83fd"></span>${t("tmb.lg.control", "Control")}</span>`;
}

function renderList(): void {
  $("ml-tcount").textContent = state.threats.length ? `(${state.threats.length})` : "";
  const box = $("ml-threats");
  if (!state.threats.length) { box.innerHTML = `<div class="mini">${t("tmb.noThreats", "No threats yet — add one above.")}</div>`; }
  else {
    box.innerHTML = state.threats.map((th) => {
      const s = strideOf(th.stride);
      const lvl = (v: string, sel: string) => `<option ${v === sel ? "selected" : ""}>${v}</option>`;
      const ctls = th.controls.map((c) => `<span class="chip">${esc(trunc(c.name, 26))} <b data-delctl="${th.id}:${c.id}">✕</b></span>`).join("");
      return `<div class="tcard">
        <div class="trow">
          <span class="badge" style="background:${s.color}" title="${esc(th.stride)}">${s.abbr}</span>
          <input class="in" style="flex:1;padding:4px 7px" data-title="${th.id}" value="${esc(th.title)}">
          <button class="x" data-delthreat="${th.id}" title="Remove">✕</button>
        </div>
        <div class="trow" style="margin-bottom:6px">
          <span class="mini">L</span><select class="sel" data-lik="${th.id}">${LEVELS.map((v) => lvl(v, th.likelihood)).join("")}</select>
          <span class="mini">I</span><select class="sel" data-imp="${th.id}">${LEVELS.map((v) => lvl(v, th.impact)).join("")}</select>
        </div>
        <div>
          <input class="in" style="padding:4px 7px" list="ml-ctl-dl" data-ctlinput="${th.id}" placeholder="${esc(t("tmb.addControl", "+ mitigating control (ControlName)…"))}">
          <div>${ctls}</div>
        </div>
      </div>`;
    }).join("") + `<datalist id="ml-ctl-dl">${CONTROLS.map((c) => `<option value="${esc(c.label)}">`).join("")}</datalist>`;

    // wire handlers
    box.querySelectorAll<HTMLInputElement>("input[data-title]").forEach((el) => { el.onchange = () => { const th = state.threats.find((x) => x.id === +el.dataset.title!); if (th) { th.title = el.value; renderGraph(); } }; });
    box.querySelectorAll<HTMLSelectElement>("select[data-lik]").forEach((el) => { el.onchange = () => { const th = state.threats.find((x) => x.id === +el.dataset.lik!); if (th) { th.likelihood = el.value; renderGraph(); } }; });
    box.querySelectorAll<HTMLSelectElement>("select[data-imp]").forEach((el) => { el.onchange = () => { const th = state.threats.find((x) => x.id === +el.dataset.imp!); if (th) { th.impact = el.value; renderGraph(); } }; });
    box.querySelectorAll<HTMLButtonElement>("button[data-delthreat]").forEach((el) => { el.onclick = () => delThreat(+el.dataset.delthreat!); });
    box.querySelectorAll<HTMLElement>("b[data-delctl]").forEach((el) => { el.onclick = () => { const [tid, cid] = el.dataset.delctl!.split(":").map(Number); delControl(tid, cid); }; });
    box.querySelectorAll<HTMLInputElement>("input[data-ctlinput]").forEach((el) => { el.onchange = () => { if (el.value.trim()) { addControl(+el.dataset.ctlinput!, el.value); } }; });
  }
  // assets in scope
  $("ml-assets").innerHTML = state.assets.length
    ? state.assets.map((a) => `<span class="chip" style="border-color:#2f5e46">${esc(trunc(a.name, 30))} <b data-delasset="${a.id}">✕</b></span>`).join("")
    : `<div class="mini">${t("tmb.noAssets", "No assets in scope yet.")}</div>`;
  $("ml-assets").querySelectorAll<HTMLElement>("b[data-delasset]").forEach((el) => { el.onclick = () => delAsset(+el.dataset.delasset!); });
}

// ── live layered SVG graph (assets → model → threats → controls) ─────────────────
function renderGraph(): void {
  const name = ($("ml-name") as HTMLInputElement).value.trim();
  const threats = state.threats, assets = state.assets;
  if (!name && !threats.length && !assets.length) { $("tmb-canvas").innerHTML = `<div class="mini" style="padding:40px;text-align:center">${t("tmb.empty", "Name your model and add STRIDE threats — the graph builds itself here.")}</div>`; return; }

  const colA = 95, colM = 340, colT = 610, colC = 880, W = 980;
  const rowH = 60, pad = 34;
  const rows = Math.max(assets.length, threats.length, threats.reduce((n, th) => n + Math.max(1, th.controls.length), 0), 1);
  const H = Math.max(300, pad * 2 + rows * rowH);
  const mid = H / 2;
  const node = (x: number, y: number, w: number, h: number, fill: string, stroke: string, label: string, sub = "", txt = "#e2e8f0"): string =>
    `<g><rect x="${x}" y="${y - h / 2}" width="${w}" height="${h}" rx="9" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>` +
    `<text x="${x + w / 2}" y="${sub ? y - 2 : y + 4}" text-anchor="middle" fill="${txt}" font-size="12" font-weight="600">${esc(trunc(label, 26))}</text>` +
    (sub ? `<text x="${x + w / 2}" y="${y + 12}" text-anchor="middle" fill="#94a3b8" font-size="10">${esc(trunc(sub, 30))}</text>` : "") + `</g>`;
  const edge = (x1: number, y1: number, x2: number, y2: number, c = "#3a4568"): string => {
    const mx = (x1 + x2) / 2;
    return `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none" stroke="${c}" stroke-width="1.4" opacity="0.8"/>`;
  };

  const parts: string[] = [];
  // model node (center-left)
  const mW = 176, mH = 52;
  // assets column
  assets.forEach((a, i) => {
    const y = assets.length === 1 ? mid : pad + rowH / 2 + i * ((H - pad * 2 - rowH) / Math.max(1, assets.length - 1));
    parts.push(edge(colA + 150, y, colM, mid, "#2f5e46"));
    parts.push(node(colA, y, 150, 40, "#12261c", "#34d399", a.name, "ASSET", "#a7f3d0"));
  });
  // threats + controls
  let cRow = 0;
  threats.forEach((th, i) => {
    const s = strideOf(th.stride);
    const ty = threats.length === 1 ? mid : pad + rowH / 2 + i * ((H - pad * 2 - rowH) / Math.max(1, threats.length - 1));
    parts.push(edge(colM + mW, mid, colT, ty, s.color));
    // threat node
    parts.push(`<g><rect x="${colT}" y="${ty - 22}" width="200" height="44" rx="9" fill="#161a2e" stroke="${riskColor(th.impact)}" stroke-width="2"/>` +
      `<rect x="${colT}" y="${ty - 22}" width="7" height="44" rx="3" fill="${s.color}"/>` +
      `<circle cx="${colT + 22}" cy="${ty}" r="11" fill="${s.color}"/><text x="${colT + 22}" y="${ty + 4}" text-anchor="middle" fill="#0b0d18" font-size="12" font-weight="800">${s.abbr}</text>` +
      `<text x="${colT + 40}" y="${ty - 2}" fill="#e2e8f0" font-size="11.5" font-weight="600">${esc(trunc(th.title, 20))}</text>` +
      `<text x="${colT + 40}" y="${ty + 11}" fill="#94a3b8" font-size="9.5">L:${esc(th.likelihood)} · I:${esc(th.impact)}</text></g>`);
    // controls for this threat
    if (th.controls.length) {
      th.controls.forEach((c) => {
        const cy = pad + rowH / 2 + cRow * ((H - pad * 2 - rowH) / Math.max(1, rows - 1));
        parts.push(edge(colT + 200, ty, colC, cy, "#4b53a8"));
        parts.push(node(colC, cy, 150, 36, "#191d3a", "#7c83fd", c.name, "", "#c7cbff"));
        cRow++;
      });
    }
  });
  // the model node on top
  parts.push(node(colM, mid, mW, mH, "#1a1f3a", "#7c83fd", name || t("tmb.untitled", "Untitled model"), `STRIDE · ${threats.length} threat(s)`, "#e2e8f0"));

  $("tmb-canvas").innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" style="min-width:${W}px;display:block">${parts.join("")}</svg>`;
}

// ── save (create everything via the existing API) ────────────────────────────────
function status(msg: string, kind: "ok" | "err" | "info" = "info"): void {
  const el = $("tmb-status"); el.textContent = msg;
  el.style.color = kind === "ok" ? "#34d399" : kind === "err" ? "#f87171" : "#94a3b8";
}
async function save(): Promise<void> {
  const name = ($("ml-name") as HTMLInputElement).value.trim();
  const owner = ($("ml-owner") as HTMLInputElement).value.trim();
  if (!name) { status(t("tmb.needName", "Give the model a name first."), "err"); ($("ml-name") as HTMLElement).focus(); return; }
  const btn = $("ml-save") as HTMLButtonElement; btn.disabled = true;
  try {
    status(t("tmb.saving", "Creating model…"), "info");
    const { id } = await sendJSON("/api/threat-model", { name, description: "", methodology: "STRIDE", status: "Draft", scope: "", riskLevel: "", owner });
    if (!id) throw new Error("no id");
    if (state.assets.length) await sendJSON("/api/threatmodel-assets", { modelId: id, assetIds: state.assets.map((a) => a.id) }, "PUT");
    for (const th of state.threats) {
      const res = await sendJSON("/api/threatmodel-threats", { modelId: id, threat: { Title: th.title, STRIDECategory: th.stride, Description: "", Likelihood: th.likelihood, Impact: th.impact, RiskScore: th.impact, Status: "Open" } });
      const tid = res.id;
      if (tid && th.controls.length) await sendJSON("/api/threat-controls", { threatId: tid, controlIds: th.controls.map((c) => c.id) }, "PUT");
    }
    status(t("tmb.created", "✓ Threat model created — opening the diagram…"), "ok");
    setTimeout(() => { window.location.href = `/threat-model-graph?id=${id}`; }, 900);
  } catch (e) {
    status(t("tmb.saveErr", "Could not create the model:") + " " + String(e), "err");
    btn.disabled = false;
  }
}

// ── init ─────────────────────────────────────────────────────────────────────────
async function init(): Promise<void> {
  translateChrome();
  renderPalette();
  renderList();
  await loadLookups();
  renderList();
  ($("ml-name") as HTMLInputElement).oninput = () => renderGraph();
  ($("ml-asset-input") as HTMLInputElement).onchange = (e) => { const el = e.target as HTMLInputElement; if (el.value.trim()) { addAsset(el.value); el.value = ""; } };
  ($("ml-save") as HTMLButtonElement).onclick = () => void save();
  renderGraph();
}
void init();
