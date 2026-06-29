/**
 * authz-governance.ts — API Authorization Governance page (/authz-governance).
 * Renders the authZ posture (OWASP API Top 10 / NIST CSF / NIST 800-207), the gateway/PDP/policy
 * inventory, and a vendor-neutral decision evaluator (PEP test harness for OPA / Cedar / AuthZEN).
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function val(id: string): string { return (document.getElementById(id) as HTMLInputElement).value.trim(); }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string, ok = true): void {
  const t = $("toast"); t.textContent = msg; t.className = ok ? "toast-ok" : "toast-err";
  (t as HTMLElement).style.opacity = "1"; setTimeout(() => ((t as HTMLElement).style.opacity = "0"), 2600);
}
const pctColor = (p: number): string => p >= 70 ? "#22c55e" : p >= 40 ? "#f59e0b" : "#ef4444";
const badge = (s: string): string => `<span class="badge b-${esc(s)}">${esc(s)}</span>`;

interface Control { id: string; name: string; status: string; weight: number; evidence: string; recommendation: string; frameworks: { fw: string; ref: string }[]; }
interface Posture { score: number; controls: Control[]; frameworks: { fw: string; label: string; readinessPct: number }[]; counts: { gateways: number; pdps: number; policies: number; ungoverned: number }; evaluatedAt: string; }
interface Inventory { gateways: Record<string, unknown>[]; pdps: Record<string, unknown>[]; policies: Record<string, unknown>[]; tests: Record<string, unknown>[]; }

let pdps: Record<string, unknown>[] = [];
let byPdpTrend: Record<number, { passed: number; total: number; errors: number }[]> = {};

// tiny inline pass-rate sparkline (returns "" when too few points)
function miniSpark(trend: { passed: number; total: number; errors: number }[]): string {
  if (!trend || trend.length < 2) return "";
  const W = 90, H = 18, n = trend.length;
  const rate = (t: { passed: number; total: number; errors: number }): number => { const e = t.total - t.errors; return e > 0 ? (t.passed / e) * 100 : 0; };
  const pts = trend.map((t, i) => `${(i / (n - 1)) * W},${(H - (rate(t) / 100) * H).toFixed(1)}`).join(" ");
  const last = rate(trend[trend.length - 1]);
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:90px;height:18px;vertical-align:middle"><polyline points="${pts}" fill="none" stroke="${pctColor(last)}" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`;
}

interface SuiteRun { at: string; total: number; passed: number; failed: number; errors: number; findings: number; }
function renderSuiteTrend(trend: SuiteRun[]): void {
  const host = document.getElementById("suite-trend"); if (!host) return;
  if (!trend || trend.length < 2) { host.innerHTML = ""; return; }
  const W = 220, H = 34, n = trend.length, evald = trend.filter((t) => t.total > t.errors);
  const rate = (t: SuiteRun): number => { const e = t.total - t.errors; return e > 0 ? Math.round((t.passed / e) * 100) : 0; };
  const pts = trend.map((t, i) => `${(i / (n - 1)) * W},${(H - (rate(t) / 100) * H).toFixed(1)}`).join(" ");
  const last = evald.length ? rate(evald[evald.length - 1]) : 0;
  host.innerHTML = `<div class="muted" style="font-size:11px;margin-top:10px">BOLA/BFLA pass-rate trend (${n} runs)
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:220px;height:34px;vertical-align:middle;margin-left:6px"><polyline points="${pts}" fill="none" stroke="${pctColor(last)}" stroke-width="2" vector-effect="non-scaling-stroke"/></svg></div>`;
}

async function load(): Promise<void> {
  let d: { inventory: Inventory; posture: Posture; suiteTrend?: SuiteRun[]; suiteTrendsByPdp?: Record<number, { passed: number; total: number; errors: number }[]> };
  try { const r = await fetch("/api/authz-governance"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("az-posture").innerHTML = `<div class="muted" style="padding:24px;text-align:center">Failed to load: ${esc(e)}</div>`; return; }
  byPdpTrend = d.suiteTrendsByPdp || {};
  pdps = d.inventory.pdps;
  renderPosture(d.posture);
  renderTopology(d.inventory);
  renderInventory(d.inventory);
  renderSuiteTrend(d.suiteTrend || []);
  const sel = $("gw-pdp") as HTMLSelectElement;
  sel.innerHTML = `<option value="">— none —</option>` + pdps.map((p) => `<option value="${p.PdpID}">${esc(p.Name)} (${esc(p.Engine)})</option>`).join("");
}

function renderPosture(p: Posture): void {
  const order: Record<string, number> = { gap: 0, partial: 1, proven: 2, na: 3 };
  const controls = p.controls.slice().sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
  $("az-posture").innerHTML = `
    <div class="az-hero">
      <span class="az-score" style="color:${pctColor(p.score)}">${p.score}%</span>
      <div style="flex:1"><div class="az-bar"><i style="width:${p.score}%;background:${pctColor(p.score)}"></i></div>
        <div class="muted" style="font-size:12px;margin-top:4px">Authorization posture · evaluated ${esc(p.evaluatedAt)}</div></div>
    </div>
    <div class="chips">${p.frameworks.map((f) => `<span class="chip">${esc(f.label)} <b style="color:${pctColor(f.readinessPct)}">${f.readinessPct}%</b></span>`).join("")}</div>
    <div class="counts">
      <span class="pill p-ok">${p.counts.gateways} gateway(s)</span>
      <span class="pill p-ok">${p.counts.pdps} PDP(s)</span>
      <span class="pill p-ok">${p.counts.policies} policy(ies)</span>
      <span class="pill ${p.counts.ungoverned ? "p-bad" : "p-na"}">${p.counts.ungoverned} ungoverned</span>
    </div>
    ${controls.map((c) => `<div class="ctl">
      <div class="top"><span class="nm">${esc(c.name)}</span><span class="refs">${c.frameworks.map((f) => esc(f.fw === "owaspapi" ? "OWASP" : f.fw === "nistcsf" ? "CSF" : "ZT") + " " + esc(f.ref)).join(" · ")}</span>${badge(c.status)}</div>
      <div class="ev">${esc(c.evidence)}</div>
      ${c.status === "proven" ? "" : `<div class="rec">↳ ${esc(c.recommendation)}</div>`}
    </div>`).join("")}`;
}

function yn(v: unknown): string { return v == null ? "<span class='muted'>?</span>" : (v === 1 || v === "1" ? "✓" : "✗"); }
function renderInventory(inv: Inventory): void {
  const del = (kind: string, id: unknown): string => `<a href="#" data-del="${kind}" data-id="${id}" style="color:#f87171">✕</a>`;
  const gwT = inv.gateways.length ? `<table class="az"><thead><tr><th>Gateway</th><th>Type</th><th>AuthN</th><th>AuthZ</th><th>PDP</th><th>Deny-dflt</th><th>Log</th><th></th></tr></thead><tbody>${inv.gateways.map((g) => `<tr><td>${esc(g.Name)}</td><td>${esc(g.GatewayType)}</td><td>${esc(g.AuthnMethods || "—")}</td><td>${esc(g.AuthzModel)}</td><td>${g.PdpID ? esc((pdps.find((p) => p.PdpID === g.PdpID) || {}).Name || g.PdpID) : "<span class='muted'>none</span>"}</td><td>${yn(g.DenyByDefault)}</td><td>${yn(g.DecisionLogging)}</td><td>${del("gateway", g.GatewayID)}</td></tr>`).join("")}</tbody></table>` : `<div class="muted" style="margin-bottom:10px">No gateways yet.</div>`;
  const pdpT = inv.pdps.length ? `<table class="az"><thead><tr><th>PDP</th><th>Engine</th><th>Endpoint</th><th>AuthZEN</th><th>Status</th><th>Pass-rate</th><th></th></tr></thead><tbody>${inv.pdps.map((p) => `<tr><td>${esc(p.Name)}</td><td>${esc(p.Engine)}</td><td class="muted">${esc(p.Endpoint || "—")}</td><td>${yn(p.AuthzenCompliant)}</td><td>${esc(p.Status)}</td><td>${miniSpark(byPdpTrend[Number(p.PdpID)] || [])}</td><td>${del("pdp", p.PdpID)}</td></tr>`).join("")}</tbody></table>` : `<div class="muted" style="margin-bottom:10px">No PDPs yet.</div>`;
  const polT = inv.policies.length ? `<table class="az"><thead><tr><th>Policy</th><th>Engine</th><th>Default-deny</th><th>Versioned</th><th>Tested</th><th></th></tr></thead><tbody>${inv.policies.map((p) => `<tr><td>${esc(p.Name)}</td><td>${esc(p.Engine)}</td><td>${yn(p.DefaultDeny)}</td><td>${yn(p.Versioned)}</td><td>${yn(p.Tested)}</td><td>${del("policy", p.PolicyID)}</td></tr>`).join("")}</tbody></table>` : `<div class="muted" style="margin-bottom:10px">No policies yet.</div>`;
  $("az-inventory").innerHTML = `<div class="sect-h" style="margin-top:6px">Gateways (PEP)</div>${gwT}<div class="sect-h">Policy decision points (PDP)</div>${pdpT}<div class="sect-h">Policies</div>${polT}`;
  $("az-inventory").querySelectorAll<HTMLAnchorElement>("a[data-del]").forEach((a) => a.onclick = async (e) => {
    e.preventDefault(); if (!confirm("Delete this item?")) return;
    await fetch(`/api/authz-governance/${a.dataset.del}/${a.dataset.id}`, { method: "DELETE" });
    toast("Deleted"); void load();
  });
}

// Layered topology: gateways (PEP) → PDPs → policies. Edges from PdpID. Ungoverned PEPs in red.
function renderTopology(inv: Inventory): void {
  const host = document.getElementById("az-topology"); if (!host) return;
  const gws = inv.gateways, ps = inv.pdps, pols = inv.policies;
  if (!gws.length && !ps.length) { host.innerHTML = `<div class="muted" style="padding:8px">Nothing to map yet — register gateways and PDPs.</div>`; return; }
  const colX = [40, 320, 600], boxW = 200, boxH = 30, gap = 14, top = 30;
  const yOf = (i: number): number => top + i * (boxH + gap);
  const rows = Math.max(gws.length, ps.length, pols.length, 1);
  const H = top + rows * (boxH + gap) + 10, W = 820;
  const pdpIndex = new Map<number, number>(); ps.forEach((p, i) => pdpIndex.set(Number(p.PdpID), i));
  const cx = (col: number, side: "l" | "r"): number => colX[col] + (side === "r" ? boxW : 0);
  const edges: string[] = [];
  gws.forEach((g, gi) => { if (g.PdpID != null && pdpIndex.has(Number(g.PdpID))) { const pj = pdpIndex.get(Number(g.PdpID))!; edges.push(`<path d="M${cx(0, "r")},${yOf(gi) + boxH / 2} C${(colX[1] + colX[0] + boxW) / 2},${yOf(gi) + boxH / 2} ${(colX[1] + colX[0] + boxW) / 2},${yOf(pj) + boxH / 2} ${cx(1, "l")},${yOf(pj) + boxH / 2}" fill="none" stroke="#64748b" stroke-width="1.5"/>`); } });
  pols.forEach((po, qi) => { if (po.PdpID != null && pdpIndex.has(Number(po.PdpID))) { const pj = pdpIndex.get(Number(po.PdpID))!; edges.push(`<path d="M${cx(1, "r")},${yOf(pj) + boxH / 2} C${(colX[2] + colX[1] + boxW) / 2},${yOf(pj) + boxH / 2} ${(colX[2] + colX[1] + boxW) / 2},${yOf(qi) + boxH / 2} ${cx(2, "l")},${yOf(qi) + boxH / 2}" fill="none" stroke="#3b4663" stroke-width="1.2" stroke-dasharray="3,3"/>`); } });
  const box = (col: number, i: number, label: string, sub: string, color: string): string =>
    `<g><rect x="${colX[col]}" y="${yOf(i)}" width="${boxW}" height="${boxH}" rx="6" fill="#13162a" stroke="${color}"/>
      <text x="${colX[col] + 8}" y="${yOf(i) + 13}" fill="#e2e8f0" font-size="11" font-weight="600">${esc(label).slice(0, 28)}</text>
      <text x="${colX[col] + 8}" y="${yOf(i) + 25}" fill="#64748b" font-size="9">${esc(sub).slice(0, 32)}</text></g>`;
  const gwBoxes = gws.map((g, i) => box(0, i, String(g.Name), String(g.GatewayType || ""), g.PdpID ? "#34d399" : "#ef4444")).join("");
  const pdpBoxes = ps.map((p, i) => box(1, i, String(p.Name), String(p.Engine || ""), "#a78bfa")).join("");
  const polBoxes = pols.map((po, i) => box(2, i, String(po.Name), String(po.Engine || ""), "#38bdf8")).join("");
  const hdr = (col: number, t: string): string => `<text x="${colX[col]}" y="18" fill="#94a3b8" font-size="11" font-weight="700">${t}</text>`;
  host.innerHTML = `<div style="overflow-x:auto;border:1px solid #2d3250;border-radius:10px;background:#0f1117;padding:6px">
    <svg viewBox="0 0 ${W} ${H}" style="width:100%;min-width:640px;height:${H}px">
      ${hdr(0, "Gateways (PEP)")}${hdr(1, "Decision points (PDP)")}${hdr(2, "Policies")}
      ${edges.join("")}${gwBoxes}${pdpBoxes}${polBoxes}
    </svg></div>
    <div class="muted" style="font-size:11px;margin-top:4px">Green = governed PEP · <span style="color:#ef4444">red = ungoverned ingress</span> · dashed = policy attached to a PDP.</div>`;
}

async function post(path: string, body: Record<string, unknown>): Promise<Record<string, unknown> | null> {
  const r = await fetch(`/api/authz-governance/${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({})); if (!r.ok) { toast(String(j.error || `HTTP ${r.status}`), false); return null; }
  return j;
}

async function evaluate(): Promise<void> {
  let context: unknown = {};
  const cx = val("ev-context"); if (cx) { try { context = JSON.parse(cx); } catch { toast("Context must be valid JSON", false); return; } }
  const out = await post("evaluate", {
    engine: val("ev-engine"), subject: val("ev-subject"), action: val("ev-action"), resource: val("ev-resource"),
    context, expected: val("ev-expected") || undefined, endpoint: val("ev-endpoint") || undefined,
    live: (document.getElementById("ev-live") as HTMLInputElement).checked,
  });
  if (!out) return;
  const dec = String(out.decision);
  const col = dec === "allow" ? "#6ee7b7" : dec === "deny" ? "#fecaca" : "#94a3b8";
  const passTxt = out.pass == null ? "" : out.pass === 1 ? ` <span style="color:#6ee7b7">✓ matches expected</span>` : ` <span style="color:#fecaca">✗ differs from expected</span>`;
  $("ev-out").innerHTML = `<div style="margin-top:10px"><b>Decision:</b> <span style="color:${col};font-weight:700">${esc(dec)}</span>${passTxt} <span class="muted" style="font-size:11px">— ${esc(out.note)}</span></div>
    <div class="muted" style="font-size:11px;margin:8px 0 3px">Request payload sent to the ${esc(out.engine)} PDP:</div>
    <pre class="payload">${esc(JSON.stringify(out.request, null, 2))}</pre>`;
  void load();
}

async function runSuite(): Promise<void> {
  const out = await post("test-suite", {
    engine: val("ev-engine"), endpoint: val("ev-endpoint") || undefined,
    live: (document.getElementById("ev-live") as HTMLInputElement).checked,
  });
  if (!out) return;
  const r = out as unknown as { engine: string; total: number; passed: number; failed: number; errors: number; byCategory: Record<string, { total: number; failed: number }>; findings: { category: string; ref: string; name: string; severity: string }[]; results: { name: string; category: string; decision: string; expected: string; pass: boolean | null }[] };
  const row = (t: { name: string; category: string; decision: string; expected: string; pass: boolean | null }): string => {
    const c = t.pass === null ? "#94a3b8" : t.pass ? "#6ee7b7" : "#fecaca";
    const mark = t.pass === null ? "—" : t.pass ? "✓ deny" : "✗ ALLOWED";
    return `<tr><td>${esc(t.category)}</td><td>${esc(t.name)}</td><td style="color:${c};font-weight:600">${mark}</td></tr>`;
  };
  const findingBanner = r.findings.length
    ? `<div class="pill p-bad" style="display:inline-block;margin-bottom:8px">⚠ ${r.findings.length} broken-authorization finding(s): ${r.findings.map((f) => f.ref).filter((v, i, a) => a.indexOf(v) === i).join(", ")}</div>`
    : r.errors === r.total ? `<div class="pill p-na" style="display:inline-block;margin-bottom:8px">Not evaluated — enable “Call PDP live” with a reachable endpoint to get decisions.</div>`
    : `<div class="pill p-ok" style="display:inline-block;margin-bottom:8px">✓ No broken-authorization findings — every negative test was denied.</div>`;
  $("suite-out").innerHTML = `<div style="margin-top:12px"><b>BOLA/BFLA test battery</b> — ${r.passed} passed · ${r.failed} failed · ${r.errors} not evaluated (of ${r.total})</div>
    ${findingBanner}
    <table class="az"><thead><tr><th>OWASP</th><th>Negative test (must deny)</th><th>Result</th></tr></thead><tbody>${r.results.map(row).join("")}</tbody></table>`;
  void load();
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n(); void load();
  $("ev-run").onclick = () => void evaluate();
  $("ev-suite").onclick = () => void runSuite();
  $("gw-add").onclick = async () => {
    if (!val("gw-name")) return toast("Name required", false);
    const r = await post("gateway", { name: val("gw-name"), gatewayType: val("gw-type"), authzModel: val("gw-model"),
      authnMethods: val("gw-authn"), pdpId: val("gw-pdp"), environment: val("gw-env"),
      denyByDefault: val("gw-deny"), decisionLogging: val("gw-log") });
    if (r) { toast("Gateway added"); (document.getElementById("gw-name") as HTMLInputElement).value = ""; void load(); }
  };
  $("pdp-add").onclick = async () => {
    if (!val("pdp-name")) return toast("Name required", false);
    const r = await post("pdp", { name: val("pdp-name"), engine: val("pdp-engine"), endpoint: val("pdp-endpoint"),
      status: val("pdp-status"), authzenCompliant: (document.getElementById("pdp-authzen") as HTMLInputElement).checked,
      regressionEnabled: (document.getElementById("pdp-regression") as HTMLInputElement).checked });
    if (r) { toast("PDP added"); (document.getElementById("pdp-name") as HTMLInputElement).value = ""; void load(); }
  };
  $("pol-add").onclick = async () => {
    if (!val("pol-name")) return toast("Name required", false);
    const vt = val("pol-vt");
    const r = await post("policy", { name: val("pol-name"), engine: val("pol-engine"), defaultDeny: val("pol-deny"),
      versioned: vt === "vt" || vt === "v" ? "1" : vt === "0" ? "0" : "", tested: vt === "vt" ? "1" : vt === "0" || vt === "v" ? "0" : "" });
    if (r) { toast("Policy added"); (document.getElementById("pol-name") as HTMLInputElement).value = ""; void load(); }
  };
});
