/**
 * cra-compliance.ts — EU Cyber Resilience Act conformity cockpit (/cra-compliance).
 * Products with digital elements, the Annex I requirement matrix, the release-readiness gate and
 * conformity scoring (CRANE-style) over XORCISM's SBOM / vulnerability / evidence data.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function val(id: string): string { return (document.getElementById(id) as HTMLInputElement).value.trim(); }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string, ok = true): void { const t = $("toast"); t.textContent = msg; t.className = ok ? "toast-ok" : "toast-err"; (t as HTMLElement).style.opacity = "1"; setTimeout(() => ((t as HTMLElement).style.opacity = "0"), 2600); }
const pctColor = (p: number): string => p >= 80 ? "#22c55e" : p >= 50 ? "#f59e0b" : "#ef4444";
const supPill = (s: string): string => `<span class="pill ${s === "active" ? "p-ok" : s === "expiring" ? "p-warn" : s === "expired" ? "p-bad" : "p-na"}">${esc(s)}</span>`;

interface DashProduct { id: number; name: string; class: string; annexIPct: number; supportStatus: string; gateReady: boolean; gatePassed: number; gateTotal: number; releases: number; }
interface Dashboard { products: DashProduct[]; summary: { products: number; conformant: number; avgConformity: number; supportExpiring: number; supportExpired: number; byClass: Record<string, number> }; }

let selected: number | null = null;

async function load(): Promise<void> {
  let d: { dashboard: Dashboard };
  try { const r = await fetch("/api/cra"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cra-products").innerHTML = `<div class="muted">Failed to load: ${esc(e)}</div>`; return; }
  const s = d.dashboard.summary;
  $("cra-kpis").innerHTML = [
    `<div class="kpi"><div class="v">${s.products}</div><div class="l">Products (PDE)</div></div>`,
    `<div class="kpi"><div class="v" style="color:${pctColor(s.conformant && s.products ? 100 : 0)}">${s.conformant}/${s.products}</div><div class="l">Release-gate ready</div></div>`,
    `<div class="kpi"><div class="v" style="color:${pctColor(s.avgConformity)}">${s.avgConformity}%</div><div class="l">Avg Annex I conformity</div></div>`,
    `<div class="kpi"><div class="v" style="color:${s.supportExpiring ? "#fcd34d" : "#64748b"}">${s.supportExpiring}</div><div class="l">Support expiring</div></div>`,
    `<div class="kpi"><div class="v" style="color:${s.supportExpired ? "#f87171" : "#64748b"}">${s.supportExpired}</div><div class="l">Support expired</div></div>`,
  ].join("");
  $("cra-products").innerHTML = d.dashboard.products.length ? `<table class="cra"><thead><tr><th>Product</th><th>Class</th><th>Annex I</th><th>Support</th><th>Release gate</th><th>Releases</th></tr></thead><tbody>${d.dashboard.products.map((p) => `<tr class="clk" data-id="${p.id}"><td>${esc(p.name)}</td><td>${esc(p.class)}</td><td><span class="bar"><i style="width:${p.annexIPct}%;background:${pctColor(p.annexIPct)}"></i></span> ${p.annexIPct}%</td><td>${supPill(p.supportStatus)}</td><td><span class="pill ${p.gateReady ? "p-ok" : "p-bad"}">${p.gatePassed}/${p.gateTotal} ${p.gateReady ? "ready" : "blocked"}</span></td><td>${p.releases}</td></tr>`).join("")}</tbody></table>` : `<div class="muted">No products yet — register one above.</div>`;
  $("cra-products").querySelectorAll<HTMLTableRowElement>("tr.clk").forEach((tr) => tr.onclick = () => { selected = Number(tr.dataset.id); void detail(selected); });
  if (selected != null) void detail(selected);
}

interface Conformity {
  product: Record<string, unknown>; annexIPct: number; partI: { met: number; total: number }; partII: { met: number; total: number };
  requirements: { id: number; ref: string; title: string; part: string; status: string; evidence: string }[];
  releases: { id: number; version: string; date: string; status: string; sbom: boolean }[];
  gate: { ready: boolean; passed: number; total: number; items: { id: string; label: string; status: string; detail: string; ref: string }[] };
  supportStatus: string; requiredRoute: string;
}

async function detail(id: number): Promise<void> {
  let c: Conformity;
  try { const r = await fetch(`/api/cra/product/${id}`); if (!r.ok) throw new Error(`HTTP ${r.status}`); c = await r.json(); }
  catch (e) { $("cra-detail").innerHTML = `<div class="muted">${esc(e)}</div>`; return; }
  const gmark = (s: string): string => s === "pass" ? "✓" : s === "fail" ? "✗" : "?";
  const gcol = (s: string): string => s === "pass" ? "#6ee7b7" : s === "fail" ? "#fecaca" : "#94a3b8";
  const opt = (sel: string): string => ["met", "partial", "gap", "na"].map((o) => `<option ${o === sel ? "selected" : ""}>${o}</option>`).join("");
  const parts: Record<string, string> = { product: "Annex I Part I — product security", "vuln-handling": "Annex I Part II — vulnerability handling", conformity: "Conformity" };
  let reqHtml = "";
  for (const part of ["product", "vuln-handling", "conformity"]) {
    const rs = c.requirements.filter((r) => r.part === part); if (!rs.length) continue;
    reqHtml += `<div class="grp">${parts[part]}</div>` + rs.map((r) => `<div style="display:grid;grid-template-columns:auto 1fr auto;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid #1e2133">
      <span class="muted" style="font-family:ui-monospace,monospace;font-size:11px;min-width:120px">${esc(r.ref)}</span>
      <span style="font-size:12.5px">${esc(r.title)}</span>
      <span><select data-req="${r.id}" class="r-st" style="background:#0f1117;border:1px solid #2d3250;color:#e2e8f0;border-radius:6px;padding:3px 6px;font-size:11px">${opt(r.status)}</select></span></div>`).join("");
  }
  $("cra-detail").innerHTML = `
    <div class="sect-h">${esc(c.product.Name)} — conformity</div>
    <div class="card2">
      <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
        <span style="font-size:34px;font-weight:700;color:${pctColor(c.annexIPct)}">${c.annexIPct}%</span>
        <div class="muted" style="font-size:12px">Annex I conformity · Part I ${c.partI.met}/${c.partI.total} · Part II ${c.partII.met}/${c.partII.total} · support ${supPill(c.supportStatus)}${c.product.TargetSL ? ` · target ${esc(c.product.TargetSL)}` : ""}<br>Class ${esc(c.product.Class)} → required route: <b>${esc(c.requiredRoute)}</b></div>
        <span style="flex:1"></span>
        <span class="pill ${c.gate.ready ? "p-ok" : "p-bad"}">Release gate ${c.gate.passed}/${c.gate.total} ${c.gate.ready ? "READY" : "BLOCKED"}</span>
      </div>
    </div>
    <div class="card2">
      <div style="font-size:12px;font-weight:600;color:#e7ebf3;margin-bottom:6px">Release-readiness gate</div>
      ${c.gate.items.map((g) => `<div class="gate"><span style="color:${gcol(g.status)};font-weight:700;width:14px">${gmark(g.status)}</span><span style="flex:1">${esc(g.label)} <span class="muted" style="font-size:11px">(${esc(g.ref)})</span></span><span class="muted" style="font-size:11px">${esc(g.detail)}</span></div>`).join("")}
    </div>
    <div class="card2">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><div style="font-size:12px;font-weight:600;color:#e7ebf3">Releases</div></div>
      ${c.releases.length ? `<table class="cra"><thead><tr><th>Version</th><th>Date</th><th>Status</th><th>SBOM</th></tr></thead><tbody>${c.releases.map((r) => `<tr><td>${esc(r.version)}</td><td>${esc(r.date)}</td><td>${esc(r.status)}</td><td>${r.sbom ? "✓" : "<span class='muted'>—</span>"}</td></tr>`).join("")}</tbody></table>` : `<div class="muted" style="font-size:12px">No releases.</div>`}
      <div class="row" style="margin-top:8px">
        <div class="fld"><label>Version</label><input id="r-ver" placeholder="1.0.0"></div>
        <div class="fld"><label>Date</label><input id="r-date" type="date"></div>
        <div class="fld"><label>SBOM id (from /sca)</label><input id="r-sbom" placeholder="optional"></div>
        <div class="fld"><label>&nbsp;</label><button class="btn-cra" id="r-add">Add release</button></div>
      </div>
    </div>
    <div class="card2">
      <div style="font-size:12px;font-weight:600;color:#e7ebf3;margin-bottom:4px">Annex I requirement matrix</div>
      ${reqHtml}
    </div>`;
  $("cra-detail").querySelectorAll<HTMLSelectElement>("select.r-st").forEach((sel) => sel.onchange = async () => {
    await fetch(`/api/cra/requirement/${sel.dataset.req}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: sel.value }) });
    toast("Requirement updated"); void load();
  });
  ($("r-add") as HTMLButtonElement).onclick = async () => {
    if (!val("r-ver")) return toast("Version required", false);
    const r = await fetch("/api/cra/release", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ productId: id, version: val("r-ver"), releaseDate: val("r-date"), sbomId: val("r-sbom") || undefined, status: "draft" }) });
    if (r.ok) { toast("Release added"); void detail(id); void load(); } else toast("Failed", false);
  };
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n(); void load();
  $("p-add").onclick = async () => {
    if (!val("p-name")) return toast("Name required", false);
    const r = await fetch("/api/cra/product", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: val("p-name"), class: val("p-class"), manufacturer: val("p-mfr"), supportUntil: val("p-support"), targetSl: val("p-sl"), conformityRoute: val("p-route") }) });
    if (r.ok) { toast("Product registered"); (document.getElementById("p-name") as HTMLInputElement).value = ""; void load(); } else toast("Failed", false);
  };
});
