/**
 * asset-management.ts — Asset Management inventory + governance worklist (/asset-management).
 * Renders the asset estate with posture (owner / exposure / backup / controls / vulns) +
 * derived governance findings, from /api/asset-management. Fully i18n via t("asm.*").
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface AssetRow {
  id: number; name: string; criticality: string; owner: string | null; environment: string;
  exposure: "Internet" | "Internal"; backed: boolean; backupPlan: boolean; pii: boolean;
  businessValue: number | null; financialValue: number | null; riskScore: number | null;
  os: string; address: string; vulns: { open: number; kev: number; critical: number };
  controls: number; hasBia: boolean; lastChecked: string | null; flags: string[]; score: number;
  tags: string[]; mfaEnabled: boolean;
}
interface AssetFinding { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; assetId: number; asset: string; }
interface Inventory {
  rows: AssetRow[]; findings: AssetFinding[];
  summary: {
    total: number; crownJewels: number; internetFacing: number; pii: number;
    unbackedCritical: number; noOwner: number; withCriticalVulns: number; stale: number;
    byCriticality: Record<string, number>; byEnvironment: Record<string, number>;
  };
}

// Bulk-selection state + the last-loaded inventory (for client-side filtering of the table).
const SEL = new Set<number>();
let DATA: Inventory | null = null;
let FILTER = { tag: "", crit: "", env: "", exp: "", mfa: "" };
function filteredRows(): AssetRow[] {
  const rows = DATA?.rows ?? [];
  return rows.filter((r) =>
    (!FILTER.tag || r.tags.includes(FILTER.tag)) &&
    (!FILTER.crit || r.criticality === FILTER.crit) &&
    (!FILTER.env || r.environment === FILTER.env) &&
    (!FILTER.exp || r.exposure === FILTER.exp) &&
    (!FILTER.mfa || (FILTER.mfa === "yes" ? r.mfaEnabled : !r.mfaEnabled)));
}

const critClass = (c: string): string => `c-${(c || "unrated").toLowerCase()}`;
const scoreClass = (n: number): string => (n >= 40 ? "s-hi" : n >= 15 ? "s-md" : "s-lo");
const yn = (b: boolean): string => (b ? `<span class="ok">✓</span>` : `<span class="no">✗</span>`);
// Exposure is a server enum ("Internet"/"Internal"); localize for display only.
const expLabel = (e: string): string => (e === "Internet" ? t("asm.exp.internet") : t("asm.exp.internal"));

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="am-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function vulnCell(v: AssetRow["vulns"]): string {
  if (!v.open) return `<span class="muted">—</span>`;
  const out: string[] = [];
  if (v.kev) out.push(`<span class="vbadge v-kev">${v.kev} KEV</span>`);
  if (v.critical) out.push(`<span class="vbadge v-crit">${fmt("asm.vb.crit", { n: v.critical })}</span>`);
  out.push(`<span class="vbadge v-open">${fmt("asm.vb.open", { n: v.open })}</span>`);
  return out.join("");
}

function rowHtml(r: AssetRow): string {
  const flags = r.flags.length ? r.flags.map((f) => `<span class="flag">${esc(f)}</span>`).join("") : `<span class="muted">—</span>`;
  const tags = r.tags.length ? `<div class="muted" style="font-size:10px;margin-top:2px">${r.tags.slice(0, 6).map((x) => `<span class="flag" style="background:#1e2940;border-color:#2d3250">${esc(x)}</span>`).join("")}</div>` : "";
  return `<tr>
    <td style="width:26px;text-align:center"><input type="checkbox" class="am-sel" data-id="${r.id}"${SEL.has(r.id) ? " checked" : ""}></td>
    <td><div class="aname">${esc(r.name)}</div>
      <div class="muted" style="font-size:11px">${esc(r.os || r.environment)}${r.address ? ` · ${esc(r.address)}` : ""}</div>${tags}</td>
    <td><span class="crit ${critClass(r.criticality)}">${esc(r.criticality)}</span></td>
    <td>${esc(r.owner || "—")}</td>
    <td><span class="pill ${r.exposure === "Internet" ? "exp-internet" : "exp-internal"}">${esc(expLabel(r.exposure))}</span></td>
    <td>${r.mfaEnabled ? `<span class="ok">✓ MFA</span>` : `<span class="no">✗</span>`}</td>
    <td>${yn(r.backed)}${r.backupPlan ? ` <span class="muted" style="font-size:11px">${t("asm.cell.plan")}</span>` : ""}</td>
    <td>${vulnCell(r.vulns)}</td>
    <td>${r.controls || `<span class="no">0</span>`} · ${r.hasBia ? `<span class="ok">BIA</span>` : `<span class="no">${t("asm.cell.noBia")}</span>`}</td>
    <td>${flags}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: AssetFinding): string {
  // Click-through opens the ASSET explorer view filtered to the finding's asset (by name).
  const href = f.asset
    ? `/?db=XORCISM&table=ASSET&filterCol=AssetName&filterVal=${encodeURIComponent(f.asset)}`
    : "/?db=XORCISM&table=ASSET";
  return `<li><span class="sev-dot dot-${f.severity}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> —
    <a href="${esc(href)}">${esc(f.label)}</a></li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/asset-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("am-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;
  DATA = d;
  for (const id of [...SEL]) if (!d.rows.some((r) => r.id === id)) SEL.delete(id); // drop stale selections

  if (!d.rows.length) {
    $("am-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("asm.empty")}</div>`;
    return;
  }

  const cards = [
    card(t("asm.card.assets"), String(s.total), fmt("asm.card.assets.f", { n: s.crownJewels })),
    card(t("asm.card.internetFacing"), String(s.internetFacing), t("asm.card.internetFacing.f"), s.internetFacing ? "#fb923c" : "#34d399"),
    card(t("asm.card.kevCritical"), String(s.withCriticalVulns), t("asm.card.kevCritical.f"), s.withCriticalVulns ? "#f87171" : "#34d399"),
    card(t("asm.card.unbacked"), String(s.unbackedCritical), t("asm.card.unbacked.f"), s.unbackedCritical ? "#f87171" : "#34d399"),
    card(t("asm.card.noOwner"), String(s.noOwner), t("asm.card.noOwner.f"), s.noOwner ? "#fb923c" : "#34d399"),
    card(t("asm.card.pii"), String(s.pii), t("asm.card.pii.f"), s.pii ? "#fbbf24" : undefined),
    card(t("asm.card.stale"), String(s.stale), t("asm.card.stale.f"), s.stale ? "#fbbf24" : undefined),
  ].join("");

  const byCrit = Object.entries(s.byCriticality).sort((a, b) => b[1] - a[1])
    .map(([c, n]) => `<span class="bd"><span class="crit ${critClass(c)}">${esc(c)}</span> <b>${n}</b></span>`).join("");
  const byEnv = Object.entries(s.byEnvironment).sort((a, b) => b[1] - a[1])
    .map(([e, n]) => `<span class="bd">${esc(e)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("asm.more", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("asm.noFindings")}</div>`;

  $("am-body").innerHTML = `<div class="am-cards">${cards}</div>
    <div class="am-section">${fmt("asm.sec.worklist", { n: d.findings.length })}</div>${findings}
    <div class="am-section">${t("asm.sec.byCriticality")}</div><div class="breakdown">${byCrit}</div>
    <div class="am-section">${t("asm.sec.byEnvironment")}</div><div class="breakdown">${byEnv}</div>
    <div class="am-section">${fmt("asm.sec.inventory", { n: d.rows.length })}</div>
    <div id="am-inv"></div>
    <div class="legend">${t("asm.legend")}</div>`;
  renderInventory();
}

// ── Inventory table with bulk selection + client-side filter ────────────────────
function renderInventory(): void {
  if (!DATA) return;
  const rows = filteredRows();
  const allTags = [...new Set(DATA.rows.flatMap((r) => r.tags))].sort((a, b) => a.localeCompare(b));
  const crits = Object.keys(DATA.summary.byCriticality).sort();
  const envs = Object.keys(DATA.summary.byEnvironment).sort();
  const opt = (v: string, cur: string, label?: string) => `<option value="${esc(v)}"${cur === v ? " selected" : ""}>${esc(label ?? v)}</option>`;
  const selCount = SEL.size;

  const bar = `<div class="am-bulkbar" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px">
      <span class="muted" style="font-size:11px">${t("asm.bulk.filter")}:</span>
      <select id="am-flt-tag" class="am-flt">${opt("", FILTER.tag, t("asm.bulk.anyTag"))}${allTags.map((x) => opt(x, FILTER.tag)).join("")}</select>
      <select id="am-flt-crit" class="am-flt">${opt("", FILTER.crit, t("asm.bulk.anyCrit"))}${crits.map((x) => opt(x, FILTER.crit)).join("")}</select>
      <select id="am-flt-env" class="am-flt">${opt("", FILTER.env, t("asm.bulk.anyEnv"))}${envs.map((x) => opt(x, FILTER.env)).join("")}</select>
      <select id="am-flt-exp" class="am-flt">${opt("", FILTER.exp, t("asm.bulk.anyExp"))}${opt("Internet", FILTER.exp, t("asm.exp.internet"))}${opt("Internal", FILTER.exp, t("asm.exp.internal"))}</select>
      <select id="am-flt-mfa" class="am-flt">${opt("", FILTER.mfa, t("asm.bulk.anyMfa"))}${opt("yes", FILTER.mfa, t("asm.bulk.mfaYes"))}${opt("no", FILTER.mfa, t("asm.bulk.mfaNo"))}</select>
      <button class="btn btn-ghost btn-sm" id="am-sel-matching">${fmt("asm.bulk.selectMatching", { n: rows.length })}</button>
      <button class="btn btn-ghost btn-sm" id="am-sel-clear">${t("asm.bulk.clearSel")}</button>
      <span style="flex:1"></span>
      <span class="muted" style="font-size:12px" id="am-sel-count">${fmt("asm.bulk.selected", { n: selCount })}</span>
      <button class="btn-newasset" id="am-bulk-btn"${selCount ? "" : " disabled"}>${t("asm.bulk.update")}</button>
    </div>`;

  const table = `<table class="am"><thead><tr>
      <th style="width:26px;text-align:center"><input type="checkbox" id="am-sel-all" title="${t("asm.bulk.selectAll")}"></th>
      <th>${t("asm.th.asset")}</th><th>${t("asm.th.criticality")}</th><th>${t("asm.th.owner")}</th><th>${t("asm.th.exposure")}</th><th>MFA</th><th>${t("asm.th.backup")}</th><th>${t("asm.th.vulns")}</th><th>${t("asm.th.controlsBia")}</th><th>${t("asm.th.findings")}</th><th title="${t("asm.th.risk.title")}">${t("asm.th.risk")}</th>
    </tr></thead><tbody>${rows.map(rowHtml).join("") || `<tr><td colspan="11" class="muted" style="padding:14px;text-align:center">${t("asm.bulk.noMatch")}</td></tr>`}</tbody></table>`;

  $("am-inv").innerHTML = bar + table;

  const reFilter = () => {
    FILTER = {
      tag: (document.getElementById("am-flt-tag") as HTMLSelectElement).value,
      crit: (document.getElementById("am-flt-crit") as HTMLSelectElement).value,
      env: (document.getElementById("am-flt-env") as HTMLSelectElement).value,
      exp: (document.getElementById("am-flt-exp") as HTMLSelectElement).value,
      mfa: (document.getElementById("am-flt-mfa") as HTMLSelectElement).value,
    };
    renderInventory();
  };
  document.querySelectorAll<HTMLSelectElement>(".am-flt").forEach((el) => el.onchange = reFilter);
  document.querySelectorAll<HTMLInputElement>(".am-sel").forEach((el) => el.onchange = () => {
    const id = Number(el.dataset.id); if (el.checked) SEL.add(id); else SEL.delete(id);
    updateSelUi();
  });
  (document.getElementById("am-sel-all") as HTMLInputElement).onchange = (e) => {
    const on = (e.target as HTMLInputElement).checked;
    for (const r of filteredRows()) { if (on) SEL.add(r.id); else SEL.delete(r.id); }
    renderInventory();
  };
  $("am-sel-matching").onclick = () => { for (const r of filteredRows()) SEL.add(r.id); renderInventory(); };
  $("am-sel-clear").onclick = () => { SEL.clear(); renderInventory(); };
  $("am-bulk-btn").onclick = openBulk;
}

function updateSelUi(): void {
  const c = $("am-sel-count"); if (c) c.textContent = fmt("asm.bulk.selected", { n: SEL.size });
  const b = document.getElementById("am-bulk-btn") as HTMLButtonElement | null; if (b) b.disabled = SEL.size === 0;
}

// ── Bulk-update modal ───────────────────────────────────────────────────────────
async function openBulk(): Promise<void> {
  if (!SEL.size) return;
  // Owner options (best-effort).
  let owners: { id: number; label: string }[] = [];
  try { const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName"); if (r.ok) owners = await r.json(); } catch { /* optional */ }
  const yesno = (id: string) => `<select id="${id}" disabled><option value="1">${t("asm.bulk.yes")}</option><option value="0">${t("asm.bulk.no")}</option></select>`;
  const crits = [...new Set([...(DATA ? Object.keys(DATA.summary.byCriticality) : []), "Low", "Medium", "High", "Critical"])];
  // Each row: [apply-checkbox] label [value control]. Only checked rows are sent.
  const F = (key: string, label: string, control: string): string =>
    `<div class="am-bf" style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid #1e2133">
       <label style="display:flex;align-items:center;gap:7px;flex:1;font-size:13px;color:#cbd5e1">
         <input type="checkbox" class="am-bf-on" data-field="${key}"> ${esc(label)}</label>
       <div style="flex:1">${control}</div></div>`;
  const html = `<div id="am-bulk-modal" style="position:fixed;inset:0;background:rgba(4,6,15,.72);display:flex;align-items:flex-start;justify-content:center;z-index:1200;overflow:auto">
    <div style="background:#0f1322;border:1px solid #2d3250;border-radius:12px;padding:18px 20px;margin:44px 16px;max-width:560px;width:100%">
      <h2 style="font-size:16px;margin:0 0 4px">${t("asm.bulk.update")}</h2>
      <div class="muted" style="font-size:12px;margin-bottom:12px">${fmt("asm.bulk.applyTo", { n: SEL.size })}</div>
      <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">${t("asm.bulk.tick")}</div>
      ${F("mfaEnabled", t("asm.bulk.mfa"), yesno("am-bf-mfaEnabled"))}
      ${F("publicFacing", t("asm.bulk.internetFacing"), yesno("am-bf-publicFacing"))}
      ${F("hostPii", t("asm.bulk.pii"), yesno("am-bf-hostPii"))}
      ${F("backed", t("asm.th.backup"), yesno("am-bf-backed"))}
      ${F("enabled", t("asm.bulk.enabled"), yesno("am-bf-enabled"))}
      ${F("criticality", t("asm.th.criticality"), `<select id="am-bf-criticality" disabled>${crits.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("")}</select>`)}
      ${F("environment", t("asm.bulk.env"), `<select id="am-bf-environment" disabled><option value="Cloud">Cloud</option><option value="Virtual">Virtual</option><option value="Third-party">Third-party</option><option value="On-premises">On-premises</option></select>`)}
      ${F("businessValue", t("asm.bulk.bizval"), `<input id="am-bf-businessValue" disabled placeholder="1-5">`)}
      ${F("financialValue", t("asm.bulk.finval"), `<input id="am-bf-financialValue" type="number" disabled placeholder="e.g. 50000">`)}
      ${F("currency", t("asm.bulk.currency"), `<input id="am-bf-currency" disabled placeholder="USD" maxlength="10" style="width:90px">`)}
      ${F("ownerPersonId", t("asm.th.owner"), `<select id="am-bf-ownerPersonId" disabled><option value="">— ${t("asm.bulk.clearOwner")} —</option>${owners.map((o) => `<option value="${o.id}">${esc(o.label || ("#" + o.id))}</option>`).join("")}</select>`)}
      <div id="am-bulk-err" style="color:#f87171;font-size:12px;min-height:16px;margin-top:8px"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">
        <button class="btn btn-ghost btn-sm" id="am-bulk-cancel">${t("asm.btn.cancel")}</button>
        <button class="btn-newasset" id="am-bulk-apply">${t("asm.bulk.apply")}</button>
      </div>
    </div></div>`;
  const wrap = document.createElement("div"); wrap.innerHTML = html; document.body.appendChild(wrap.firstElementChild!);
  const close = () => document.getElementById("am-bulk-modal")?.remove();
  // Enable a field's control only when its "apply" box is ticked.
  document.querySelectorAll<HTMLInputElement>(".am-bf-on").forEach((cb) => cb.onchange = () => {
    const ctl = document.getElementById("am-bf-" + cb.dataset.field) as HTMLInputElement | HTMLSelectElement | null;
    if (ctl) { ctl.disabled = !cb.checked; if (cb.checked) ctl.focus(); }
  });
  $("am-bulk-cancel").onclick = close;
  document.getElementById("am-bulk-modal")!.onclick = (e) => { if (e.target === e.currentTarget) close(); };
  $("am-bulk-apply").onclick = () => void applyBulk(close);
}

async function applyBulk(close: () => void): Promise<void> {
  const set: Record<string, unknown> = {};
  document.querySelectorAll<HTMLInputElement>(".am-bf-on:checked").forEach((cb) => {
    const field = cb.dataset.field!;
    const ctl = document.getElementById("am-bf-" + field) as HTMLInputElement | HTMLSelectElement | null;
    if (ctl) set[field] = ctl.value;
  });
  const err = $("am-bulk-err");
  if (!Object.keys(set).length) { err.textContent = `⚠️ ${t("asm.bulk.pickField")}`; return; }
  const btn = $("am-bulk-apply") as HTMLButtonElement; btn.disabled = true; err.textContent = t("asm.bulk.applying");
  try {
    const r = await fetch("/api/asset-management/bulk-update", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ assetIds: [...SEL], set }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    close();
    SEL.clear();
    await load();
    toast(fmt("asm.bulk.done", { u: d.updated, f: (d.fields || []).length }));
  } catch (e) { err.textContent = `⚠️ ${e}`; btn.disabled = false; }
}

// ── Guided "new asset" modal ───────────────────────────────────────────────────
async function loadOwners(): Promise<void> {
  try {
    const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName");
    if (!r.ok) return;
    const list = (await r.json()) as { id: number; label: string }[];
    const sel = $("am-f-owner") as HTMLSelectElement;
    for (const p of list) { const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label || `#${p.id}`; sel.appendChild(o); }
  } catch { /* lookup unavailable */ }
}

function openModal(): void {
  for (const id of ["am-f-name", "am-f-os", "am-f-host", "am-f-ip", "am-f-bv", "am-f-fv", "am-f-notes"]) (document.getElementById(id) as HTMLInputElement).value = "";
  for (const id of ["am-f-crit", "am-f-env", "am-f-owner"]) (document.getElementById(id) as HTMLSelectElement).value = "";
  for (const id of ["am-f-public", "am-f-pii", "am-f-mfa"]) (document.getElementById(id) as HTMLInputElement).checked = false;
  $("am-f-err").textContent = "";
  $("am-modal").classList.add("open");
  ($("am-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("am-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createAsset(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const ck = (id: string): boolean => (document.getElementById(id) as HTMLInputElement).checked;
  const name = v("am-f-name").trim();
  const err = $("am-f-err");
  if (!name) { err.textContent = `⚠️ ${t("asm.err.name")}`; ($("am-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("am-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = `${t("asm.creating")}`;
  try {
    const body = {
      name, criticality: v("am-f-crit") || undefined, environment: v("am-f-env") || undefined,
      os: v("am-f-os").trim() || undefined, ownerPersonId: v("am-f-owner") || undefined,
      hostname: v("am-f-host").trim() || undefined, ip: v("am-f-ip").trim() || undefined,
      businessValue: v("am-f-bv").trim() || undefined, financialValue: v("am-f-fv") || undefined,
      publicFacing: ck("am-f-public"), hostPii: ck("am-f-pii"), mfaEnabled: ck("am-f-mfa"),
      notes: v("am-f-notes").trim() || undefined,
    };
    const r = await fetch("/api/asset-management/asset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal();
    await load();
    const link = `/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${d.id}`;
    toast(fmt("asm.toast.created", { link }));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

async function matchCves(): Promise<void> {
  const btn = $("am-match") as HTMLButtonElement;
  btn.disabled = true; const label = btn.textContent; btn.textContent = `${t("asm.matching")}`;
  try {
    const r = await fetch("/api/cve-match/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ days: 30 }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    await load();
    toast(d.newLinks
      ? fmt("asm.match.new", { n: d.newLinks, a: d.assetsAffected, x: d.assetsNotified, c: d.cvesScanned })
      : fmt("asm.match.none", { c: d.cvesScanned }));
  } catch (e) { toast(`⚠️ ${e}`); }
  finally { btn.disabled = false; btn.textContent = label; }
}

// Clean CVE-match false positives — re-scores the existing keyword-matched backlog and flags the
// now-weak links (e.g. an asset tagged "email" linked to thousands of CVEs) as FalsePositive. The
// flag is reversible (the rows stay; un-flag in the explorer) and scanner/manual links are untouched.
async function cleanFalsePositives(): Promise<void> {
  if (!window.confirm(t("asm.cleanFp.confirm"))) return;
  const btn = $("am-clean-fp") as HTMLButtonElement;
  btn.disabled = true; const label = btn.textContent; btn.textContent = `${t("asm.cleaning")}`;
  try {
    const r = await fetch("/api/cve-match/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ onlyRescore: true, minConfidence: "medium" }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    await load();
    const rs = d.rescore as { scanned: number; flagged: number; kept: number } | undefined;
    toast(rs ? fmt("asm.cleanFp.done", { f: rs.flagged, k: rs.kept, s: rs.scanned }) : t("asm.cleanFp.none"));
  } catch (e) { toast(`⚠️ ${e}`); }
  finally { btn.disabled = false; btn.textContent = label; }
}

// ── Excel / CSV import with column mapping ──────────────────────────────────────
// Logical ASSET fields a spreadsheet column can map to. `guess` = lowercase header
// substrings used to auto-select a column. `bool` fields accept yes/true/1/x/✓/oui.
// Mirrors the server's ASSET_IMPORT_FIELDS (assets.ts) — keep the two in sync.
interface ImpField { key: string; labelKey: string; required?: boolean; bool?: boolean; guess: string[]; }
const IMPORT_FIELDS: ImpField[] = [
  { key: "name", labelKey: "asm.imp.f.name", required: true, guess: ["asset name", "assetname", "name", "nom", "hostname", "host", "machine", "libellé", "title"] },
  { key: "description", labelKey: "asm.imp.f.description", guess: ["description", "desc", "détail", "detail"] },
  { key: "criticality", labelKey: "asm.imp.f.criticality", guess: ["critical", "criticité", "criticite", "importance", "tier", "niveau"] },
  { key: "environment", labelKey: "asm.imp.f.environment", guess: ["environment", "environnement", "env", "deployment", "type"] },
  { key: "os", labelKey: "asm.imp.f.os", guess: ["operating system", "os name", "osname", "os", "système", "platform", "plateforme"] },
  { key: "hostname", labelKey: "asm.imp.f.hostname", guess: ["hostname", "host name", "fqdn", "host"] },
  { key: "ip", labelKey: "asm.imp.f.ip", guess: ["ipv4", "ip address", "ipaddress", "ip", "adresse ip", "address"] },
  { key: "publicFacing", labelKey: "asm.imp.f.publicFacing", bool: true, guess: ["public", "internet", "exposed", "exposé", "expose", "facing", "externe"] },
  { key: "hostPii", labelKey: "asm.imp.f.hostPii", bool: true, guess: ["pii", "personal data", "données personnelles", "dcp", "rgpd", "gdpr"] },
  { key: "mfaEnabled", labelKey: "asm.imp.f.mfaEnabled", bool: true, guess: ["mfa", "2fa", "multi-factor", "multifactor", "multi factor", "authentification", "mfaenabled"] },
  { key: "businessValue", labelKey: "asm.imp.f.businessValue", guess: ["business value", "valeur métier", "valeur metier", "business", "métier"] },
  { key: "financialValue", labelKey: "asm.imp.f.financialValue", guess: ["financial", "valeur financière", "valeur financiere", "cost", "coût", "montant", "value"] },
  { key: "currency", labelKey: "asm.imp.f.currency", guess: ["currency", "devise", "monnaie"] },
  { key: "notes", labelKey: "asm.imp.f.notes", guess: ["notes", "note", "comment", "commentaire", "remarque"] },
];

let impHeaders: string[] = [];
let impRows: unknown[][] = [];
const impSelects: Record<string, HTMLSelectElement> = {};

// Minimal local typing for the global SheetJS (UMD) build — just the bits we use; avoids a
// dependency on the optional "xlsx" type declarations (the lib loads at runtime from /vendor).
interface XlsxLib {
  read(data: Uint8Array, opts: { type: string }): { SheetNames: string[]; Sheets: Record<string, unknown> };
  utils: {
    sheet_to_json(ws: unknown, opts: { header: 1; blankrows: boolean; defval: string }): unknown[][];
    aoa_to_sheet(data: unknown[][]): unknown;
    book_new(): unknown;
    book_append_sheet(wb: unknown, ws: unknown, name: string): void;
  };
  writeFile(wb: unknown, filename: string): void;
}

// Lazy-load SheetJS (served at /vendor/xlsx.full.min.js) only when the import modal is used.
function loadXlsx(): Promise<void> {
  if ((window as unknown as { XLSX?: unknown }).XLSX) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "/vendor/xlsx.full.min.js";
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("xlsx load failed"));
    document.head.appendChild(s);
  });
}
const getXlsx = (): XlsxLib | undefined => (window as unknown as { XLSX?: XlsxLib }).XLSX;

function openImport(): void {
  impHeaders = []; impRows = [];
  ($("am-imp-file") as HTMLInputElement).value = "";
  $("am-imp-status").textContent = "";
  $("am-imp-result").innerHTML = "";
  $("am-imp-err").textContent = "";
  $("am-imp-map").innerHTML = "";
  $("am-imp-mapwrap").style.display = "none";
  ($("am-imp-upsert") as HTMLInputElement).checked = false;
  ($("am-imp-run") as HTMLButtonElement).disabled = true;
  $("am-imp-modal").classList.add("open");
}
function closeImport(): void { $("am-imp-modal").classList.remove("open"); }

function buildImportMapping(): void {
  const wrap = $("am-imp-map");
  wrap.innerHTML = "";
  const used = new Set<number>();
  for (const f of IMPORT_FIELDS) {
    const row = document.createElement("div");
    row.style.cssText = "display:flex;flex-direction:column;gap:3px";
    const lbl = document.createElement("label");
    lbl.textContent = t(f.labelKey) + (f.required ? " *" : "");
    lbl.style.cssText = "font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.4px";
    const sel = document.createElement("select");
    sel.style.cssText = "width:100%;box-sizing:border-box;background:#0f1117;border:1px solid #2d3250;border-radius:8px;padding:7px 9px;color:#e2e8f0;font-size:12.5px";
    const none = document.createElement("option"); none.value = "-1"; none.textContent = t("asm.imp.ignore"); sel.appendChild(none);
    impHeaders.forEach((h, i) => { const o = document.createElement("option"); o.value = String(i); o.textContent = h || `${t("asm.imp.col")} ${i + 1}`; sel.appendChild(o); });
    let guessIdx = -1;
    for (let i = 0; i < impHeaders.length; i++) {
      const hl = (impHeaders[i] || "").toLowerCase().trim();
      if (!used.has(i) && hl && f.guess.some((g) => hl === g || hl.includes(g))) { guessIdx = i; break; }
    }
    if (guessIdx >= 0) { sel.value = String(guessIdx); used.add(guessIdx); }
    impSelects[f.key] = sel;
    row.appendChild(lbl); row.appendChild(sel); wrap.appendChild(row);
  }
}

async function onImportFile(): Promise<void> {
  const file = ($("am-imp-file") as HTMLInputElement).files?.[0];
  if (!file) return;
  const status = $("am-imp-status");
  status.textContent = t("asm.imp.reading");
  ($("am-imp-run") as HTMLButtonElement).disabled = true;
  $("am-imp-result").innerHTML = "";
  try {
    await loadXlsx();
    const XLSX = getXlsx();
    if (!XLSX) { status.textContent = t("asm.imp.noxlsx"); return; }
    const buf = await file.arrayBuffer();
    const wb = XLSX.read(new Uint8Array(buf), { type: "array" });
    const ws = wb.Sheets[wb.SheetNames[0]];
    const aoa = XLSX.utils.sheet_to_json(ws, { header: 1, blankrows: false, defval: "" }) as unknown[][];
    if (!aoa.length) { status.textContent = t("asm.imp.empty"); return; }
    impHeaders = (aoa[0] as unknown[]).map((h) => String(h ?? "").trim());
    impRows = aoa.slice(1).filter((r) => Array.isArray(r) && r.some((c) => String(c ?? "").trim() !== ""));
    buildImportMapping();
    $("am-imp-mapwrap").style.display = "block";
    status.textContent = fmt("asm.imp.detected", { cols: impHeaders.length, rows: impRows.length });
    ($("am-imp-run") as HTMLButtonElement).disabled = impRows.length === 0;
  } catch (e) { status.textContent = `⚠️ ${e}`; }
}

async function downloadTemplate(ev: Event): Promise<void> {
  ev.preventDefault();
  try {
    await loadXlsx();
    const XLSX = getXlsx();
    if (!XLSX) { toast(`⚠️ ${t("asm.imp.noxlsx")}`); return; }
    const headers = IMPORT_FIELDS.map((f) => t(f.labelKey));
    const sample = ["web-prod-01", "Public e-commerce web server", "High", "cloud", "Ubuntu 22.04", "web-prod-01.example.com", "10.0.1.20", "yes", "yes", "no", "Revenue-critical", "250000", "EUR", "Front-end fleet"];
    const ws = XLSX.utils.aoa_to_sheet([headers, sample]);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Assets");
    XLSX.writeFile(wb, "asset-import-template.xlsx");
  } catch (e) { toast(`⚠️ ${e}`); }
}

async function runImport(): Promise<void> {
  const err = $("am-imp-err");
  err.textContent = "";
  if (Number(impSelects.name?.value ?? -1) < 0) { err.textContent = `⚠️ ${t("asm.imp.needName")}`; return; }
  const rows = impRows.map((row) => {
    const o: Record<string, unknown> = {};
    for (const f of IMPORT_FIELDS) {
      const ci = Number(impSelects[f.key]?.value ?? -1);
      if (ci >= 0) { const cell = row[ci]; if (String(cell ?? "").trim() !== "") o[f.key] = cell; }
    }
    return o;
  }).filter((o) => String(o.name ?? "").trim() !== "");
  if (!rows.length) { err.textContent = `⚠️ ${t("asm.imp.needName")}`; return; }
  const btn = $("am-imp-run") as HTMLButtonElement;
  btn.disabled = true; err.textContent = t("asm.imp.importing");
  try {
    const r = await fetch("/api/asset-management/import", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rows, upsert: ($("am-imp-upsert") as HTMLInputElement).checked }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    err.textContent = "";
    const errLines = (d.errors as { row: number; error: string }[] | undefined)?.slice(0, 8)
      .map((e) => `<div>${t("asm.imp.row")} ${e.row}: ${esc(e.error)}</div>`).join("") || "";
    $("am-imp-result").innerHTML =
      `<div style="background:#0f1117;border:1px solid #2d3250;border-radius:8px;padding:10px 12px;font-size:12.5px;color:#cbd5e1">
        <div class="ok">${fmt("asm.imp.done", { created: d.created, updated: d.updated, skipped: d.skipped })}</div>
        ${d.errors?.length ? `<div class="no" style="margin-top:6px">${fmt("asm.imp.errors", { n: d.errors.length })}</div>${errLines}` : ""}
      </div>`;
    toast(fmt("asm.imp.toast", { created: d.created, updated: d.updated }));
    await load();
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

// ── ARF (Asset Reporting Format) import / export ────────────────────────────────
async function exportArf(): Promise<void> {
  const btn = $("am-export-arf") as HTMLButtonElement;
  const label = btn.textContent;
  btn.disabled = true; btn.textContent = t("asm.arf.exporting");
  try {
    const r = await fetch("/api/asset-management/export/arf");
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || `HTTP ${r.status}`); }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `xorcism-assets-arf-${new Date().toISOString().slice(0, 10)}.xml`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    toast(t("asm.arf.exported"));
  } catch (e) { toast(`⚠️ ${e}`); }
  finally { btn.disabled = false; btn.textContent = label; }
}

let arfXml = "";
function openArf(): void {
  arfXml = "";
  ($("am-arf-file") as HTMLInputElement).value = "";
  $("am-arf-status").textContent = "";
  $("am-arf-result").innerHTML = "";
  $("am-arf-err").textContent = "";
  ($("am-arf-upsert") as HTMLInputElement).checked = false;
  ($("am-arf-run") as HTMLButtonElement).disabled = true;
  $("am-arf-modal").classList.add("open");
}
function closeArf(): void { $("am-arf-modal").classList.remove("open"); }

async function onArfFile(): Promise<void> {
  const file = ($("am-arf-file") as HTMLInputElement).files?.[0];
  if (!file) return;
  const status = $("am-arf-status");
  ($("am-arf-run") as HTMLButtonElement).disabled = true;
  $("am-arf-result").innerHTML = ""; $("am-arf-err").textContent = "";
  try {
    arfXml = await file.text();
    if (!/asset-report-collection|asset|computing-device/i.test(arfXml)) { status.textContent = t("asm.arf.notArf"); return; }
    status.textContent = fmt("asm.arf.loaded", { kb: Math.max(1, Math.round(arfXml.length / 1024)) });
    ($("am-arf-run") as HTMLButtonElement).disabled = false;
  } catch (e) { status.textContent = `⚠️ ${e}`; }
}

async function runArfImport(): Promise<void> {
  const err = $("am-arf-err"); err.textContent = "";
  if (!arfXml.trim()) { err.textContent = `⚠️ ${t("asm.arf.notArf")}`; return; }
  const btn = $("am-arf-run") as HTMLButtonElement;
  btn.disabled = true; err.textContent = t("asm.arf.importing");
  try {
    const r = await fetch("/api/asset-management/import/arf", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ xml: arfXml, upsert: ($("am-arf-upsert") as HTMLInputElement).checked }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    err.textContent = "";
    const errLines = (d.errors as { row: number; error: string }[] | undefined)?.slice(0, 8)
      .map((e) => `<div>${t("asm.imp.row")} ${e.row}: ${esc(e.error)}</div>`).join("") || "";
    $("am-arf-result").innerHTML =
      `<div style="background:#0f1117;border:1px solid #2d3250;border-radius:8px;padding:10px 12px;font-size:12.5px;color:#cbd5e1">
        <div class="ok">${fmt("asm.arf.done", { parsed: d.parsed, created: d.created, updated: d.updated, skipped: d.skipped })}</div>
        ${d.errors?.length ? `<div class="no" style="margin-top:6px">${fmt("asm.imp.errors", { n: d.errors.length })}</div>${errLines}` : ""}
      </div>`;
    toast(fmt("asm.imp.toast", { created: d.created, updated: d.updated }));
    await load();
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("am-match").addEventListener("click", () => void matchCves());
  $("am-export-arf").addEventListener("click", () => void exportArf());
  $("am-import-arf").addEventListener("click", openArf);
  $("am-arf-cancel").addEventListener("click", closeArf);
  $("am-arf-modal").addEventListener("click", (e) => { if (e.target === $("am-arf-modal")) closeArf(); });
  ($("am-arf-file") as HTMLInputElement).addEventListener("change", () => void onArfFile());
  $("am-arf-run").addEventListener("click", () => void runArfImport());
  $("am-clean-fp").addEventListener("click", () => void cleanFalsePositives());
  $("am-new").addEventListener("click", openModal);
  $("am-cancel").addEventListener("click", closeModal);
  $("am-create").addEventListener("click", () => void createAsset());
  $("am-modal").addEventListener("click", (e) => { if (e.target === $("am-modal")) closeModal(); });
  $("am-import").addEventListener("click", openImport);
  $("am-imp-cancel").addEventListener("click", closeImport);
  $("am-imp-modal").addEventListener("click", (e) => { if (e.target === $("am-imp-modal")) closeImport(); });
  ($("am-imp-file") as HTMLInputElement).addEventListener("change", () => void onImportFile());
  $("am-imp-template").addEventListener("click", (e) => void downloadTemplate(e));
  $("am-imp-run").addEventListener("click", () => void runImport());
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeModal(); closeImport(); closeArf(); } });
  ($("am-f-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createAsset(); });
  void loadOwners();
  void load();
});
