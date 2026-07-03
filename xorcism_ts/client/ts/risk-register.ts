/**
 * risk-register.ts — Risk Register inventory + treatment worklist (/risk-register).
 * Inherent→residual posture, treatment, CRQ/FAIR ALE, from /api/risk-register.
 */
import { initI18n, t } from "./i18n";
import { openXlsxImport } from "./xlsx-import";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const LVL_KEY: Record<string, string> = { critical: "rr.lvl.critical", "very high": "rr.lvl.veryHigh", high: "rr.lvl.high", medium: "rr.lvl.medium", moderate: "rr.lvl.medium", low: "rr.lvl.low", "very low": "rr.lvl.veryLow" };
const levelLabel = (label: string): string => { const k = LVL_KEY[String(label).toLowerCase()]; return k ? t(k) : label; };

interface Row { id: number; ref: string; title: string; category: string; owner: string | null; asset: string | null; status: string; open: boolean; inherent: string; current: string; residual: string; residualRank: number; treatment: string; hasPlan: boolean; ale: number | null; sle: number | null; currency: string; reviewInDays: number | null; reviewOverdue: boolean; score: number; overAppetite: boolean; measures: number; }
interface Finding { id: number; ref: string; title: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; reason: string; kind: string; label: string; }
interface Inventory {
  rows: Row[]; findings: Finding[];
  summary: { risks: number; open: number; closed: number; treatedRate: number | null; highCritical: number; untreated: number; accepted: number; overdueReview: number; noOwner: number; overAppetite: number; quantified: number; totalALE: number; currency: string; byLevel: Record<string, number>; byStatus: Record<string, number>; byTreatment: Record<string, number>; byCategory: Record<string, number>; riskScore: number; };
}

interface Gov {
  strategy: Record<string, any> | null;
  appetite: { Category: string; AppetiteLevel: string; ToleranceRank: number; Rationale: string }[];
  measures: { RiskMeasureID: number; Ref: string; Name: string; Description: string; MeasureType: string; Category: string; ControlRef: string; Effectiveness: string; Cost: string; Status: string; usage: number }[];
  options: { appetiteLevels: string[]; measureTypes: string[]; measureStatuses: string[]; linkStatuses: string[]; toleranceRanks: { rank: number; label: string }[] };
}

let CUR = "EUR";
let GOV: Gov | null = null;
let ROWS: Row[] = [];
const rankOf = (label: string): number => ({ critical: 0, "very high": 0, high: 1, medium: 2, moderate: 2, low: 3, "very low": 4 }[label.toLowerCase()] ?? 5);
const lvl = (label: string): string => `<span class="lvl lvl-${rankOf(label)}">${esc(levelLabel(label))}</span>`;
const scoreClass = (n: number): string => (n >= 50 ? "s-hi" : n >= 25 ? "s-md" : "s-lo");
const postureColor = (n: number): string => (n >= 60 ? "#f87171" : n >= 35 ? "#fbbf24" : "#34d399");
function money(n: number | null): string {
  if (n == null) return "—";
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency: CUR, maximumFractionDigits: 0 }).format(n); }
  catch { return `${CUR} ${Math.round(n).toLocaleString()}`; }
}

function card(lbl: string, val: string, foot: string, color?: string, cls = "rr-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: Row): string {
  const measureChip = `<button class="mchip" data-entry="${r.id}" data-name="${esc(r.ref)}" title="${t("rr.measuresTitle")}">🛡 ${r.measures || "+"}</button>`;
  const planChip = `<button class="mchip" data-plan-entry="${r.id}" data-name="${esc(r.ref)}" title="${t("rr.tp.chipTitle")}"${r.hasPlan ? ' style="border-color:#a78bfa;color:#c4b5fd"' : ""}>📋 ${t("rr.tp.plan")}</button>`;
  const treat = r.treatment !== "—" ? `<span class="tr">${esc(r.treatment)}</span>${r.hasPlan ? "" : ` <span class="muted" style="font-size:11px">${t("rr.noPlan")}</span>`} ${measureChip} ${planChip}` : `<span class="tag">${t("rr.untreated")}</span> ${measureChip} ${planChip}`;
  const review = r.reviewInDays == null ? `<span class="muted">—</span>` : r.reviewOverdue ? `<span class="tag">${fmt("rr.overdueD", { n: -r.reviewInDays })}</span>` : `<span class="muted">${fmt("rr.inDays", { n: r.reviewInDays })}</span>`;
  return `<tr>
    <td><div class="rname">${esc(r.ref)} <span style="font-weight:400">${esc(r.title)}</span>${r.overAppetite ? ` <span class="appetite-flag" title="${t("rr.overAppetiteTitle")}">⚑ ${t("rr.overAppetite")}</span>` : ""}</div>
      <div class="muted" style="font-size:11px">${esc(r.category)}${r.owner ? ` · ${esc(r.owner)}` : ""}${r.asset ? ` · ${esc(r.asset)}` : ""}</div></td>
    <td>${lvl(r.inherent)}<span class="arrow">→</span>${lvl(r.residual)}</td>
    <td>${treat}</td>
    <td><span class="st ${r.open ? "st-open" : "st-closed"}">${esc(r.status)}</span></td>
    <td class="num">${r.ale != null ? `<b>${esc(money(r.ale))}</b>` : "<span class=\"muted\">—</span>"}</td>
    <td>${review}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const color = f.kind === "untreated" ? "#f87171" : f.kind === "accepted" ? "#fb923c" : f.kind === "owner" ? "#64748b" : "#fbbf24";
  return `<li><span class="dot" style="background:${color}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="/?db=XCOMPLIANCE&table=RISKREGISTERENTRY&filterCol=RiskRegisterEntryID&filterVal=${esc(f.id)}">${esc(f.ref)}</a>
    ${f.title ? `<span class="muted">${esc(f.title)}</span> — ` : "— "}${esc(f.label)}</li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try {
    const [r, g] = await Promise.all([fetch("/api/risk-register"), fetch("/api/risk-register/governance")]);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    d = await r.json();
    GOV = g.ok ? await g.json() : null;
  } catch (e) { $("rr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  CUR = d.summary.currency || "EUR";
  ROWS = d.rows;
  const s = d.summary;

  if (!d.rows.length && !(GOV && (GOV.strategy || GOV.measures.length))) {
    $("rr-body").innerHTML = `${strategySection()}<div class="muted" style="padding:24px;text-align:center">${t("rr.empty")}</div>`;
    wireGov();
    return;
  }

  const cards = [
    card(t("rr.cPosture"), String(s.riskScore), t("rr.cPosture.foot"), postureColor(s.riskScore), "rr-card rr-score"),
    card(t("rr.cOpen"), String(s.open), fmt("rr.cOpen.foot", { closed: s.closed, total: s.risks })),
    card(t("rr.cHighCrit"), String(s.highCritical), t("rr.cHighCrit.foot"), s.highCritical ? "#f87171" : "#34d399"),
    card(t("rr.cOverAppetite"), String(s.overAppetite), t("rr.cOverAppetite.foot"), s.overAppetite ? "#f87171" : "#34d399"),
    card(t("rr.cUntreated"), String(s.untreated), t("rr.cUntreated.foot"), s.untreated ? "#f87171" : "#34d399"),
    card(t("rr.cTreated"), s.treatedRate != null ? `${s.treatedRate}%` : "—", t("rr.cTreated.foot"), s.treatedRate != null ? (s.treatedRate >= 70 ? "#34d399" : s.treatedRate >= 40 ? "#fbbf24" : "#f87171") : undefined),
    card(t("rr.cExposure"), money(s.totalALE), fmt("rr.cExposure.foot", { q: s.quantified, total: s.risks })),
  ].join("");

  const byLevel = ["Critical", "High", "Medium", "Low", "Very Low"].filter((k) => s.byLevel[k]).map((k) => `<span class="bd">${lvl(k)} <b>${s.byLevel[k]}</b></span>`).join("");
  const byTreat = Object.entries(s.byTreatment).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");
  const byCat = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("rr.more", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("rr.noFindings")}</div>`;

  const table = `<table class="rr"><thead><tr>
      <th>${t("rr.thRisk")}</th><th title="${t("rr.thLevel.title")}">${t("rr.thLevel")}</th><th>${t("rr.thTreatment")}</th><th>${t("rr.thStatus")}</th><th class="num" title="${t("rr.thAle.title")}">ALE</th><th title="${t("rr.thReview.title")}">${t("rr.thReview")}</th><th title="${t("rr.thScore.title")}">${t("rr.thScore")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("rr-body").innerHTML = `<div class="rr-cards">${cards}</div>
    ${strategySection()}
    <div class="rr-section">${fmt("rr.secWorklist", { n: d.findings.length })}</div>${findings}
    <div class="rr-section">${t("rr.secByLevel")}</div><div class="breakdown">${byLevel || `<span class="muted">${t("rr.none")}</span>`}</div>
    ${byTreat ? `<div class="rr-section">${t("rr.secByTreatment")}</div><div class="breakdown">${byTreat}</div>` : ""}
    ${byCat ? `<div class="rr-section">${t("rr.secByCategory")}</div><div class="breakdown">${byCat}</div>` : ""}
    <div class="rr-section">${fmt("rr.secRisks", { n: d.rows.length })}</div>${table}
    ${measuresSection()}
    <div class="legend">${t("rr.legend")}</div>`;
  wireGov();
  document.querySelectorAll<HTMLButtonElement>(".mchip[data-entry]").forEach((b) => b.addEventListener("click", () => openEntryMeasures(Number(b.dataset.entry), b.dataset.name || "")));
  document.querySelectorAll<HTMLButtonElement>(".mchip[data-plan-entry]").forEach((b) => b.addEventListener("click", () => void openTreatmentPlan(Number(b.dataset.planEntry), b.dataset.name || "")));
}

// ── Risk-management strategy & appetite ───────────────────────────────────────
const RANK_LABEL_KEY = ["rr.lvl.critical", "rr.lvl.high", "rr.lvl.medium", "rr.lvl.low", "rr.lvl.veryLow"];
const tolLabel = (rank: number): string => t(RANK_LABEL_KEY[Math.max(0, Math.min(4, rank))] || "rr.lvl.medium");

function strategySection(): string {
  const g = GOV;
  const st = g?.strategy;
  const appetite = g?.appetite ?? [];
  const head = `<div class="rr-section">${t("rr.secStrategy")}<button class="rr-mini" id="rr-edit-strategy">${t("rr.editStrategy")}</button></div>`;
  if (!st && !appetite.length) {
    return `${head}<div class="muted" style="padding:8px 0">${t("rr.noStrategy")}</div>`;
  }
  const meta = st ? `<div class="strat-meta">
      ${st.Methodology ? `<span class="bd">${t("rr.sMethodology")}: <b>${esc(st.Methodology)}</b></span>` : ""}
      ${st.RiskScale ? `<span class="bd">${t("rr.sScale")}: <b>${esc(st.RiskScale)}</b></span>` : ""}
      ${st.ReviewCadenceMonths ? `<span class="bd">${t("rr.sReview")}: <b>${fmt("rr.everyMonths", { n: esc(st.ReviewCadenceMonths) })}</b></span>` : ""}
      ${st.Owner ? `<span class="bd">${t("rr.sOwner")}: <b>${esc(st.Owner)}</b></span>` : ""}
      ${st.ApprovedBy ? `<span class="bd">${t("rr.sApproved")}: <b>${esc(st.ApprovedBy)}${st.ApprovedDate ? ` · ${esc(st.ApprovedDate)}` : ""}</b></span>` : ""}
    </div>` : "";
  const stmt = st?.Statement ? `<div class="strat-stmt">${esc(st.Statement)}</div>` : "";
  const objs = st?.Objectives ? `<div class="strat-stmt muted" style="font-size:12px">${esc(st.Objectives)}</div>` : "";
  const appTable = appetite.length ? `<table class="rr" style="margin-top:8px"><thead><tr>
      <th>${t("rr.thCategory")}</th><th>${t("rr.thAppetite")}</th><th>${t("rr.thTolerance")}</th><th>${t("rr.thRationale")}</th></tr></thead><tbody>
      ${appetite.map((a) => `<tr><td><b>${esc(a.Category)}</b></td><td>${a.AppetiteLevel ? `<span class="bd">${esc(a.AppetiteLevel)}</span>` : "<span class='muted'>—</span>"}</td>
        <td><span class="lvl lvl-${a.ToleranceRank}">≤ ${esc(tolLabel(a.ToleranceRank))}</span></td>
        <td class="muted" style="font-size:12px">${esc(a.Rationale || "—")}</td></tr>`).join("")}</tbody></table>` : "";
  return `${head}${stmt}${objs}${meta}${appTable}`;
}

// ── Measures library ──────────────────────────────────────────────────────────
const MEASURE_STATUS_COLOR: Record<string, string> = { Proposed: "#94a3b8", Approved: "#60a5fa", Implemented: "#34d399", Verified: "#22d3ee", Retired: "#64748b" };
function measuresSection(): string {
  const g = GOV;
  const ms = g?.measures ?? [];
  const head = `<div class="rr-section">${fmt("rr.secMeasures", { n: ms.length })}<button class="rr-mini" id="rr-add-measure">${t("rr.addMeasure")}</button></div>`;
  if (!ms.length) return `${head}<div class="muted" style="padding:8px 0">${t("rr.noMeasures")}</div>`;
  const rows = ms.map((m) => `<tr>
      <td><b>${esc(m.Name)}</b>${m.Ref ? ` <span class="muted" style="font-size:11px">${esc(m.Ref)}</span>` : ""}${m.Description ? `<div class="muted" style="font-size:11px">${esc(m.Description)}</div>` : ""}</td>
      <td>${m.MeasureType ? `<span class="bd">${esc(m.MeasureType)}</span>` : "<span class='muted'>—</span>"}</td>
      <td>${m.Effectiveness ? esc(m.Effectiveness) : "<span class='muted'>—</span>"}</td>
      <td>${m.ControlRef ? `<span class="muted" style="font-size:11px">${esc(m.ControlRef)}</span>` : "<span class='muted'>—</span>"}</td>
      <td><span class="muted">${m.usage || 0}</span></td>
      <td><select class="mstatus" data-id="${m.RiskMeasureID}">${(g!.options.measureStatuses).map((s) => `<option${s === m.Status ? " selected" : ""}>${esc(s)}</option>`).join("")}</select></td>
    </tr>`).join("");
  return `${head}<table class="rr"><thead><tr>
      <th>${t("rr.thMeasure")}</th><th>${t("rr.thType")}</th><th>${t("rr.thEffectiveness")}</th><th>${t("rr.thControlRef")}</th><th title="${t("rr.thUsage.title")}">${t("rr.thUsage")}</th><th>${t("rr.thStatus")}</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
}

function wireGov(): void {
  const eb = document.getElementById("rr-edit-strategy"); if (eb) eb.addEventListener("click", openStrategyModal);
  const ab = document.getElementById("rr-add-measure"); if (ab) ab.addEventListener("click", openMeasureModal);
  document.querySelectorAll<HTMLSelectElement>("select.mstatus").forEach((sel) => sel.addEventListener("change", () =>
    void api("/api/risk-register/measure/update", { id: Number(sel.dataset.id), status: sel.value }).then(() => toast(t("rr.measureUpdated")))));
}

// ── Guided "new risk" modal ───────────────────────────────────────────────────
let lookupsLoaded = false;

function inherentPreview(): void {
  const prob = Number((document.getElementById("rr-f-prob") as HTMLSelectElement).value);
  const impact = Number((document.getElementById("rr-f-impact") as HTMLSelectElement).value);
  const el = $("rr-f-preview");
  if (!prob || !impact) { el.textContent = t("rr.setLikelihood"); el.style.color = "#64748b"; return; }
  const s = prob * impact;
  const [label, color] = s >= 20 ? ["Critical", "#f87171"] : s >= 12 ? ["High", "#fb923c"]
    : s >= 6 ? ["Medium", "#fbbf24"] : s >= 3 ? ["Low", "#86efac"] : ["Very Low", "#94a3b8"];
  el.innerHTML = `<b style="color:${color}">${levelLabel(label)}</b> <span class="muted">(${prob}×${impact} = ${s})</span>`;
}

async function fillSelect(selId: string, db: string, table: string, idCol: string, labelCol: string): Promise<void> {
  try {
    const r = await fetch(`/api/lookup?db=${db}&table=${table}&idCol=${idCol}&labelCol=${labelCol}`);
    if (!r.ok) return;
    const list = (await r.json()) as { id: unknown; label: unknown }[];
    const sel = document.getElementById(selId) as HTMLSelectElement;
    for (const o of (Array.isArray(list) ? list : []).slice(0, 500)) {
      if (o.label == null || String(o.label).trim() === "") continue;
      const opt = document.createElement("option");
      opt.value = String(o.id); opt.textContent = String(o.label);
      sel.appendChild(opt);
    }
  } catch { /* optional */ }
}

function openRiskModal(): void {
  for (const id of ["rr-f-title", "rr-f-desc", "rr-f-review", "rr-f-target"]) (document.getElementById(id) as HTMLInputElement).value = "";
  for (const id of ["rr-f-category", "rr-f-owner", "rr-f-prob", "rr-f-impact", "rr-f-treatment", "rr-f-asset"]) (document.getElementById(id) as HTMLSelectElement).value = "";
  (document.getElementById("rr-f-status") as HTMLSelectElement).value = "Open";
  $("rr-f-err").textContent = "";
  inherentPreview();
  if (!lookupsLoaded) {
    lookupsLoaded = true;
    void fillSelect("rr-f-owner", "XORCISM", "PERSON", "PersonID", "FullName");
    void fillSelect("rr-f-asset", "XORCISM", "ASSET", "AssetID", "AssetName");
  }
  $("rr-modal").classList.add("open");
  ($("rr-f-title") as HTMLInputElement).focus();
}
function closeRiskModal(): void { $("rr-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createRisk(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const title = v("rr-f-title").trim();
  const err = $("rr-f-err");
  if (!title) { err.textContent = t("rr.errTitle"); ($("rr-f-title") as HTMLInputElement).focus(); return; }
  const btn = $("rr-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = t("rr.creating");
  try {
    const body = {
      title, description: v("rr-f-desc").trim() || undefined, category: v("rr-f-category") || undefined,
      ownerPersonId: v("rr-f-owner") || undefined, assetId: v("rr-f-asset") || undefined,
      probability: v("rr-f-prob") || undefined, impact: v("rr-f-impact") || undefined,
      treatment: v("rr-f-treatment") || undefined, status: v("rr-f-status"),
      reviewDate: v("rr-f-review") || undefined, targetDate: v("rr-f-target") || undefined,
    };
    const r = await fetch("/api/risk-register/entry", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeRiskModal();
    await load();
    const link = `/?db=XCOMPLIANCE&table=RISKREGISTERENTRY&editCol=RiskRegisterEntryID&editVal=${d.id}`;
    toast(fmt("rr.added", { link }));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

async function api(url: string, body: unknown): Promise<any> {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return d;
}

// ── strategy & appetite modal ─────────────────────────────────────────────────
function appetiteRowHtml(a?: Partial<{ Category: string; AppetiteLevel: string; ToleranceRank: number; Rationale: string }>): string {
  const levels = GOV?.options.appetiteLevels ?? [];
  const ranks = GOV?.options.toleranceRanks ?? [];
  return `<div class="appetite-row" style="display:grid;grid-template-columns:1.4fr 1fr 1.2fr 1.6fr auto;gap:6px;margin-bottom:6px">
    <input class="ap-cat" placeholder="${t("rr.thCategory")}" value="${esc(a?.Category ?? "")}">
    <select class="ap-level"><option value="">—</option>${levels.map((l) => `<option${l === a?.AppetiteLevel ? " selected" : ""}>${esc(l)}</option>`).join("")}</select>
    <select class="ap-tol">${ranks.map((rk) => `<option value="${rk.rank}"${a?.ToleranceRank === rk.rank ? " selected" : ""}>≤ ${esc(tolLabel(rk.rank))}</option>`).join("")}</select>
    <input class="ap-rat" placeholder="${t("rr.thRationale")}" value="${esc(a?.Rationale ?? "")}">
    <button class="rr-mini ap-rm" type="button" title="${t("rr.remove")}">✕</button></div>`;
}
function openStrategyModal(): void {
  const st = GOV?.strategy ?? {};
  const v = (id: string, val: unknown) => { (document.getElementById(id) as HTMLInputElement).value = val == null ? "" : String(val); };
  v("rr-s-statement", st.Statement); v("rr-s-objectives", st.Objectives); v("rr-s-methodology", st.Methodology);
  v("rr-s-scale", st.RiskScale); v("rr-s-cadence", st.ReviewCadenceMonths); v("rr-s-owner", st.Owner);
  v("rr-s-approvedby", st.ApprovedBy); v("rr-s-approveddate", st.ApprovedDate);
  const host = $("rr-s-appetite"); host.innerHTML = (GOV?.appetite ?? []).map((a) => appetiteRowHtml(a)).join("") || appetiteRowHtml();
  $("rr-s-err").textContent = "";
  host.querySelectorAll<HTMLButtonElement>(".ap-rm").forEach((b) => b.addEventListener("click", () => b.closest(".appetite-row")?.remove()));
  $("rr-strategy-modal").classList.add("open");
}
async function saveStrategy(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement).value;
  const appetite = Array.from(document.querySelectorAll<HTMLElement>("#rr-s-appetite .appetite-row")).map((r) => ({
    category: (r.querySelector(".ap-cat") as HTMLInputElement).value.trim(),
    appetiteLevel: (r.querySelector(".ap-level") as HTMLSelectElement).value,
    toleranceRank: Number((r.querySelector(".ap-tol") as HTMLSelectElement).value),
    rationale: (r.querySelector(".ap-rat") as HTMLInputElement).value.trim(),
  })).filter((a) => a.category);
  const btn = $("rr-s-save") as HTMLButtonElement; btn.disabled = true; $("rr-s-err").textContent = t("rr.saving");
  try {
    await api("/api/risk-register/strategy", {
      statement: v("rr-s-statement"), objectives: v("rr-s-objectives"), methodology: v("rr-s-methodology"),
      riskScale: v("rr-s-scale"), reviewCadenceMonths: v("rr-s-cadence") || null, owner: v("rr-s-owner"),
      approvedBy: v("rr-s-approvedby"), approvedDate: v("rr-s-approveddate") || undefined, appetite,
    });
    $("rr-strategy-modal").classList.remove("open"); await load(); toast(t("rr.strategySaved"));
  } catch (e) { $("rr-s-err").textContent = `⚠️ ${e}`; } finally { btn.disabled = false; }
}

// ── measure create modal ──────────────────────────────────────────────────────
function openMeasureModal(): void {
  for (const id of ["rr-m-name", "rr-m-ref", "rr-m-desc", "rr-m-control", "rr-m-cost"]) (document.getElementById(id) as HTMLInputElement).value = "";
  const types = GOV?.options.measureTypes ?? []; const statuses = GOV?.options.measureStatuses ?? [];
  (document.getElementById("rr-m-type") as HTMLSelectElement).innerHTML = `<option value="">—</option>` + types.map((x) => `<option>${esc(x)}</option>`).join("");
  (document.getElementById("rr-m-status") as HTMLSelectElement).innerHTML = statuses.map((x) => `<option${x === "Proposed" ? " selected" : ""}>${esc(x)}</option>`).join("");
  (document.getElementById("rr-m-eff") as HTMLSelectElement).value = "";
  $("rr-m-err").textContent = "";
  $("rr-measure-modal").classList.add("open");
  ($("rr-m-name") as HTMLInputElement).focus();
}
async function saveMeasure(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;
  const name = v("rr-m-name").trim();
  if (!name) { $("rr-m-err").textContent = t("rr.errMeasureName"); return; }
  const btn = $("rr-m-save") as HTMLButtonElement; btn.disabled = true; $("rr-m-err").textContent = t("rr.saving");
  try {
    await api("/api/risk-register/measure", {
      name, ref: v("rr-m-ref").trim() || undefined, description: v("rr-m-desc").trim() || undefined,
      measureType: v("rr-m-type") || undefined, controlRef: v("rr-m-control").trim() || undefined,
      effectiveness: v("rr-m-eff") || undefined, cost: v("rr-m-cost").trim() || undefined, status: v("rr-m-status"),
    });
    $("rr-measure-modal").classList.remove("open"); await load(); toast(t("rr.measureAdded"));
  } catch (e) { $("rr-m-err").textContent = `⚠️ ${e}`; } finally { btn.disabled = false; }
}

// ── entry ↔ measures modal ────────────────────────────────────────────────────
let ENTRY_ID = 0;
async function openEntryMeasures(entryId: number, ref: string): Promise<void> {
  ENTRY_ID = entryId;
  $("rr-e-title").textContent = fmt("rr.entryMeasuresTitle", { ref });
  const picker = $("rr-e-picker") as HTMLSelectElement;
  picker.innerHTML = `<option value="">${t("rr.pickMeasure")}</option>` + (GOV?.measures ?? []).map((m) => `<option value="${m.RiskMeasureID}">${esc(m.Name)}</option>`).join("");
  $("rr-entry-modal").classList.add("open");
  await renderEntryMeasures();
}
async function renderEntryMeasures(): Promise<void> {
  const host = $("rr-e-list");
  host.innerHTML = `<div class="muted">${t("rr.loadingMeasures")}</div>`;
  try {
    const r = await fetch(`/api/risk-register/entry/${ENTRY_ID}/measures`);
    const d = await r.json();
    const list = (d.measures ?? []) as { LinkID: number; ImplementationStatus: string; Name: string; MeasureType: string; Status: string }[];
    const statuses = GOV?.options.linkStatuses ?? [];
    host.innerHTML = list.length ? list.map((l) => `<div class="el-row" style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #1e2133">
        <span style="flex:1"><b>${esc(l.Name)}</b>${l.MeasureType ? ` <span class="muted" style="font-size:11px">${esc(l.MeasureType)}</span>` : ""}</span>
        <select class="el-status" data-link="${l.LinkID}">${statuses.map((s) => `<option${s === l.ImplementationStatus ? " selected" : ""}>${esc(s)}</option>`).join("")}</select>
        <button class="rr-mini el-rm" data-link="${l.LinkID}" title="${t("rr.remove")}">✕</button></div>`).join("")
      : `<div class="muted" style="padding:8px 0">${t("rr.noLinkedMeasures")}</div>`;
    host.querySelectorAll<HTMLSelectElement>(".el-status").forEach((sel) => sel.addEventListener("change", () => void api("/api/risk-register/link/update", { linkId: Number(sel.dataset.link), status: sel.value })));
    host.querySelectorAll<HTMLButtonElement>(".el-rm").forEach((b) => b.addEventListener("click", async () => { await api("/api/risk-register/link/delete", { linkId: Number(b.dataset.link) }); await renderEntryMeasures(); await load(); }));
  } catch (e) { host.innerHTML = `<div class="muted">⚠️ ${esc(e)}</div>`; }
}
async function addEntryMeasure(): Promise<void> {
  const mid = Number(($("rr-e-picker") as HTMLSelectElement).value);
  if (!mid) return;
  try { await api(`/api/risk-register/entry/${ENTRY_ID}/measure`, { measureId: mid }); await renderEntryMeasures(); await load(); }
  catch (e) { toast(`⚠️ ${e}`); }
}

function openRegisterImport(): void {
  openXlsxImport({
    title: t("rr.imp.title"),
    lead: t("rr.imp.lead"),
    endpoint: "/api/risk-register/import",
    upsertLabel: t("rr.imp.upsert"),
    templateName: "risk-register",
    fields: [
      { key: "title", label: t("rr.imp.f.title"), required: true, guess: ["title", "risk", "name", "titre", "libelle", "intitule"] },
      { key: "ref", label: t("rr.imp.f.ref"), guess: ["ref", "reference", "id", "code", "risk id", "risk ref"] },
      { key: "category", label: t("rr.imp.f.category"), guess: ["category", "categorie", "type", "domain", "domaine"] },
      { key: "description", label: t("rr.imp.f.description"), guess: ["description", "desc", "details", "detail", "summary"] },
      { key: "status", label: t("rr.imp.f.status"), guess: ["status", "statut", "state", "etat"] },
      { key: "treatment", label: t("rr.imp.f.treatment"), guess: ["treatment", "traitement", "response", "strategy", "reponse"] },
      { key: "probability", label: t("rr.imp.f.probability"), guess: ["probability", "probabilite", "likelihood", "vraisemblance", "proba"] },
      { key: "impact", label: t("rr.imp.f.impact"), guess: ["impact", "severity", "gravite", "consequence"] },
      { key: "reviewDate", label: t("rr.imp.f.reviewDate"), guess: ["review", "review date", "revue", "date revue", "next review"] },
      { key: "targetDate", label: t("rr.imp.f.targetDate"), guess: ["target", "target date", "due", "due date", "echeance", "deadline"] },
    ],
    onDone: () => { void load(); },
  });
}

function openAssessmentImport(): void {
  openXlsxImport({
    title: t("ra.imp.title"),
    lead: t("ra.imp.lead"),
    endpoint: "/api/risk-assessment/import",
    upsertLabel: t("ra.imp.upsert"),
    templateName: "risk-assessment",
    fields: [
      { key: "name", label: t("ra.imp.f.name"), required: true, guess: ["name", "nom", "title", "titre", "assessment", "evaluation"] },
      { key: "description", label: t("ra.imp.f.description"), guess: ["description", "desc", "scope", "perimetre", "details"] },
      { key: "status", label: t("ra.imp.f.status"), guess: ["status", "statut", "state", "etat"] },
      { key: "version", label: t("ra.imp.f.version"), guess: ["version", "ver", "rev", "revision"] },
      { key: "date", label: t("ra.imp.f.date"), guess: ["date", "assessment date", "date evaluation", "created", "creation"] },
    ],
    onDone: () => { void load(); },
  });
}

// ── Advanced treatment plan modal ──────────────────────────────────────────────
let PERSONS: { id: number; label: string }[] | null = null;
async function loadPersons(): Promise<void> {
  if (PERSONS) return;
  try { const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName"); PERSONS = r.ok ? await r.json() : []; } catch { PERSONS = []; }
}
const personOpts = (sel: unknown, blank: string): string =>
  `<option value="">${esc(blank)}</option>` + (PERSONS || []).map((p) => `<option value="${p.id}"${String(sel ?? "") === String(p.id) ? " selected" : ""}>${esc(p.label || ("#" + p.id))}</option>`).join("");
const selOpts = (arr: readonly string[], sel: unknown, labelKey?: string): string =>
  arr.map((o) => `<option value="${esc(o)}"${String(sel ?? "") === o ? " selected" : ""}>${labelKey ? esc(t(`${labelKey}.${o}`)) : esc(o)}</option>`).join("");

let TP_ENTRY = 0;
async function openTreatmentPlan(entryId: number, ref: string): Promise<void> {
  TP_ENTRY = entryId;
  await loadPersons();
  document.getElementById("rr-tp-modal")?.remove();
  const wrap = document.createElement("div"); wrap.id = "rr-tp-modal";
  wrap.style.cssText = "position:fixed;inset:0;background:rgba(4,6,15,.72);display:flex;align-items:flex-start;justify-content:center;z-index:1200;overflow:auto";
  wrap.innerHTML = `<div style="background:#0f1322;border:1px solid #2d3250;border-radius:12px;padding:18px 20px;margin:36px 16px;max-width:820px;width:100%">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><b style="font-size:16px;color:#e7ebf3">${t("rr.tp.title")}</b><span class="muted" style="font-size:12px">${esc(ref)}</span><span style="flex:1"></span><button id="rr-tp-close" class="rr-mini">✕</button></div>
    <div id="rr-tp-body"><div class="muted" style="padding:20px;text-align:center">${t("rr.loading")}</div></div>
  </div>`;
  document.body.appendChild(wrap);
  wrap.addEventListener("click", (e) => { if (e.target === wrap) wrap.remove(); });
  document.getElementById("rr-tp-close")!.addEventListener("click", () => wrap.remove());
  await renderTreatmentPlan();
}

async function renderTreatmentPlan(): Promise<void> {
  const body = document.getElementById("rr-tp-body"); if (!body) return;
  let d: any;
  try { const r = await fetch(`/api/risk-register/entry/${TP_ENTRY}/treatment-plan`); d = await r.json(); if (!r.ok) throw new Error(d.error); }
  catch (e) { body.innerHTML = `<div class="muted" style="padding:16px">⚠️ ${esc(e)}</div>`; return; }
  const p = d.plan || {}; const o = d.options;
  const inp = "background:#0f1117;border:1px solid #2d3250;border-radius:6px;padding:6px 9px;color:#e2e8f0;font-size:12px;font-family:inherit";
  const barColor = d.overdue ? "#f87171" : d.progress >= 100 ? "#34d399" : "#a78bfa";
  const actions = (d.actions || []).map((a: any) => {
    const overdue = a.Status !== "done" && a.Status !== "cancelled" && a.DueDate && Date.parse(a.DueDate) < Date.now();
    return `<tr data-aid="${a.ActionID}">
      <td><input class="ta-title" value="${esc(a.Title)}" style="${inp};width:100%"></td>
      <td><select class="ta-owner" style="${inp}">${personOpts(a.ActionOwnerPersonID, "—")}</select></td>
      <td><input type="date" class="ta-due" value="${esc((a.DueDate || "").slice(0, 10))}" style="${inp}"${overdue ? ';border-color:#f87171' : ""}></td>
      <td><select class="ta-status" style="${inp}">${selOpts(o.actionStatuses, a.Status, "rr.tp.as")}</select></td>
      <td><input type="number" class="ta-prog" min="0" max="100" value="${a.Progress ?? 0}" style="${inp};width:64px"></td>
      <td style="white-space:nowrap"><button class="rr-mini ta-save">${t("rr.tp.save")}</button> <button class="rr-mini ta-del" style="color:#f87171">✕</button></td>
    </tr>`;
  }).join("") || `<tr><td colspan="6" class="muted" style="padding:8px;text-align:center">${t("rr.tp.noActions")}</td></tr>`;

  body.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:8px">
      <label class="tpf">${t("rr.tp.strategy")}<select id="tp-strategy" style="${inp}"><option value="">—</option>${selOpts(o.strategies, p.Strategy, "rr.tp.st")}</select></label>
      <label class="tpf">${t("rr.tp.status")}<select id="tp-status" style="${inp}">${selOpts(o.planStatuses, p.Status || "draft", "rr.tp.ps")}</select></label>
      <label class="tpf">${t("rr.tp.owner")}<select id="tp-owner" style="${inp}">${personOpts(p.OwnerPersonID, "—")}</select></label>
      <label class="tpf">${t("rr.tp.targetLevel")}<input id="tp-trl" value="${esc(p.TargetResidualLevel || "")}" placeholder="Low" style="${inp}"></label>
      <label class="tpf">${t("rr.tp.targetDate")}<input type="date" id="tp-td" value="${esc((p.TargetDate || "").slice(0, 10))}" style="${inp}"></label>
      <label class="tpf">${t("rr.tp.budget")}<input type="number" id="tp-budget" value="${p.Budget ?? ""}" style="${inp}"></label>
    </div>
    <label class="tpf" style="display:block;margin-bottom:8px">${t("rr.tp.rationale")}<textarea id="tp-rat" rows="2" style="${inp};width:100%;box-sizing:border-box">${esc(p.Rationale || "")}</textarea></label>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <div style="flex:1"><div style="height:8px;border-radius:4px;background:#1e2133;overflow:hidden"><i style="display:block;height:100%;width:${d.progress}%;background:${barColor}"></i></div></div>
      <span class="muted" style="font-size:12px">${d.progress}%</span>
      ${d.overdue ? `<span class="tag" style="background:#7f1d1d;color:#fecaca">${t("rr.tp.overdue")}</span>` : ""}
      ${p.ApprovedBy ? `<span class="tag" style="background:#064e3b;color:#6ee7b7">✓ ${esc(p.ApprovedBy)} · ${esc((p.ApprovedDate || "").slice(0, 10))}</span>` : ""}
      <button class="rr-mini" id="tp-save">${t("rr.tp.savePlan")}</button>
      <button class="rr-mini" id="tp-approve" style="border-color:#34d399;color:#6ee7b7">${t("rr.tp.approve")}</button>
    </div>
    <div class="rr-section" style="margin-top:4px">${t("rr.tp.actions")}</div>
    <table class="rr" style="font-size:12px"><thead><tr><th>${t("rr.tp.action")}</th><th>${t("rr.tp.owner")}</th><th>${t("rr.tp.due")}</th><th>${t("rr.tp.status")}</th><th>%</th><th></th></tr></thead><tbody>${actions}</tbody></table>
    <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap">
      <input id="tp-new-title" placeholder="${t("rr.tp.newActionPh")}" style="${inp};flex:1;min-width:200px">
      <input type="date" id="tp-new-due" style="${inp}">
      <select id="tp-new-owner" style="${inp}">${personOpts("", "—")}</select>
      <button class="rr-mini" id="tp-add">+ ${t("rr.tp.addAction")}</button>
    </div>`;

  const v = (id: string) => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  document.getElementById("tp-save")!.addEventListener("click", async () => {
    try {
      await api(`/api/risk-register/entry/${TP_ENTRY}/treatment-plan`, { strategy: v("tp-strategy"), status: v("tp-status"), ownerPersonId: v("tp-owner"), targetResidualLevel: v("tp-trl"), targetDate: v("tp-td"), budget: v("tp-budget"), rationale: v("tp-rat") });
      toast(t("rr.tp.saved")); await renderTreatmentPlan(); void load();
    } catch (e) { toast(`⚠️ ${esc(e)}`); }
  });
  document.getElementById("tp-approve")!.addEventListener("click", async () => {
    try { await api(`/api/risk-register/entry/${TP_ENTRY}/treatment-plan/approve`, {}); toast(t("rr.tp.approved")); await renderTreatmentPlan(); }
    catch (e) { toast(`⚠️ ${esc(e)}`); }
  });
  document.getElementById("tp-add")!.addEventListener("click", async () => {
    const title = v("tp-new-title").trim(); if (!title) return;
    try { await api(`/api/risk-register/entry/${TP_ENTRY}/treatment-plan/action`, { title, dueDate: v("tp-new-due"), actionOwnerPersonId: v("tp-new-owner") }); await renderTreatmentPlan(); void load(); }
    catch (e) { toast(`⚠️ ${esc(e)}`); }
  });
  body.querySelectorAll<HTMLTableRowElement>("tr[data-aid]").forEach((tr) => {
    const aid = Number(tr.dataset.aid);
    const av = (cls: string) => (tr.querySelector("." + cls) as HTMLInputElement | HTMLSelectElement).value;
    tr.querySelector(".ta-save")!.addEventListener("click", async () => {
      try { const r = await fetch(`/api/risk-register/treatment-action/${aid}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title: av("ta-title"), actionOwnerPersonId: av("ta-owner"), dueDate: av("ta-due"), status: av("ta-status"), progress: av("ta-prog") }) }); if (!r.ok) throw new Error((await r.json()).error); toast(t("rr.tp.actionSaved")); await renderTreatmentPlan(); void load(); }
      catch (e) { toast(`⚠️ ${esc(e)}`); }
    });
    tr.querySelector(".ta-del")!.addEventListener("click", async () => {
      if (!window.confirm(t("rr.tp.delConfirm"))) return;
      try { await fetch(`/api/risk-register/treatment-action/${aid}`, { method: "DELETE" }); await renderTreatmentPlan(); void load(); }
      catch (e) { toast(`⚠️ ${esc(e)}`); }
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  $("rr-new").addEventListener("click", openRiskModal);
  $("rr-import").addEventListener("click", openRegisterImport);
  $("rr-import-ra").addEventListener("click", openAssessmentImport);
  $("rr-s-save").addEventListener("click", () => void saveStrategy());
  $("rr-s-cancel").addEventListener("click", () => $("rr-strategy-modal").classList.remove("open"));
  $("rr-s-add-appetite").addEventListener("click", () => { const h = $("rr-s-appetite"); h.insertAdjacentHTML("beforeend", appetiteRowHtml()); const row = h.lastElementChild as HTMLElement; row?.querySelector(".ap-rm")?.addEventListener("click", () => row.remove()); });
  $("rr-m-save").addEventListener("click", () => void saveMeasure());
  $("rr-m-cancel").addEventListener("click", () => $("rr-measure-modal").classList.remove("open"));
  $("rr-e-add").addEventListener("click", () => void addEntryMeasure());
  $("rr-e-close").addEventListener("click", () => $("rr-entry-modal").classList.remove("open"));
  for (const m of ["rr-strategy-modal", "rr-measure-modal", "rr-entry-modal"]) $(m).addEventListener("click", (e) => { if (e.target === $(m)) $(m).classList.remove("open"); });
  $("rr-cancel").addEventListener("click", closeRiskModal);
  $("rr-create").addEventListener("click", () => void createRisk());
  for (const id of ["rr-f-prob", "rr-f-impact"]) (document.getElementById(id) as HTMLSelectElement).addEventListener("change", inherentPreview);
  $("rr-modal").addEventListener("click", (e) => { if (e.target === $("rr-modal")) closeRiskModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeRiskModal(); });
  initI18n();
  void load();
});
