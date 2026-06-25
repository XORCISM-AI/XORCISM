/**
 * pqcmm.ts — PQCMM (Post-Quantum Cryptography Maturity Model) quantum-readiness (/pqcmm).
 * The 6-level model + per-subject maturity assessments + posture rollup, from /api/pqcmm.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Level { level: number; name: string; summary: string; criteria: string; }
interface Row { id: number; subject: string; type: string; assetId: number | null; asset: string | null; current: number; currentName: string; target: number | null; gap: number; standard: string; cryptoAgile: boolean; zeroLegacy: boolean; hasCBOM: boolean; owner: string | null; status: string; assessedDate: string | null; reviewInDays: number | null; reviewOverdue: boolean; }
interface Finding { id: number; subject: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; reason: string; kind: string; label: string; }
interface Inventory {
  levels: Level[]; rows: Row[]; findings: Finding[];
  summary: { assessments: number; byLevel: number[]; quantumVulnerable: number; productionReady: number; managed: number; avgLevel: number | null; maturityScore: number; belowTarget: number; noTarget: number; withCBOM: number; cryptoAgile: number; reviewOverdue: number; };
}

// level 0..5 → colour (red → emerald)
const LCOL = ["#ef4444", "#fb923c", "#fbbf24", "#a3e635", "#34d399", "#10b981"];
const lvlPill = (n: number, name?: string): string => `<span class="lvl" style="background:${LCOL[n]}22;color:${LCOL[n]};border:1px solid ${LCOL[n]}66">L${n}${name ? " " + esc(name) : ""}</span>`;
const scoreColor = (n: number): string => (n >= 80 ? "#10b981" : n >= 50 ? "#fbbf24" : n >= 25 ? "#fb923c" : "#ef4444");

function card(lbl: string, val: string, foot: string, color?: string, cls = "pq-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: Row): string {
  const flags = [r.hasCBOM ? "CBOM" : "", r.cryptoAgile ? t("pq.flagAgile") : "", r.zeroLegacy ? t("pq.flagZero") : ""].filter(Boolean).map((f) => `<span class="flag">${f}</span>`).join("");
  const review = r.reviewInDays == null ? "" : r.reviewOverdue ? ` <span class="gap" style="background:#3f1d1d;color:#fca5a5">${fmt("pq.reviewOverdue", { n: -r.reviewInDays })}</span>` : "";
  return `<tr>
    <td><div class="pname">${esc(r.subject)}</div><div class="muted" style="font-size:11px">${esc(r.type)}${r.asset ? ` · ${esc(r.asset)}` : ""}${r.owner ? ` · ${esc(r.owner)}` : ""}${r.standard ? ` · ${esc(r.standard)}` : ""}</div></td>
    <td>${lvlPill(r.current, r.currentName)}${r.target != null ? ` <span class="muted">→ L${r.target}</span>` : ""}${r.gap > 0 ? `<span class="gap">${fmt("pq.gapN", { n: r.gap })}</span>` : ""}${review}</td>
    <td>${flags || '<span class="muted">—</span>'}</td>
    <td><span class="muted">${esc(r.status)}${r.assessedDate ? ` · ${esc(r.assessedDate)}` : ""}</span></td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const color = f.kind === "vulnerable" ? "#ef4444" : f.kind === "below-target" ? "#fb923c" : "#94a3b8";
  return `<li><span class="dot" style="background:${color}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="/?db=XCOMPLIANCE&table=PQCMMASSESSMENT&filterCol=AssessmentID&filterVal=${esc(f.id)}">${esc(f.subject)}</a> — ${esc(f.label)}</li>`;
}

function levelRef(levels: Level[]): string {
  return `<div class="pq-levels">${levels.map((l) => `<div class="pq-lv" style="border-left-color:${LCOL[l.level]}">
    <div class="ln" style="color:${LCOL[l.level]}">L${l.level}</div>
    <div><div class="lt">${esc(l.name)}</div><div class="ld">${esc(l.summary)}</div><div class="lc">▸ ${esc(l.criteria)}</div></div>
  </div>`).join("")}</div>`;
}

function levelOpts(levels: Level[], sel?: number, blank?: string): string {
  return (blank != null ? `<option value="">${esc(blank)}</option>` : "") +
    levels.map((l) => `<option value="${l.level}"${sel === l.level ? " selected" : ""}>L${l.level} — ${esc(l.name)}</option>`).join("");
}

async function assess(levels: Level[]): Promise<void> {
  const stat = $("pq-stat"), btn = $("pq-go") as HTMLButtonElement;
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;
  const ck = (id: string): boolean => (document.getElementById(id) as HTMLInputElement).checked;
  const subjectName = v("pq-subject").trim();
  if (!subjectName) { stat.innerHTML = t("pq.errSubject"); return; }
  btn.disabled = true; stat.textContent = t("pq.saving");
  try {
    const body = { subjectName, subjectType: v("pq-type"), currentLevel: Number(v("pq-current")), targetLevel: v("pq-target") === "" ? undefined : Number(v("pq-target")), standard: v("pq-standard").trim() || undefined, cryptoAgile: ck("pq-agile"), zeroLegacy: ck("pq-zero"), hasCBOM: ck("pq-cbom") };
    const r = await fetch("/api/pqcmm/assess", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    stat.innerHTML = fmt("pq.assessed", { s: `<b>${esc(subjectName)}</b>`, n: esc(d.currentLevel), name: esc(levels[d.currentLevel]?.name ?? "") });
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
  void levels;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/pqcmm"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("pq-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  if (!d.levels.length) { $("pq-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("pq.notSeeded")}</div>`; return; }
  const s = d.summary;

  const cards = [
    card(t("pq.cReadiness"), `${s.maturityScore}%`, s.avgLevel != null ? fmt("pq.cReadiness.foot", { n: s.avgLevel }) : t("pq.cReadiness.footNone"), scoreColor(s.maturityScore), "pq-card pq-score"),
    card(t("pq.cAssessments"), String(s.assessments), fmt("pq.cAssessments.foot", { c: s.withCBOM, a: s.cryptoAgile })),
    card(t("pq.cVulnerable"), String(s.quantumVulnerable), t("pq.cVulnerable.foot"), s.quantumVulnerable ? "#ef4444" : "#34d399"),
    card(t("pq.cProdReady"), String(s.productionReady), t("pq.cProdReady.foot"), s.productionReady ? "#34d399" : "#94a3b8"),
    card(t("pq.cManaged"), String(s.managed), t("pq.cManaged.foot"), s.managed ? "#10b981" : "#94a3b8"),
    card(t("pq.cBelowTarget"), String(s.belowTarget), fmt("pq.cBelowTarget.foot", { n: s.noTarget }), s.belowTarget ? "#fbbf24" : "#34d399"),
  ].join("");

  // level distribution bar
  const total = s.byLevel.reduce((a, b) => a + b, 0) || 1;
  const dist = s.byLevel.map((n, i) => n ? `<div class="seg" style="flex:${n};background:${LCOL[i]}" title="${fmt("pq.distTitle", { i, n })}">${n}</div>` : "").join("");
  const distLeg = d.levels.map((l) => `<span class="l"><span class="sw" style="background:${LCOL[l.level]}"></span>L${l.level} ${esc(l.name)} (${s.byLevel[l.level]})</span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("pq.moreN", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("pq.noFindings")}</div>`;

  const table = d.rows.length ? `<table class="pq"><thead><tr>
      <th>${t("pq.thSubject")}</th><th>${t("pq.thMaturity")}</th><th>${t("pq.thCapabilities")}</th><th>${t("pq.thStatus")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">${t("pq.noAssessments")}</div>`;

  const form = `<div class="pq-form">
      <div class="pq-fld"><label>${t("pq.fSubject")}</label><input id="pq-subject" type="text" placeholder="${t("pq.fSubjectPh")}" style="min-width:260px"></div>
      <div class="pq-fld"><label>${t("pq.fType")}</label><select id="pq-type"><option>Asset</option><option>Application</option><option>Service</option><option>Product</option><option>Protocol</option><option>Library</option><option>Certificate / PKI</option></select></div>
      <div class="pq-fld"><label>${t("pq.fCurrent")}</label><select id="pq-current">${levelOpts(d.levels, 0)}</select></div>
      <div class="pq-fld"><label>${t("pq.fTarget")}</label><select id="pq-target">${levelOpts(d.levels, undefined, t("pq.optNone"))}</select></div>
      <div class="pq-fld"><label>${t("pq.fStandard")}</label><input id="pq-standard" type="text" placeholder="${t("pq.fStandardPh")}" style="width:150px"></div>
      <div class="pq-chk"><label><input type="checkbox" id="pq-agile"> ${t("pq.flagAgile")}</label><label><input type="checkbox" id="pq-cbom"> CBOM</label><label><input type="checkbox" id="pq-zero"> ${t("pq.flagZero")}</label></div>
      <button id="pq-go" class="pq-go">${t("pq.assessBtn")}</button>
      <div class="pq-stat" id="pq-stat"></div>
    </div>`;

  $("pq-body").innerHTML = `<div class="pq-cards">${cards}</div>
    <div class="pq-section">${fmt("pq.secDist", { n: total })}</div>
    <div class="pq-dist">${dist || `<div class="seg" style="flex:1;background:#1e2133;color:#64748b">${t("pq.noAssessmentsDist")}</div>`}</div>
    <div class="pq-distleg">${distLeg}</div>
    <div class="pq-section" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">${t("pq.secAssess")}
      <button id="pq-boot" class="pq-go" style="background:#0e7490;padding:5px 12px;font-size:12px" title="${t("pq.bootTitle")}">${t("pq.bootBtn")}</button>
      <span id="pq-bootstat" style="font-size:12px;font-weight:400;text-transform:none;letter-spacing:0;color:#94a3b8"></span>
    </div>${form}
    <div class="pq-section">${fmt("pq.secWorklist", { n: d.findings.length })}</div>${findings}
    <div class="pq-section">${fmt("pq.secAssessments", { n: d.rows.length })}</div>${table}
    <div class="pq-section">${t("pq.secModel")}</div>${levelRef(d.levels)}
    <div class="legend">${t("pq.legend")}</div>`;

  ($("pq-go") as HTMLButtonElement).addEventListener("click", () => void assess(d.levels));
  const boot = document.getElementById("pq-boot") as HTMLButtonElement | null;
  if (boot) boot.addEventListener("click", () => void bootstrap(boot));
}

/** Auto-seed PQCMM subjects from the asset crypto inventory (CPE). */
async function bootstrap(btn: HTMLButtonElement): Promise<void> {
  const stat = $("pq-bootstat");
  btn.disabled = true; stat.textContent = t("pq.scanning");
  try {
    const r = await fetch("/api/pqcmm/bootstrap", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    stat.innerHTML = d.scanned
      ? fmt("pq.bootDone", { c: `<b>${esc(d.created)}</b>`, s: esc(d.scanned), skipped: d.skipped ? fmt("pq.bootSkipped", { k: esc(d.skipped) }) : "" })
      : t("pq.bootNone");
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
