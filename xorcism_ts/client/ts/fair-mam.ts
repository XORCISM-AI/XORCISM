/**
 * fair-mam.ts — FAIR-MAM materiality assessment (/fair-mam). An interactive loss-decomposition
 * calculator over the FAIR-MAM taxonomy + a list of saved assessments, from /api/fair-mam.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Cat { id: number; code: string; name: string; parent: string | null; lossType: "primary" | "secondary"; party: "first-party" | "third-party"; description: string; sortOrder: number; }
interface Assessment { id: number; name: string; scenarioRef: string | null; currency: string; total: number; primary: number; secondary: number; firstParty: number; thirdParty: number; threshold: number | null; ratio: number | null; determination: string; lineCount: number; createdDate: string | null; }
interface Risk { id: number; ref: string; title: string; }
interface Inventory {
  categories: Cat[]; assessments: Assessment[]; risks: Risk[];
  summary: { assessments: number; material: number; approaching: number; largestExposure: number; totalExposure: number; currency: string; avgPrimaryShare: number | null };
}

let CATS: Cat[] = [];
let RISKS: Risk[] = [];
let CUR = "EUR";

function fmt(n: number): string {
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency: CUR, maximumFractionDigits: 0 }).format(n || 0); }
  catch { return `${CUR} ${Math.round(n || 0).toLocaleString()}`; }
}
const pert = (lo: number, m: number, hi: number): number => {
  const a = [lo, m, hi].map((x) => (Number.isFinite(x) ? x : NaN));
  if (a.every((x) => Number.isFinite(x))) return (a[0] + 4 * a[1] + a[2]) / 6;
  if (Number.isFinite(a[1])) return a[1];
  const v = [a[0], a[2]].filter((x) => Number.isFinite(x));
  return v.length ? v.reduce((s, x) => s + x, 0) / v.length : 0;
};
const verdictClass = (d: string): string => `v-${d.toLowerCase().replace(/[^a-z]/g, "").replace("notmaterial", "not")}`;

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="fm-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

/** Build the calculator table: leaf categories (those with no children) grouped by top-level. */
function calcTable(): string {
  const childrenOf = new Set(CATS.filter((c) => c.parent).map((c) => c.parent));
  const isLeaf = (c: Cat): boolean => !CATS.some((x) => x.parent === c.code);
  const tops = CATS.filter((c) => !c.parent);
  const rowsFor = (loss: "primary" | "secondary"): string => tops.filter((t) => t.lossType === loss).map((t) => {
    const leaves = isLeaf(t) ? [t] : CATS.filter((c) => c.parent === t.code);
    const head = `<tr class="fm-grp"><td colspan="5">${esc(t.name)}<span class="pp pp-${t.lossType}">${t.lossType}</span> <span class="muted" style="font-weight:400;text-transform:none">· ${esc(t.party)}</span></td></tr>`;
    const body = leaves.map((c) => `<tr data-row="${c.id}">
      <td><div class="cat-name">${esc(c.code === t.code ? c.name : c.name)}</div>${c.description ? `<div class="cat-d">${esc(c.description)}</div>` : ""}</td>
      <td class="num"><input class="fm-in" type="number" min="0" step="1000" data-cat="${c.id}" data-k="min" placeholder="0"></td>
      <td class="num"><input class="fm-in" type="number" min="0" step="1000" data-cat="${c.id}" data-k="ml" placeholder="0"></td>
      <td class="num"><input class="fm-in" type="number" min="0" step="1000" data-cat="${c.id}" data-k="max" placeholder="0"></td>
      <td class="num fm-exp" data-exp="${c.id}">—</td>
    </tr>`).join("");
    return head + body;
  }).join("");
  void childrenOf;
  return `<table class="fm"><thead><tr>
      <th>Cost category</th><th class="num">Min</th><th class="num">Most likely</th><th class="num">Max</th><th class="num">Expected</th>
    </tr></thead><tbody>
      <tr class="fm-grp"><td colspan="5" style="background:#0b1f17;color:#6ee7b7">— Primary loss (first-party, direct) —</td></tr>
      ${rowsFor("primary")}
      <tr class="fm-grp"><td colspan="5" style="background:#241a0b;color:#fcd34d">— Secondary loss (stakeholder reactions) —</td></tr>
      ${rowsFor("secondary")}
    </tbody></table>`;
}

function recompute(): void {
  const get = (id: number, k: string): number => {
    const el = document.querySelector(`input[data-cat="${id}"][data-k="${k}"]`) as HTMLInputElement | null;
    const v = el ? parseFloat(el.value) : NaN; return Number.isFinite(v) ? v : NaN;
  };
  const catById = new Map(CATS.map((c) => [c.id, c]));
  let total = 0, primary = 0, secondary = 0, firstP = 0, thirdP = 0;
  const inputCats = new Set([...document.querySelectorAll("input.fm-in")].map((e) => Number((e as HTMLElement).dataset.cat)));
  for (const id of inputCats) {
    const e = pert(get(id, "min"), get(id, "ml"), get(id, "max"));
    const cell = document.querySelector(`[data-exp="${id}"]`);
    if (cell) cell.textContent = e ? fmt(e) : "—";
    if (!e) continue;
    total += e;
    const c = catById.get(id);
    if (c?.lossType === "secondary") secondary += e; else primary += e;
    if (c?.party === "third-party") thirdP += e; else firstP += e;
  }
  const thr = parseFloat((document.getElementById("fm-threshold") as HTMLInputElement)?.value || "");
  const threshold = Number.isFinite(thr) && thr > 0 ? thr : null;
  const det = !threshold ? "Unassessed" : total >= threshold ? "Material" : total >= 0.5 * threshold ? "Approaching" : "Not material";
  $("fm-total").textContent = fmt(total);
  $("fm-split").innerHTML = `Primary <b>${fmt(primary)}</b> · Secondary <b>${fmt(secondary)}</b> &nbsp;|&nbsp; First-party <b>${fmt(firstP)}</b> · Third-party <b>${fmt(thirdP)}</b>${threshold ? ` &nbsp;|&nbsp; ${Math.round((total / threshold) * 100)}% of threshold` : ""}`;
  const v = $("fm-verdict"); v.textContent = det; v.className = `fm-verdict ${verdictClass(det)}`;
}

async function save(): Promise<void> {
  const btn = $("fm-save") as HTMLButtonElement; const stat = $("fm-stat");
  const lines: { categoryId: number; min?: number; mostLikely?: number; max?: number }[] = [];
  for (const id of new Set([...document.querySelectorAll("input.fm-in")].map((e) => Number((e as HTMLElement).dataset.cat)))) {
    const num = (k: string): number | undefined => { const el = document.querySelector(`input[data-cat="${id}"][data-k="${k}"]`) as HTMLInputElement | null; const v = el ? parseFloat(el.value) : NaN; return Number.isFinite(v) ? v : undefined; };
    const min = num("min"), ml = num("ml"), mx = num("max");
    if (min != null || ml != null || mx != null) lines.push({ categoryId: id, min, mostLikely: ml, max: mx });
  }
  if (!lines.length) { stat.innerHTML = "⚠️ Enter at least one loss estimate first."; return; }
  const name = (document.getElementById("fm-name") as HTMLInputElement).value.trim() || undefined;
  const thr = parseFloat((document.getElementById("fm-threshold") as HTMLInputElement).value || "");
  const threshold = Number.isFinite(thr) && thr > 0 ? thr : undefined;
  const riskSel = document.getElementById("fm-risk") as HTMLSelectElement | null;
  const riskRegisterEntryId = riskSel && riskSel.value ? Number(riskSel.value) : undefined;
  btn.disabled = true; stat.textContent = "Saving…";
  try {
    const r = await fetch("/api/fair-mam/assess", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, currency: CUR, threshold, lines, riskRegisterEntryId }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    const wb = d.riskWriteback
      ? ` &nbsp;↪ wrote <b>SLE ${esc(fmt(d.riskWriteback.sle))}</b>${d.riskWriteback.ale != null ? ` · ALE ${esc(fmt(d.riskWriteback.ale))}` : ""} back to risk <a href="/?db=XCOMPLIANCE&table=RISKREGISTERENTRY&filterCol=RiskRegisterEntryID&filterVal=${esc(d.riskWriteback.id)}">${esc(d.riskWriteback.ref)}</a>`
      : "";
    stat.innerHTML = `✅ Saved assessment #${esc(d.assessmentId)} — total ${esc(fmt(d.total))}, <b>${esc(d.determination)}</b>.${wb} <a href="/fair-mam">↻ refresh</a>`;
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
}

function savedTable(rows: Assessment[]): string {
  if (!rows.length) return `<div class="muted" style="padding:12px 0">No saved assessments yet — build one above and click <b>Save</b>.</div>`;
  return `<table class="fa"><thead><tr>
      <th>Assessment</th><th class="num">Single-loss</th><th class="num">Primary</th><th class="num">Secondary</th><th class="num">Threshold</th><th class="num">% thr.</th><th>Determination</th>
    </tr></thead><tbody>${rows.map((a) => `<tr>
      <td>${esc(a.name)}${a.scenarioRef ? `<div class="muted" style="font-size:11px">${esc(a.scenarioRef)}</div>` : ""}<div class="muted" style="font-size:11px">${a.lineCount} line(s)${a.createdDate ? ` · ${esc(a.createdDate)}` : ""}</div></td>
      <td class="num"><b>${esc(fmt(a.total))}</b></td>
      <td class="num">${esc(fmt(a.primary))}</td>
      <td class="num">${esc(fmt(a.secondary))}</td>
      <td class="num">${a.threshold != null ? esc(fmt(a.threshold)) : "<span class=\"muted\">—</span>"}</td>
      <td class="num">${a.ratio != null ? a.ratio + "%" : "<span class=\"muted\">—</span>"}</td>
      <td><span class="det det-${esc(a.determination.replace(/\s/g, ""))}">${esc(a.determination)}</span></td>
    </tr>`).join("")}</tbody></table>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/fair-mam"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("fm-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  CATS = d.categories; RISKS = d.risks || []; CUR = d.summary.currency || "EUR";
  if (!CATS.length) { $("fm-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">FAIR-MAM taxonomy not seeded. Restart the server to seed FAIRMAMCATEGORY.</div>`; return; }
  const s = d.summary;

  const cards = [
    card("Assessments", String(s.assessments), `${s.material} material · ${s.approaching} approaching`),
    card("Material events", String(s.material), "≥ threshold", s.material ? "#f87171" : "#34d399"),
    card("Largest single-loss", fmt(s.largestExposure), "biggest assessed event"),
    card("Total assessed", fmt(s.totalExposure), `${s.assessments} assessment(s)`),
    card("Avg primary share", s.avgPrimaryShare != null ? `${s.avgPrimaryShare}%` : "—", "first-party / direct"),
  ].join("");

  $("fm-body").innerHTML = `<div class="fm-cards">${cards}</div>
    <div class="fm-section">Materiality calculator — decompose a single loss event</div>
    <div class="fm-calc">
      <div class="fm-meta">
        <div class="fm-fld"><label>Assessment name</label><input id="fm-name" type="text" placeholder="e.g. Ransomware on ERP — Q3" style="min-width:280px"></div>
        <div class="fm-fld"><label>Materiality threshold</label><input id="fm-threshold" type="number" min="0" step="100000" placeholder="e.g. 5000000"></div>
        <div class="fm-fld"><label>Currency</label><select id="fm-currency"><option>EUR</option><option>USD</option><option>GBP</option><option>CHF</option></select></div>
        ${RISKS.length ? `<div class="fm-fld"><label>Link to risk (writes back SLE)</label><select id="fm-risk" style="min-width:240px"><option value="">— none —</option>${RISKS.map((r) => `<option value="${r.id}">${esc(r.ref)} — ${esc(r.title)}</option>`).join("")}</select></div>` : ""}
      </div>
      ${calcTable()}
      <div class="fm-tot">
        <div><div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase">Expected single-loss</div><div class="big fm-exp" id="fm-total">${fmt(0)}</div></div>
        <div><span id="fm-verdict" class="fm-verdict v-unassessed">Unassessed</span><div class="fm-split" id="fm-split" style="margin-top:6px"></div></div>
        <button id="fm-save" class="fm-save">💾 Save assessment</button>
        <div class="fm-stat" id="fm-stat"></div>
      </div>
    </div>
    <div class="fm-section">Saved assessments (${d.assessments.length})</div>${savedTable(d.assessments)}
    <div class="legend">↳ Each line is a <b>PERT</b> estimate: <b>Expected = (min + 4·most-likely + max) / 6</b>.
      <b>Primary</b> loss = first-party costs you incur directly (response, extortion, business interruption,
      restoration); <b>Secondary</b> loss = stakeholder reactions (liability, regulatory, PCI, reputation).
      <b>Material</b> when the expected single-loss ≥ your threshold (e.g. an SEC materiality figure).
      Based on the FAIR Institute's open <i>FAIR-MAM</i> model.</div>`;

  const curSel = document.getElementById("fm-currency") as HTMLSelectElement;
  if (curSel) { curSel.value = CUR; curSel.onchange = () => { CUR = curSel.value; recompute(); }; }
  $("fm-body").addEventListener("input", (ev) => { const t = ev.target as HTMLElement; if (t.classList.contains("fm-in") || t.id === "fm-threshold") recompute(); });
  ($("fm-save") as HTMLButtonElement).addEventListener("click", () => void save());
  recompute();
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
