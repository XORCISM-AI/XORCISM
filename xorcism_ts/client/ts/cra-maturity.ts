/**
 * cra-maturity.ts — ENISA SME Cyber Resilience Maturity self-assessment cockpit (/cra-maturity).
 * Create an assessment, score the 25 questions on the 1-5 anchored rubric, and read back live
 * domain averages, the overall maturity band and the band-appropriate improvement roadmap.
 */
import { initI18n } from "./i18n";

interface Level { level: number; name: string; meaning: string }
interface Band { key: string; label: string; min: number; max: number; emoji: string; summary: string }
interface Question { ref: string; question: string; anchors: string[] }
interface Domain { domain: string; key: string; name: string; cra: string; questions: Question[] }
interface Catalogue { title: string; version: string; source: string; levels: Level[]; bands: Band[]; domains: Domain[] }
interface Assessment {
  id: number; name: string; orgName: string; productScope: string; assessor: string; status: string;
  overallScore: number; band: string; bandLabel: string; answered: number; total: number;
}
interface DomainScore { key: string; domain: string; name: string; avg: number; answered: number; gapTo5: number; band: string }
interface Score { overall: number; answered: number; total: number; domains: DomainScore[]; distribution: number[]; atOrAboveL3: number; belowL3: number }
interface QView { ref: string; domainKey: string; domain: string; question: string; anchors: string[]; score: number; rag: string; evidence: string }
interface Roadmap { band: string; bandSummary: string; groups: { domain: string; avg: number; priority: boolean; actions: string[] }[] }
interface Detail { assessment: Assessment; score: Score; answers: Record<string, { score: number; evidence: string }>; questions: QView[]; roadmap: Roadmap }
interface Dash { assessments: Assessment[]; summary: Record<string, number>; catalogue: { domains: number; questions: number } }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }

let DASH: Dash | null = null;
let CAT: Catalogue | null = null;
let SEL: number | null = null;

const bandChip = (key: string, label: string): string =>
  key ? `<span class="sm-chip b-${esc(key)}">${esc(label || key)}</span>` : '<span class="muted">not scored</span>';

async function api(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `Error ${r.status}`);
  return d;
}

function renderDash(): void {
  if (!DASH) return;
  const s = DASH.summary, c = DASH.catalogue;
  $("sm-cat").textContent = `${c.domains} domains · ${c.questions} questions`;
  $("sm-kpis").innerHTML = [
    ["Assessments", String(s.assessments)], ["Completed", String(s.completed)],
    ["Avg score", `${s.avgScore}/5`], ["Advanced", String(s.advanced)],
    ["Intermediate", String(s.intermediate)], ["Basic", String(s.basic)],
  ].map(([l, v]) => `<div class="sm-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");

  $("sm-body").innerHTML = DASH.assessments.length ? DASH.assessments.map((a) => `
    <tr class="sm-row ${a.id === SEL ? "sel" : ""}" data-id="${a.id}">
      <td><b>${esc(a.name)}</b><div class="muted">${esc(a.orgName)}${a.productScope ? " · " + esc(a.productScope) : ""}</div></td>
      <td><b style="color:#38bdf8">${a.answered ? a.overallScore.toFixed(1) : "—"}</b> <span class="muted">/5</span></td>
      <td>${bandChip(a.band, a.bandLabel)}</td>
      <td><span class="sm-bar"><span style="width:${Math.round((a.answered / a.total) * 100)}%"></span></span><div class="muted">${a.answered}/${a.total}</div></td>
      <td>${esc(a.status)}</td>
      <td><button class="sm-btn ghost danger sm-del" data-id="${a.id}">Del</button></td>
    </tr>`).join("") : `<tr><td colspan="6" class="muted">No assessment yet — create one above to start the ENISA self-check.</td></tr>`;
}

const LVLNAME = (n: number): string => CAT?.levels.find((l) => l.level === n)?.name ?? String(n);

function renderDetail(d: Detail): void {
  SEL = d.assessment.id;
  $("sm-detail").style.display = "";
  const a = d.assessment;
  $("sm-d-title").innerHTML = `&#128202; ${esc(a.name)} <span class="muted">— ${esc(a.orgName)}${a.assessor ? " · " + esc(a.assessor) : ""}</span>`;
  $("sm-d-score").textContent = d.score.answered ? d.score.overall.toFixed(1) : "0.0";
  const band = CAT?.bands.find((b) => b.key === a.band);
  $("sm-d-band").innerHTML = d.score.answered
    ? `${band?.emoji ?? ""} ${bandChip(a.band, a.bandLabel)} <span class="muted">${d.score.atOrAboveL3} q ≥ L3 · ${d.score.belowL3} q &lt; L3</span>`
    : '<span class="muted">answer the questions below to compute the band</span>';
  $("sm-d-bandsum").textContent = d.score.answered ? (band?.summary ?? "") : "";
  $("sm-d-progress").textContent = `(${d.score.answered}/${d.score.total} answered)`;

  // score distribution (levels 1..5)
  const dist = d.score.distribution, maxd = Math.max(1, ...dist);
  $("sm-d-dist").innerHTML = dist.map((n, i) =>
    `<div class="bar" style="height:${Math.round((n / maxd) * 100)}%" title="Level ${i + 1}: ${n}"><b>${n || ""}</b><i>L${i + 1}</i></div>`).join("");

  // domain scores
  $("sm-domscores").innerHTML = d.score.domains.map((dd) => `
    <tr><td style="width:52%"><b>${esc(dd.name)}</b><div class="muted">${dd.answered}/5 answered · gap to 5: ${dd.gapTo5}</div></td>
      <td><span class="sm-bar"><span style="width:${(dd.avg / 5) * 100}%"></span></span></td>
      <td style="width:44px;text-align:right"><b style="color:${dd.avg >= 4 ? "#4ade80" : dd.avg >= 2.6 ? "#7dd3fc" : "#fbbf24"}">${dd.answered ? dd.avg.toFixed(1) : "—"}</b></td></tr>`).join("");

  // questions grouped by domain (from the catalogue for ordering + anchors)
  const byRef = new Map(d.questions.map((q) => [q.ref, q] as const));
  $("sm-questions").innerHTML = (CAT?.domains ?? []).map((dom) => {
    const ds = d.score.domains.find((x) => x.key === dom.key);
    const qs = dom.questions.map((q) => {
      const qv = byRef.get(q.ref)!;
      const levels = q.anchors.map((desc, i) => {
        const lvl = i + 1;
        return `<div class="sm-lvl ${qv.score === lvl ? "sel" : ""}" data-ref="${esc(q.ref)}" data-score="${lvl}">
          <div class="lh">${lvl} · ${esc(LVLNAME(lvl))}</div><div class="ld">${esc(desc)}</div></div>`;
      }).join("");
      return `<div class="sm-q">
        <div><span class="qref">${esc(q.ref)}</span><span class="qtext">${esc(q.question)}</span>
          ${qv.score ? `<span class="sm-chip rag-${esc(qv.rag)}" style="float:right">${qv.score} · ${esc(LVLNAME(qv.score))}</span>` : ""}</div>
        <div class="sm-levels">${levels}</div></div>`;
    }).join("");
    return `<div class="sm-domblock">
      <div class="sm-domhdr"><span class="nm">${esc(dom.domain)}. ${esc(dom.name)}</span>
        <span class="avg">${ds && ds.answered ? ds.avg.toFixed(1) : "—"}/5</span></div>
      ${qs}
      <div class="sm-q"><div class="sm-cra"><b>CRA:</b> ${esc(dom.cra)}</div></div>
    </div>`;
  }).join("");

  // roadmap
  const rm = d.roadmap;
  $("sm-road-band-lbl").innerHTML = d.score.answered ? bandChip(rm.band, band?.label ?? rm.band) : "";
  $("sm-roadmap").innerHTML = d.score.answered ? `
    <div class="sm-road-band">${band?.emoji ?? ""} <b>${esc(band?.label ?? rm.band)}</b> — ${esc(rm.bandSummary)}<br>
      <span class="muted">ENISA guidance: prioritise the domains scoring lowest (below 2.5), pick a few actions for the next 3–6 months, then re-check.</span></div>
    ${rm.groups.map((g) => `<div class="sm-road-grp">
      <h4>${esc(g.domain)}${g.priority ? ' <span class="sm-pri">priority · &lt;2.5</span>' : ""}${g.avg > 0 && g.avg < 90 ? ` <span class="muted" style="font-weight:400">(${g.avg.toFixed(1)}/5)</span>` : ""}</h4>
      <ul>${g.actions.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`).join("")}`
    : '<div class="muted">Complete some questions to generate a band-appropriate action checklist.</div>';
}

async function load(): Promise<void> {
  try {
    if (!CAT) CAT = await api("/api/cra-maturity/catalogue");
    DASH = await api("/api/cra-maturity"); renderDash();
  } catch (e) { toast((e as Error).message); }
}
async function open(id: number): Promise<void> {
  try { renderDetail(await api(`/api/cra-maturity/${id}`)); renderDash(); }
  catch (e) { toast((e as Error).message); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("sm-add").addEventListener("click", async () => {
    const body = {
      name: ($("sm-name") as HTMLInputElement).value.trim(),
      orgName: ($("sm-org") as HTMLInputElement).value.trim(),
      productScope: ($("sm-scope") as HTMLInputElement).value.trim(),
      assessor: ($("sm-assessor") as HTMLInputElement).value.trim(),
    };
    if (!body.name) { toast("assessment name required"); return; }
    try {
      const r = await api("/api/cra-maturity", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      ($("sm-name") as HTMLInputElement).value = ""; ($("sm-org") as HTMLInputElement).value = "";
      ($("sm-scope") as HTMLInputElement).value = ""; ($("sm-assessor") as HTMLInputElement).value = "";
      $("sm-msg").textContent = `created #${r.id}`;
      await load(); await open(r.id);
      $("sm-detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast((e as Error).message); }
  });

  $("sm-body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".sm-del") as HTMLElement | null;
    if (del) {
      ev.stopPropagation();
      if (!confirm("Delete this assessment and its answers?")) return;
      try { await api(`/api/cra-maturity/${del.dataset.id}`, { method: "DELETE" }); SEL = null; $("sm-detail").style.display = "none"; await load(); }
      catch (e) { toast((e as Error).message); }
      return;
    }
    const row = t.closest(".sm-row") as HTMLElement | null;
    if (row) void open(Number(row.dataset.id));
  });

  // score a question by clicking a level card
  $("sm-questions").addEventListener("click", async (ev) => {
    const lvl = (ev.target as HTMLElement).closest(".sm-lvl") as HTMLElement | null;
    if (!lvl || SEL == null) return;
    const ref = lvl.dataset.ref!, cur = Number(lvl.dataset.score);
    const already = lvl.classList.contains("sel");
    try {
      const d = await api(`/api/cra-maturity/${SEL}/answer`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ref, score: already ? 0 : cur }),   // click the selected level again to clear it
      });
      renderDetail(d as Detail); renderDash();
    } catch (e) { toast((e as Error).message); }
  });
});
