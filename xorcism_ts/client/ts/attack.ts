/**
 * attack.ts — MITRE ATT&CK matrix view (tactics → techniques → sub-techniques),
 * read from XTHREAT.ATTACK* via /api/attack/matrix.
 */
// Aliased as `tr`: `t` is already used as a loop variable (technique) in this file.
import { initI18n, t as tr } from "./i18n";

interface Sub { attackId: string; name: string; url: string | null }
interface Tech { attackId: string; name: string; url: string | null; subtechniques: Sub[] }
interface Tactic { attackId: string; name: string; shortName: string; url: string | null; techniques: Tech[] }
interface Matrix { domain: string; tactics: Tactic[] }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function el(tag: string, cls?: string): HTMLElement { const e = document.createElement(tag); if (cls) e.className = cls; return e; }

// ── Validation coverage (BAS): heatmap per ATT&CK technique ──────────────────────
interface Cov { tests: number; detected: number; prevented: number; status: string }
let coverage: Record<string, Cov> = {};
const COV_COLOR: Record<string, string> = { prevented: "#22c55e", detected: "#2dd4bf", tested: "#f59e0b" };
// Coverage label resolved AT CALL TIME (not at module load: t() isn't ready yet
// during top-level constant evaluation).
const covLabel = (s: string): string => tr("cov." + s) || s;
const COV_RANK: Record<string, number> = { "": 0, tested: 1, detected: 2, prevented: 3 };
// Aggregated status = max(technique, its sub-techniques); counters summed.
function rollup(t: Tech): Cov {
  const best: Cov = { tests: 0, detected: 0, prevented: 0, status: "" };
  const acc = (c?: Cov): void => {
    if (!c) return;
    best.tests += c.tests; best.detected += c.detected; best.prevented += c.prevented;
    if ((COV_RANK[c.status] ?? 0) > (COV_RANK[best.status] ?? 0)) best.status = c.status;
  };
  acc(coverage[t.attackId]);
  for (const s of t.subtechniques) acc(coverage[s.attackId]);
  return best;
}

// ── LLM ATT&CK Navigator (Anthropic): AI-enablement layer over the same techniques ──
interface LlmTech { name: string; tactic: string; actorCount: number | null; prevalence: number | null; ariesMean: number | null }
let layerMode: "bas" | "llm" = "bas";
let llmLayer: Record<string, LlmTech> = {};
let llmMeta: { source: string; accounts: number; observations: number; version: string; window: string; aries: string } | null = null;
let currentMatrix: Matrix | null = null;
// Parent cell = the highest-prevalence match among the technique or its sub-techniques.
function llmRollup(t: Tech): { id: string; v: LlmTech } | null {
  let best: { id: string; v: LlmTech } | null = null;
  const consider = (id: string): void => {
    const v = llmLayer[id];
    if (v && (!best || (v.prevalence ?? -1) > (best.v.prevalence ?? -1))) best = { id, v };
  };
  consider(t.attackId);
  for (const s of t.subtechniques) consider(s.attackId);
  return best;
}
function llmColor(prev: number | null): string {
  if (prev == null) return "rgba(244,63,94,0.10)"; // observed, no published prevalence
  return `rgba(244,63,94,${(0.18 + Math.min(1, prev / 70) * 0.62).toFixed(2)})`;
}
function updateCredit(): void {
  const c = $("att-llm-credit");
  if (layerMode === "llm" && llmMeta) {
    c.style.display = "";
    c.innerHTML = `🤖 <b>LLM ATT&amp;CK Navigator</b> — Anthropic (${llmMeta.window}): ${llmMeta.accounts} banned accounts, ` +
      `${llmMeta.observations.toLocaleString()} observations mapped to ${llmMeta.version}. ` +
      `Cell shading = % of banned accounts using the technique. ${llmMeta.aries}. ` +
      `<a href="${llmMeta.source}" target="_blank" rel="noopener" style="color:#7c83fd">source ↗</a>`;
  } else c.style.display = "none";
}

function techLink(attackId: string, name: string, url: string | null): HTMLElement {
  const a = document.createElement("a");
  a.textContent = name;
  a.title = `${attackId} — ${name}`;
  if (url) { a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; }
  return a;
}

function render(m: Matrix): void {
  const root = $("att-matrix");
  root.innerHTML = "";
  let techCount = 0, subCount = 0, covered = 0;
  for (const tac of m.tactics) {
    const col = el("div", "att-col");
    const head = el("div", "att-col-head");
    head.innerHTML =
      `<div class="att-tac-name">${tac.name}</div>` +
      `<div class="att-tac-meta">${tac.attackId} · ${tac.techniques.length} tech.</div>`;
    col.appendChild(head);
    const bodyEl = el("div", "att-col-body");
    for (const t of tac.techniques) {
      techCount++;
      subCount += t.subtechniques.length;
      const cell = el("div", "att-cell");
      cell.dataset.s = `${t.attackId} ${t.name}`.toLowerCase() +
        " " + t.subtechniques.map((s) => `${s.attackId} ${s.name}`).join(" ").toLowerCase();
      const main = el("div", "att-cell-main");
      const id = el("span", "att-id"); id.textContent = t.attackId;
      main.appendChild(id);
      main.appendChild(techLink(t.attackId, t.name, t.url));
      let subsBox: HTMLElement | null = null;
      if (t.subtechniques.length) {
        const toggle = el("span", "att-sub-toggle");
        toggle.textContent = `▸ ${t.subtechniques.length}`;
        subsBox = el("div", "att-subs");
        for (const s of t.subtechniques) {
          const sd = el("div", "att-sub");
          const sid = el("span", "att-id"); sid.textContent = s.attackId.split(".").pop() || s.attackId;
          sd.appendChild(sid); sd.appendChild(document.createTextNode(" "));
          sd.appendChild(techLink(s.attackId, s.name, s.url));
          subsBox.appendChild(sd);
        }
        toggle.onclick = () => {
          const open = subsBox!.classList.toggle("open");
          toggle.textContent = `${open ? "▾" : "▸"} ${t.subtechniques.length}`;
        };
        main.appendChild(toggle);
      }
      if (layerMode === "bas") {
        // Validation coverage (BAS): border + badge based on the aggregated status.
        const cov = rollup(t);
        if (cov.status) {
          covered++;
          cell.style.borderLeft = `3px solid ${COV_COLOR[cov.status]}`;
          const badge = el("span", "att-cov");
          badge.textContent = "🛡" + (cov.tests || cov.detected + cov.prevented);
          badge.title = `${tr("tip.validation")} ${covLabel(cov.status)} · ${tr("tip.tests")} ${cov.tests}, ${tr("cov.detected")} ${cov.detected}, ${tr("cov.prevented")} ${cov.prevented}`;
          badge.style.cssText = `margin-left:6px;font-size:10px;color:${COV_COLOR[cov.status]}`;
          main.appendChild(badge);
        }
      } else {
        // LLM ATT&CK Navigator (Anthropic): AI-enablement heatmap by prevalence.
        const hit = llmRollup(t);
        if (hit) {
          covered++;
          cell.style.background = llmColor(hit.v.prevalence);
          cell.style.borderLeft = "3px solid #f43f5e";
          const badge = el("span", "att-cov");
          const lbl = hit.v.prevalence != null ? `${hit.v.prevalence}%` : (hit.v.actorCount != null ? String(hit.v.actorCount) : "obs");
          badge.textContent = "🤖 " + lbl;
          badge.title = `Anthropic LLM ATT&CK · ${hit.id} ${hit.v.name}` +
            (hit.v.prevalence != null ? ` · ${hit.v.prevalence}% of banned accounts` : "") +
            (hit.v.actorCount != null ? ` · ${hit.v.actorCount} actors` : "") + " (AI-enabled)";
          badge.style.cssText = "margin-left:6px;font-size:10px;color:#f43f5e";
          main.appendChild(badge);
        }
      }
      cell.appendChild(main);
      if (subsBox) cell.appendChild(subsBox);
      bodyEl.appendChild(cell);
    }
    col.appendChild(bodyEl);
    root.appendChild(col);
  }
  const base = `${m.tactics.length} ${tr("attack.tactics")} · ${techCount} ${tr("attack.techniques")} · ${subCount} ${tr("attack.subtechniques")}`;
  if (layerMode === "llm") {
    $("att-stats").innerHTML = `${base} · <span style="color:#f43f5e">🤖 ${covered} AI-enabled (Anthropic)</span>`;
  } else {
    $("att-stats").innerHTML = Object.keys(coverage).length
      ? `${base} · <span style="color:${COV_COLOR.tested}">🛡 ${covered} ${tr("attack.validated")}</span> ` +
        `<span style="color:#64748b">(<span style="color:${COV_COLOR.prevented}">■</span> ${tr("cov.prevented")} ` +
        `<span style="color:${COV_COLOR.detected}">■</span> ${tr("cov.detected")} ` +
        `<span style="color:${COV_COLOR.tested}">■</span> ${tr("cov.tested")})</span>`
      : base;
  }
  updateCredit();
  applyFilter();
}

function applyFilter(): void {
  const q = ($("att-search") as HTMLInputElement).value.trim().toLowerCase();
  document.querySelectorAll<HTMLElement>(".att-cell").forEach((c) => {
    c.style.display = !q || (c.dataset.s ?? "").includes(q) ? "" : "none";
  });
}

async function load(domain: string): Promise<void> {
  const root = $("att-matrix");
  root.innerHTML = `<div style="padding:24px;color:var(--text-muted)">Loading…</div>`;
  try {
    const r = await fetch(`/api/attack/matrix?domain=${encodeURIComponent(domain)}`);
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(d as { error?: string }).error || `Error ${r.status}`}</div>`;
      return;
    }
    const matrix = (await r.json()) as Matrix;
    currentMatrix = matrix;
    // Overlay layers — best-effort, do not block rendering.
    try { coverage = ((await (await fetch("/api/attack/coverage")).json()) as { byAttackId: Record<string, Cov> }).byAttackId || {}; }
    catch { coverage = {}; }
    try {
      const lr = await (await fetch("/api/attack/llm-layer")).json() as { byAttackId: Record<string, LlmTech>; meta: typeof llmMeta };
      llmLayer = lr.byAttackId || {}; llmMeta = lr.meta || null;
    } catch { llmLayer = {}; }
    render(matrix);
  } catch (e) {
    root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(e as Error).message}</div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  const sel = $("att-domain") as HTMLSelectElement;
  sel.onchange = () => void load(sel.value);
  ($("att-search") as HTMLInputElement).oninput = applyFilter;
  // Overlay-layer selector (BAS coverage / LLM ATT&CK). ?layer=llm deep-links the LLM layer.
  const layerSel = $("att-layer") as HTMLSelectElement;
  if (new URLSearchParams(location.search).get("layer") === "llm") { layerMode = "llm"; layerSel.value = "llm"; }
  layerSel.onchange = () => {
    layerMode = layerSel.value === "llm" ? "llm" : "bas";
    if (currentMatrix) render(currentMatrix); else void load(sel.value); // re-render from cache, no refetch
  };
  void load(sel.value);
});
