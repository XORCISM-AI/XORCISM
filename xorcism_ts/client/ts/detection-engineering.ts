/**
 * detection-engineering.ts — Detection Engineering studio (OrchiCyb-inspired ACI module).
 * Pick an ATT&CK technique → generate detection logic across 12 platforms (AI + offline),
 * save any rule into the detection library, and view Cyber Insights over the knowledge graph.
 */
import { initI18n } from "./i18n";

interface Platform { key: string; label: string; language: string; kind: string }
interface GenResult { platform: string; label: string; language: string; kind: string; rule: string; offline: boolean; model: string }
interface Insight { kind: string; severity: string; title: string; detail: string; count?: number }
interface Insights {
  summary: { techniques: number; covered: number; coveragePct: number; sigma: number; yara: number; detection: number; platforms: number };
  byPlatform: { platform: string; count: number }[];
  topGaps: { attackId: string; name: string }[];
  insights: Insight[];
}

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }

let PLATFORMS: Platform[] = [];
let LAST_TECH = { id: "", name: "" };

async function loadPlatforms(): Promise<void> {
  const r = await fetch("/api/detection-eng/platforms");
  const d = await r.json();
  PLATFORMS = d.platforms || [];
  $("de-plats").innerHTML = PLATFORMS.map((p) =>
    `<label class="de-plat" title="${esc(p.kind)} · ${esc(p.language)}"><input type="checkbox" class="de-pk" value="${esc(p.key)}" checked> ${esc(p.label)}</label>`).join("");
}

function selectedPlatforms(): string[] {
  return Array.from(document.querySelectorAll<HTMLInputElement>(".de-pk")).filter((c) => c.checked).map((c) => c.value);
}

function parseTech(): { id: string; name: string } {
  const raw = ($("de-tech") as HTMLInputElement).value.trim();
  const m = raw.match(/T\d{4}(?:\.\d{3})?/i);
  const id = m ? m[0].toUpperCase() : "";
  const name = raw.replace(/^.*?T\d{4}(?:\.\d{3})?\s*[—:-]?\s*/i, "").trim() || raw;
  return { id, name };
}

let techTimer: number | undefined;
function onTechInput(): void {
  window.clearTimeout(techTimer);
  const q = ($("de-tech") as HTMLInputElement).value.trim();
  if (q.length < 2) return;
  techTimer = window.setTimeout(async () => {
    try {
      const r = await fetch(`/api/detection-eng/techniques?q=${encodeURIComponent(q)}`);
      const d = await r.json();
      $("de-tech-list").innerHTML = (d.techniques || []).map((t: { id: string; name: string }) =>
        `<option value="${esc(t.id)} — ${esc(t.name)}">`).join("");
    } catch { /* ignore */ }
  }, 220);
}

function ruleCard(g: GenResult): string {
  const badge = g.offline ? `<span class="de-badge b-offline">template</span>` : `<span class="de-badge b-ai">AI</span>`;
  return `<div class="de-card" data-plat="${esc(g.platform)}">
    <div class="de-card-head">
      <span class="pn">${esc(g.label)}</span><span class="pk">${esc(g.kind)} · ${esc(g.language)}</span>
      <span class="sp"></span>${badge}
      <button class="de-btn ghost de-copy">Copy</button>
      <button class="de-btn ghost de-save">Save</button>
    </div>
    <pre class="de-rule">${esc(g.rule)}</pre>
  </div>`;
}

async function generate(): Promise<void> {
  const { id, name } = parseTech();
  if (!/^T\d{4}(\.\d{3})?$/.test(id)) { toast("Enter a valid ATT&CK technique id (e.g. T1059.001)"); return; }
  const platforms = selectedPlatforms();
  if (!platforms.length) { toast("Select at least one platform"); return; }
  LAST_TECH = { id, name };
  const cmd = ($("de-cmd") as HTMLInputElement).value.trim();
  const useAi = ($("de-useai") as HTMLInputElement).checked;
  const btn = $("de-gen") as HTMLButtonElement; btn.disabled = true;
  $("de-status").textContent = `Generating ${platforms.length} detections for ${id}…`;
  $("de-results").innerHTML = "";
  try {
    const r = await fetch("/api/detection-eng/generate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ techId: id, techName: name, platforms, useAi, context: cmd ? { command: cmd } : undefined }),
    });
    if (!r.ok) { const e = await r.json().catch(() => ({})); toast(e.error || `Error ${r.status}`); return; }
    const d = await r.json() as { results: GenResult[]; aiReachable: boolean };
    $("de-results").innerHTML = `<div class="de-section-h">${esc(id)} — ${esc(name)} · ${d.results.length} detections ${d.aiReachable ? "(AI-assisted)" : "(offline templates — no local model reachable)"}</div><div class="de-grid">${d.results.map(ruleCard).join("")}</div>`;
    $("de-status").textContent = "";
  } catch (e) { toast((e as Error).message); }
  finally { btn.disabled = false; }
}

async function onResultsClick(ev: MouseEvent): Promise<void> {
  const t = ev.target as HTMLElement;
  const card = t.closest(".de-card") as HTMLElement | null;
  if (!card) return;
  const platform = card.dataset.plat!;
  const rule = (card.querySelector(".de-rule") as HTMLElement).textContent || "";
  if (t.classList.contains("de-copy")) {
    try { await navigator.clipboard.writeText(rule); toast("Copied"); } catch { toast("Copy failed"); }
  } else if (t.classList.contains("de-save")) {
    (t as HTMLButtonElement).disabled = true;
    try {
      const r = await fetch("/api/detection-eng/save", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ platform, techId: LAST_TECH.id, techName: LAST_TECH.name, rule }),
      });
      const d = await r.json();
      if (r.ok) { toast(`Saved to ${d.store} #${d.id}`); void loadInsights(); }
      else toast(d.error || "Save failed");
    } catch (e) { toast((e as Error).message); }
    finally { (t as HTMLButtonElement).disabled = false; }
  }
}

async function loadInsights(): Promise<void> {
  try {
    const r = await fetch("/api/detection-eng/insights");
    if (!r.ok) return;
    const d = await r.json() as Insights;
    const s = d.summary;
    $("de-kpis").innerHTML = [
      ["Technique coverage", `${s.coveragePct}%`],
      ["Covered", `${s.covered}/${s.techniques}`],
      ["Sigma rules", String(s.sigma)],
      ["YARA rules", String(s.yara)],
      ["Platform rules", String(s.detection)],
    ].map(([l, v]) => `<div class="de-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
    $("de-topgaps").innerHTML = d.topGaps.length
      ? `<div style="font-size:11.5px;color:#94a3b8;margin-top:4px">Top coverage gaps (click to load):</div><div class="de-gaps">${d.topGaps.map((g) => `<span class="de-gap" data-id="${esc(g.attackId)}" data-name="${esc(g.name)}">${esc(g.attackId)} · ${esc(g.name)}</span>`).join("")}</div>`
      : "";
    $("de-insights").innerHTML = d.insights.map((i) =>
      `<div class="de-ins ${esc(i.severity)}"><div class="it">${esc(i.title)}</div><div class="id">${esc(i.detail)}</div></div>`).join("");
  } catch { /* ignore */ }
}

async function loadAiBadge(): Promise<void> {
  // reflected from a generate call; show a neutral hint until then
  $("de-ai-badge").innerHTML = `<span class="de-badge b-offline">local-AI optional</span>`;
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void loadPlatforms();
  void loadInsights();
  void loadAiBadge();
  ($("de-tech") as HTMLInputElement).addEventListener("input", onTechInput);
  $("de-gen").addEventListener("click", () => void generate());
  $("de-all").addEventListener("click", () => document.querySelectorAll<HTMLInputElement>(".de-pk").forEach((c) => (c.checked = true)));
  $("de-none").addEventListener("click", () => document.querySelectorAll<HTMLInputElement>(".de-pk").forEach((c) => (c.checked = false)));
  $("de-results").addEventListener("click", (e) => void onResultsClick(e as MouseEvent));
  $("de-topgaps").addEventListener("click", (e) => {
    const g = (e.target as HTMLElement).closest(".de-gap") as HTMLElement | null;
    if (!g) return;
    ($("de-tech") as HTMLInputElement).value = `${g.dataset.id} — ${g.dataset.name}`;
    void generate();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
});
