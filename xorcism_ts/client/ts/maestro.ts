/**
 * maestro.ts — MAESTRO matrix view (CSA agentic-AI threat model), read from
 * XTHREAT.MAESTRO* via /api/maestro/matrix. Seven architecture layers (columns) → threats,
 * plus a cross-layer column and the six-step methodology panel.
 */
import { initI18n } from "./i18n";

interface Threat { maestroId: string; name: string; description: string | null }
interface Layer { number: number | null; name: string; description: string | null; isVertical: boolean; threats: Threat[] }
interface Matrix { layers: Layer[]; crossLayer: Threat[]; summary: { layers: number; threats: number; crossLayer: number } }

const STEPS: [string, string][] = [
  ["System Decomposition", "Break the system into components across the seven layers; define capabilities, goals and interactions."],
  ["Layer-Specific Threat Modeling", "Apply each layer's threat landscape to identify relevant threats; customise for system specifics."],
  ["Cross-Layer Threat Identification", "Analyse layer interactions to find cross-layer threats and assess vulnerability propagation."],
  ["Risk Assessment", "Evaluate likelihood and impact of each threat with risk matrices; prioritise the results."],
  ["Mitigation Planning", "Develop remediation using layer-specific, cross-layer and AI-specific controls."],
  ["Implementation & Monitoring", "Execute mitigations; continuously monitor and update the threat model as the system evolves."],
];

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function el(tag: string, cls?: string): HTMLElement { const e = document.createElement(tag); if (cls) e.className = cls; return e; }

function renderSteps(): void {
  const root = $("maestro-steps");
  root.innerHTML = "";
  STEPS.forEach(([title, desc], i) => {
    const s = el("div", "maestro-step");
    s.innerHTML = `<div class="sn">STEP ${i + 1}</div><div class="st">${title}</div><div class="sd">${desc}</div>`;
    root.appendChild(s);
  });
}

function column(title: string, subtitle: string | null, meta: string, threats: Threat[], extraCls: string): HTMLElement {
  const col = el("div", "att-col" + (extraCls ? " " + extraCls : ""));
  const head = el("div", "att-col-head");
  head.innerHTML = `<div class="att-tac-name">${title}</div>` +
    (subtitle ? `<div class="att-tac-desc">${subtitle}</div>` : "") +
    `<div class="att-tac-meta">${meta}</div>`;
  col.appendChild(head);
  const body = el("div", "att-col-body");
  for (const t of threats) {
    const cell = el("div", "att-cell");
    cell.dataset.s = `${t.maestroId} ${t.name}`.toLowerCase();
    const id = el("span", "att-id"); id.textContent = t.maestroId;
    const nm = el("div", "tn"); nm.textContent = t.name;
    if (t.description) cell.title = t.description;
    cell.appendChild(id); cell.appendChild(nm);
    body.appendChild(cell);
  }
  col.appendChild(body);
  return col;
}

function render(m: Matrix): void {
  const root = $("maestro-matrix");
  root.innerHTML = "";
  for (const lay of m.layers) {
    const title = (lay.number ? `L${lay.number} · ` : "") + lay.name + (lay.isVertical ? " ⇅" : "");
    root.appendChild(column(title, lay.description, `${lay.threats.length} threats`, lay.threats, lay.isVertical ? "vertical" : ""));
  }
  if (m.crossLayer.length)
    root.appendChild(column("Cross-Layer Threats", "Threats that span or propagate across multiple layers.", `${m.crossLayer.length} threats`, m.crossLayer, "cross"));
  $("maestro-stats").textContent = `${m.summary.layers} layers · ${m.summary.threats} layer threats · ${m.summary.crossLayer} cross-layer`;
  applyFilter();
}

function applyFilter(): void {
  const q = ($("maestro-search") as HTMLInputElement).value.trim().toLowerCase();
  document.querySelectorAll<HTMLElement>(".att-cell").forEach((c) => {
    c.style.display = !q || (c.dataset.s ?? "").includes(q) ? "" : "none";
  });
}

async function load(): Promise<void> {
  const root = $("maestro-matrix");
  root.innerHTML = `<div style="padding:24px;color:var(--text-muted)">Loading…</div>`;
  try {
    const r = await fetch("/api/maestro/matrix");
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(d as { error?: string }).error || `Error ${r.status}`}</div>`;
      return;
    }
    const m = (await r.json()) as Matrix;
    render(m);
    if (!m.layers.some((l) => l.threats.length) && !m.crossLayer.length) {
      root.insertAdjacentHTML("afterbegin",
        `<div style="padding:0 16px 12px;color:var(--text-dim);font-size:12px">No threats imported. Run <code>python xorcism_python/importers/import_maestro.py</code>.</div>`);
    }
  } catch (e) {
    root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(e as Error).message}</div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  renderSteps();
  ($("maestro-search") as HTMLInputElement).oninput = applyFilter;
  void load();
});
