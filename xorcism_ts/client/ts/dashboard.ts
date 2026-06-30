/**
 * dashboard.ts — XORCISM Dashboard page
 *  - Vulnerabilities by year (bars, VULNERABILITY table)
 *  - Incidents by status (doughnut, INCIDENT ⋈ INCIDENTSTATUS)
 */

import { api } from "./api";
import { initI18n, lang, t } from "./i18n";

// Chart.js is loaded globally via CDN in dashboard.html
declare const Chart: any;

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

const PALETTE = [
  "#7c83fd", "#4ade80", "#f87171", "#fbbf24", "#60a5fa",
  "#f472b6", "#34d399", "#a78bfa", "#fb923c", "#22d3ee",
  "#e879f9", "#facc15", "#2dd4bf",
];

// Score color according to its severity (neutral / green / amber / red).
function riskColor(s: number): string {
  if (s >= 100) return "#f87171";
  if (s >= 30) return "#fbbf24";
  if (s > 0) return "#4ade80";
  return "#94a3b8";
}

// EnterpriseRiskScore of the current tenant — refreshed every 30 s.
async function refreshRiskScore(): Promise<void> {
  const valEl = $("risk-score-value");
  const statsEl = $("risk-stats");
  try {
    const r = await api.getEnterpriseRiskScore();
    valEl.textContent = r.score.toLocaleString();
    valEl.style.color = riskColor(r.score);
    statsEl.textContent = t("dash.updated") + " " + new Date().toLocaleTimeString(lang());
  } catch (e) {
    statsEl.textContent = t("dash.loadError") + " " + e;
  }
}

function initRiskScore(): void {
  void refreshRiskScore();
  window.setInterval(() => void refreshRiskScore(), 30_000); // recompute every 30 s
}

async function initVuln(): Promise<void> {
  let data: { year: string; count: number }[] = [];
  try {
    data = await api.getVulnByYear();
  } catch (e) {
    $("vuln-stats").textContent = t("dash.loadError") + " " + e;
    return;
  }
  if (!data.length) {
    $("vuln-empty").style.display = "";
    return;
  }
  const labels = data.map((d) => d.year);
  const counts = data.map((d) => d.count);
  const total = counts.reduce((a, b) => a + b, 0);
  $("vuln-stats").textContent =
    `${total.toLocaleString()} ${t("dash.vulnsUnit")} • ${labels.length} ${t("dash.yearsUnit")} ` +
    `(${labels[0]}–${labels[labels.length - 1]})`;

  if (typeof Chart === "undefined") {
    $("vuln-stats").textContent += "  " + t("dash.chartJsMissing");
    return;
  }
  new Chart(($("vuln-chart") as HTMLCanvasElement).getContext("2d"), {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: t("dash.vulns"),
          data: counts,
          backgroundColor: "#7c83fd",
          hoverBackgroundColor: "#9aa0ff",
          borderRadius: 4,
          maxBarThickness: 48,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: { label: (ctx: any) => ` ${ctx.parsed.y.toLocaleString()} ${t("dash.vulnsUnit")}` },
        },
      },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e2133" } },
        y: { beginAtZero: true, ticks: { color: "#94a3b8" }, grid: { color: "#1e2133" } },
      },
    },
  });
}

async function initFinancial(): Promise<void> {
  let data: { assets: { name: string; value: number }[]; total: number; count: number };
  try {
    data = await api.getAssetFinancialValues();
  } catch (e) {
    $("fin-stats").textContent = t("dash.loadError") + " " + e;
    return;
  }
  const money = (n: number): string =>
    new Intl.NumberFormat(lang(), { maximumFractionDigits: 0 }).format(n);
  if (!data.assets.length) {
    $("fin-empty").style.display = "";
    return;
  }
  $("fin-stats").textContent =
    `${t("dash.financialTotal")} : ${money(data.total)} • ${data.count} ${t("dash.assetsUnit")}`;

  if (typeof Chart === "undefined") {
    $("fin-stats").textContent += "  " + t("dash.chartJsMissing");
    return;
  }
  new Chart(($("fin-chart") as HTMLCanvasElement).getContext("2d"), {
    type: "bar",
    data: {
      labels: data.assets.map((a) => a.name),
      datasets: [
        {
          label: t("dash.assetFinancialValue"),
          data: data.assets.map((a) => a.value),
          backgroundColor: "#22d3ee",
          hoverBackgroundColor: "#67e8f9",
          borderRadius: 4,
          maxBarThickness: 48,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (ctx: any) => " " + money(ctx.parsed.y) } },
      },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e2133" } },
        y: { beginAtZero: true, ticks: { color: "#94a3b8", callback: (v: any) => money(Number(v)) }, grid: { color: "#1e2133" } },
      },
    },
  });
}

let finHistChart: any = null;
async function initFinancialHistory(): Promise<void> {
  const input = $("finhist-asset") as HTMLInputElement;
  // Datalist of asset names (input aid)
  try {
    const opts = await api.getLookup("XORCISM", "ASSET", "AssetID", "AssetName");
    const dl = $("finhist-assets");
    dl.innerHTML = "";
    const seen = new Set<string>();
    for (const o of opts) {
      const name = String(o.label ?? "").trim();
      if (!name || seen.has(name)) continue;
      seen.add(name);
      const opt = document.createElement("option");
      opt.value = name;
      dl.appendChild(opt);
    }
  } catch { /* lookup unavailable */ }

  const money = (n: number): string =>
    new Intl.NumberFormat(lang(), { maximumFractionDigits: 0 }).format(n);

  const run = async (): Promise<void> => {
    const name = input.value.trim();
    if (!name) return;
    let data: { asset: string; points: { date: string; value: number; currency: string | null }[] };
    try {
      data = await api.getAssetFinancialHistory(name);
    } catch (e) {
      $("finhist-empty").textContent = t("dash.loadError") + " " + e;
      $("finhist-empty").style.display = "";
      return;
    }
    if (finHistChart) { finHistChart.destroy(); finHistChart = null; }
    if (!data.points.length) {
      $("finhist-empty").textContent = t("dash.finHistoryEmpty");
      $("finhist-empty").style.display = "";
      return;
    }
    $("finhist-empty").style.display = "none";
    if (typeof Chart === "undefined") return;
    const cur = data.points[data.points.length - 1].currency || "";
    finHistChart = new Chart(($("finhist-chart") as HTMLCanvasElement).getContext("2d"), {
      type: "line",
      data: {
        labels: data.points.map((p) => p.date),
        datasets: [
          {
            label: `${name} (${cur})`,
            data: data.points.map((p) => p.value),
            borderColor: "#4ade80",
            backgroundColor: "rgba(74,222,128,.15)",
            pointBackgroundColor: "#4ade80",
            tension: 0.2,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: "#94a3b8" } },
          tooltip: { callbacks: { label: (ctx: any) => ` ${money(ctx.parsed.y)} ${cur}` } },
        },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e2133" } },
          y: { beginAtZero: true, ticks: { color: "#94a3b8", callback: (v: any) => money(Number(v)) }, grid: { color: "#1e2133" } },
        },
      },
    });
  };
  $("finhist-go").addEventListener("click", () => void run());
  input.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void run(); });
}

async function initRiskExposure(): Promise<void> {
  let data: {
    assets: { name: string; risk: number; value: number; exposure: number }[];
    totalExposure: number; totalValue: number; count: number;
  };
  try {
    data = await api.getAssetRiskExposure();
  } catch (e) {
    $("exp-stats").textContent = t("dash.loadError") + " " + e;
    return;
  }
  const money = (n: number): string =>
    new Intl.NumberFormat(lang(), { maximumFractionDigits: 0 }).format(n);
  if (!data.assets.length) {
    $("exp-empty").style.display = "";
    return;
  }
  // Some assets carry a value OR a risk, but none both → zero exposure:
  // an all-zero chart would look broken, we show the explanatory message instead.
  if (data.totalExposure === 0) {
    const empty = $("exp-empty");
    empty.textContent = t("dash.noExposure");
    empty.style.display = "";
    $("exp-stats").textContent =
      `${t("dash.exposureTotal")} : ${money(0)} • ${data.count} ${t("dash.assetsUnit")}`;
    return;
  }
  $("exp-stats").textContent =
    `${t("dash.exposureTotal")} : ${money(data.totalExposure)} • ${data.count} ${t("dash.assetsUnit")}`;

  if (typeof Chart === "undefined") {
    $("exp-stats").textContent += "  " + t("dash.chartJsMissing");
    return;
  }
  new Chart(($("exp-chart") as HTMLCanvasElement).getContext("2d"), {
    type: "bar",
    data: {
      labels: data.assets.map((a) => a.name),
      datasets: [
        {
          label: t("dash.riskExposure"),
          data: data.assets.map((a) => a.exposure),
          backgroundColor: "#f87171",
          hoverBackgroundColor: "#fca5a5",
          borderRadius: 4,
          maxBarThickness: 48,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx: any) => {
              const a = data.assets[ctx.dataIndex];
              return ` ${money(a.exposure)}  (${t("dash.riskShort")} ${a.risk} × ${money(a.value)})`;
            },
          },
        },
      },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e2133" } },
        y: { beginAtZero: true, ticks: { color: "#94a3b8", callback: (v: any) => money(Number(v)) }, grid: { color: "#1e2133" } },
      },
    },
  });
}

async function initIncidents(): Promise<void> {
  let data: { status: string; count: number }[] = [];
  try {
    data = await api.getIncidentsByStatus();
  } catch (e) {
    $("inc-stats").textContent = t("dash.loadError") + " " + e;
    return;
  }
  if (!data.length) {
    $("inc-empty").style.display = "";
    return;
  }
  const labels = data.map((d) => d.status);
  const counts = data.map((d) => d.count);
  const total = counts.reduce((a, b) => a + b, 0);
  $("inc-stats").textContent =
    `${total.toLocaleString()} incidents • ${labels.length} ${t("dash.statusesUnit")}`;

  if (typeof Chart === "undefined") {
    $("inc-stats").textContent += "  " + t("dash.chartJsMissing");
    return;
  }
  new Chart(($("inc-chart") as HTMLCanvasElement).getContext("2d"), {
    type: "doughnut",
    data: {
      labels,
      datasets: [
        {
          label: "Incidents",
          data: counts,
          backgroundColor: labels.map((_l, i) => PALETTE[i % PALETTE.length]),
          borderColor: "#13162a",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#cbd5e1", boxWidth: 14 } },
        tooltip: {
          callbacks: {
            label: (ctx: any) => {
              const v = ctx.parsed;
              const pct = total ? ((v / total) * 100).toFixed(1) : "0";
              return ` ${ctx.label}: ${v.toLocaleString()} (${pct}%)`;
            },
          },
        },
      },
    },
  });
}

let assetChart: any = null;

async function renderIncidentsByAsset(from?: string, to?: string): Promise<void> {
  let data: { asset: string; count: number }[] = [];
  try {
    data = await api.getIncidentsByAsset(from, to);
  } catch (e) {
    $("asset-stats").textContent = t("dash.loadError") + " " + e;
    return;
  }
  if (assetChart) {
    assetChart.destroy();
    assetChart = null;
  }
  const emptyEl = $("asset-empty");
  if (!data.length) {
    emptyEl.style.display = "";
    $("asset-stats").textContent = "";
    return;
  }
  emptyEl.style.display = "none";

  const labels = data.map((d) => d.asset);
  const counts = data.map((d) => d.count);
  const total = counts.reduce((a, b) => a + b, 0);
  const periode = from || to
    ? ` • ${t("dash.period")} ${from || "…"} → ${to || "…"}`
    : ` • ${t("dash.allDates")}`;
  $("asset-stats").textContent =
    `${total.toLocaleString()} ${t("dash.incidentUnit")} • ${labels.length} ${t("dash.assetUnit")}${periode}`;

  if (typeof Chart === "undefined") return;
  assetChart = new Chart(($("asset-chart") as HTMLCanvasElement).getContext("2d"), {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Incidents",
          data: counts,
          backgroundColor: "#4ade80",
          hoverBackgroundColor: "#86efac",
          borderRadius: 4,
          maxBarThickness: 48,
        },
      ],
    },
    options: {
      indexAxis: "y", // horizontal bars (readable asset names)
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (ctx: any) => ` ${ctx.parsed.x} ${t("dash.incidentUnit")}` } },
      },
      scales: {
        x: { beginAtZero: true, ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "#1e2133" } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "#1e2133" } },
      },
    },
  });
}

function initIncidentsByAsset(): void {
  const fromEl = $("asset-from") as HTMLInputElement;
  const toEl = $("asset-to") as HTMLInputElement;
  $("asset-apply").onclick = () =>
    renderIncidentsByAsset(fromEl.value || undefined, toEl.value || undefined);
  $("asset-reset").onclick = () => {
    fromEl.value = "";
    toEl.value = "";
    renderIncidentsByAsset();
  };
  renderIncidentsByAsset(); // initial display (all dates)
}

// Tag cloud: font size proportional to the tag frequency; each
// tag points to the ASSETTAG table filtered on that value.
async function initTagCloud(): Promise<void> {
  const host = $("tagcloud");
  let data: { tag: string; count: number }[] = [];
  try {
    data = await api.getAssetTagCloud();
  } catch (e) {
    $("tagcloud-stats").textContent = t("dash.loadError") + " " + e;
    return;
  }
  if (!data.length) { $("tagcloud-empty").style.display = ""; return; }
  const counts = data.map((d) => d.count);
  const max = Math.max(...counts), min = Math.min(...counts);
  $("tagcloud-stats").textContent = `${data.length} tags`;
  host.innerHTML = "";
  for (const d of data) {
    const ratio = max === min ? 1 : (d.count - min) / (max - min); // 0..1
    const size = 13 + Math.round(ratio * 17); // 13px → 30px according to the frequency
    const a = document.createElement("a");
    a.href = `/?db=XORCISM&table=ASSETTAG&filterCol=Tag&filterVal=${encodeURIComponent(d.tag)}`;
    a.textContent = d.tag;
    a.title = `${d.tag} — ${d.count}`;
    a.style.cssText = `font-size:${size}px;color:var(--accent);text-decoration:none;opacity:${(0.6 + ratio * 0.4).toFixed(2)}`;
    host.appendChild(a);
  }
}

// EnterpriseRiskScore over time (ORGANISATIONRISKSCORE) — line chart with a selectable period.
let riskHistChart: any = null;
async function initRiskHistory(): Promise<void> {
  const sel = document.getElementById("riskhist-period") as HTMLSelectElement | null;
  const run = async (): Promise<void> => {
    const days = sel ? Number(sel.value) : 90;
    let d: { organisationId: number | null; current: number | null; points: { date: string; score: number }[] };
    try { const r = await fetch(`/api/dashboard/risk-history?days=${days}`); if (!r.ok) throw new Error(String(r.status)); d = await r.json(); }
    catch (e) { $("riskhist-stats").textContent = t("dash.loadError") + " " + e; return; }
    if (riskHistChart) { riskHistChart.destroy(); riskHistChart = null; }
    if (!d.points || !d.points.length) {
      $("riskhist-empty").style.display = "";
      $("riskhist-stats").textContent = d.current != null ? `${t("dash.current")}: ${d.current.toLocaleString()}` : "";
      return;
    }
    $("riskhist-empty").style.display = "none";
    const last = d.points[d.points.length - 1].score, first = d.points[0].score, delta = Math.round(last - first);
    $("riskhist-stats").textContent = `${d.points.length} ${t("dash.pointsUnit")} · ${t("dash.current")}: ${Math.round(last).toLocaleString()}` + (d.points.length > 1 ? ` (${delta >= 0 ? "+" : ""}${delta.toLocaleString()})` : "");
    if (typeof Chart === "undefined") return;
    riskHistChart = new Chart(($("riskhist-chart") as HTMLCanvasElement).getContext("2d"), {
      type: "line",
      data: { labels: d.points.map((p) => p.date), datasets: [{ label: t("dash.riskScore"), data: d.points.map((p) => Math.round(p.score)), borderColor: "#f87171", backgroundColor: "rgba(248,113,113,.12)", pointBackgroundColor: "#f87171", tension: 0.25, fill: true, pointRadius: d.points.length > 60 ? 0 : 3, borderWidth: 2 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (ctx: any) => ` ${ctx.parsed.y.toLocaleString()}` } } },
        scales: { x: { ticks: { color: "#94a3b8", maxTicksLimit: 12, autoSkip: true }, grid: { color: "#1e2133" } }, y: { beginAtZero: true, ticks: { color: "#94a3b8" }, grid: { color: "#1e2133" } } },
      },
    });
  };
  if (sel) sel.onchange = () => void run();
  await run();
}

// Enterprise-risk breakdown — horizontal bar of the signed contributors to the RiskScore.
async function initRiskBreakdown(): Promise<void> {
  let d: { total: number; drivers: { key: string; label: string; value: number }[] };
  try { const r = await fetch("/api/dashboard/risk-breakdown"); if (!r.ok) throw new Error(String(r.status)); d = await r.json(); }
  catch { return; }
  if (!d.drivers || !d.drivers.length) { $("risk-breakdown-empty").style.display = ""; return; }
  if (typeof Chart === "undefined") return;
  const driverColor = (k: string, v: number): string =>
    v < 0 ? "#34d399" : k === "incidents" ? "#f87171" : k === "riskRegister" ? "#fb923c" : k === "compliance" ? "#fbbf24" : "#7c83fd";
  new Chart(($("risk-breakdown-chart") as HTMLCanvasElement).getContext("2d"), {
    type: "bar",
    data: {
      labels: d.drivers.map((x) => x.label),
      datasets: [{ data: d.drivers.map((x) => x.value), backgroundColor: d.drivers.map((x) => driverColor(x.key, x.value)), borderRadius: 4, maxBarThickness: 30 }],
    },
    options: {
      indexAxis: "y", responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        title: { display: true, text: `${t("dash.riskTotal")}: ${d.total.toLocaleString()}`, color: "#cbd5e1", font: { size: 13 } },
        tooltip: { callbacks: { label: (ctx: any) => ` ${ctx.parsed.x > 0 ? "+" : ""}${ctx.parsed.x} ${t("dash.riskPoints")}` } },
      },
      scales: { x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e2133" } }, y: { ticks: { color: "#cbd5e1" }, grid: { display: false } } },
    },
  });
}

// Security-program maturity radar — the "higher = better" program scores (0-100).
async function initPostureRadar(): Promise<void> {
  let k: any;
  try { const r = await fetch("/api/dashboard/kpis"); if (!r.ok) throw new Error(String(r.status)); k = await r.json(); }
  catch { return; }
  const axes = [
    { label: t("dash.radar.detection"), value: k.tid?.detectRate },
    { label: t("dash.radar.mitigation"), value: k.tid?.mitigateRate },
    { label: t("dash.radar.validation"), value: k.tid?.testRate },
    { label: t("dash.radar.compliance"), value: k.compliance?.completionRate },
    { label: t("dash.radar.crisis"), value: k.crisis?.readinessScore },
    { label: t("dash.radar.riskTreated"), value: k.risk?.treatedRate },
  ].filter((a) => a.value != null && Number.isFinite(Number(a.value)));
  if (axes.length < 3) { $("radar-empty").style.display = ""; return; }
  $("radar-stats").textContent = `${axes.length} ${t("dash.programs")}`;
  if (typeof Chart === "undefined") return;
  new Chart(($("radar-chart") as HTMLCanvasElement).getContext("2d"), {
    type: "radar",
    data: { labels: axes.map((a) => a.label), datasets: [{ label: t("dash.maturityPct"), data: axes.map((a) => Number(a.value)), backgroundColor: "rgba(124,131,253,.2)", borderColor: "#7c83fd", pointBackgroundColor: "#7c83fd", borderWidth: 2 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: "#94a3b8" } }, tooltip: { callbacks: { label: (ctx: any) => ` ${ctx.label}: ${ctx.parsed.r}%` } } },
      scales: { r: { min: 0, max: 100, ticks: { color: "#64748b", backdropColor: "transparent", stepSize: 20 }, grid: { color: "#1e2133" }, angleLines: { color: "#1e2133" }, pointLabels: { color: "#cbd5e1", font: { size: 12 } } } },
    },
  });
}

// Risk heatmap — open risk-register entries on a 5×5 probability × impact grid (bubble = count,
// colour = risk zone). Vanilla Chart.js bubble chart (no extra plugin).
async function initRiskHeatmap(): Promise<void> {
  let d: { grid: { p: number; i: number; count: number; refs: string[] }[]; total: number; placed: number };
  try { const r = await fetch("/api/dashboard/risk-heatmap"); if (!r.ok) throw new Error(String(r.status)); d = await r.json(); }
  catch { return; }
  if (!d.grid || !d.grid.length) {
    $("heatmap-empty").style.display = "";
    $("heatmap-stats").textContent = d && d.total ? `${d.total} ${t("dash.risksUnit")}` : "";
    return;
  }
  $("heatmap-stats").textContent = `${d.placed}/${d.total} ${t("dash.risksPlaced")}`;
  if (typeof Chart === "undefined") return;
  const zone = (p: number, i: number): string => { const s = p * i; return s >= 20 ? "#ef4444" : s >= 12 ? "#fb923c" : s >= 6 ? "#fbbf24" : "#22c55e"; };
  const maxC = Math.max(...d.grid.map((g) => g.count));
  const pts = d.grid.map((g) => ({ x: g.p, y: g.i, r: 12 + (maxC > 1 ? (g.count / maxC) * 22 : 8), c: g.count, refs: g.refs, col: zone(g.p, g.i) }));
  new Chart(($("heatmap-chart") as HTMLCanvasElement).getContext("2d"), {
    type: "bubble",
    data: { datasets: [{ data: pts, backgroundColor: pts.map((p) => p.col + "cc"), borderColor: pts.map((p) => p.col), borderWidth: 1.5 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: {
          label: (ctx: any) => { const p = pts[ctx.dataIndex]; return ` ${t("dash.prob")} ${p.x} × ${t("dash.impact")} ${p.y}: ${p.c} ${t("dash.risksUnit")}`; },
          afterLabel: (ctx: any) => pts[ctx.dataIndex].refs.join(", "),
        } },
      },
      scales: {
        x: { min: 0.5, max: 5.5, title: { display: true, text: t("dash.probability"), color: "#94a3b8" }, ticks: { stepSize: 1, color: "#94a3b8", callback: (v: any) => (v >= 1 && v <= 5 ? v : "") }, grid: { color: "#1e2133" } },
        y: { min: 0.5, max: 5.5, title: { display: true, text: t("dash.impactAxis"), color: "#94a3b8" }, ticks: { stepSize: 1, color: "#94a3b8", callback: (v: any) => (v >= 1 && v <= 5 ? v : "") }, grid: { color: "#1e2133" } },
      },
    },
  });
}

// Security-posture KPI strip — aggregates the governance module summaries.
interface Kpis {
  riskScore: number | null;
  adversaryOpportunity: { index: number; date: string; net: number | null } | null;
  insurance: { score: number; grade: string; gap: number; critical: number } | null;
  assets: { total: number; crownJewels: number; internetFacing: number; criticalVulns: number; unbacked: number; noOwner: number } | null;
  identities: { total: number; privileged: number; orphaned: number; mfaGaps: number } | null;
  incidents: { open: number; criticalOpen: number; breached: number; mttrHours: number | null; mttdMinutes: number | null } | null;
  compliance: { completionRate: number | null; openFindings: number; highOpen: number; overdue: number } | null;
  tid: { tidScore: number; detectRate: number; mitigateRate: number; testRate: number; detectionFailed: number; detectionRegressed: number; exposed: number; threatRelevant: number } | null;
  crisis: { readinessScore: number; exercises: number; completionRate: number | null; scenarioCoverage: number; openActions: number; overdueActions: number; scenariosNeverExercised: number } | null;
  risk: { riskScore: number; open: number; highCritical: number; untreated: number; overdueReview: number; treatedRate: number | null; totalALE: number; currency: string } | null;
  pqcmm: { maturityScore: number; assessments: number; quantumVulnerable: number; productionReady: number; managed: number } | null;
  patch: { coverage: number | null; overdue: number; kevUnpatched: number; unpatched: number; instances: number; mttr: number | null } | null;
  policy: { published: number; requiringAck: number; ackCoverage: number; pendingAcks: number; fullyAcknowledged: number } | null;
  accessGov: { entitlements: number; sodViolations: number; sodCritical: number; pendingRequests: number; jitActive: number } | null;
  remediation: { open: number; overdue: number; slaCompliance: number | null; mttrHours: number | null; autonomousPct: number | null } | null;
  policyCoverage: { coveragePct: number; uncoveredCritical: number; uncovered: number } | null;
  aware: { agents: number; governed: number; ungoverned: number; autonomousUngoverned: number; revoked: number } | null;
}
const badColor = (n: number): string => (n > 0 ? "#f87171" : "#34d399");
const warnColor = (n: number): string => (n > 0 ? "#fbbf24" : "#34d399");
const pctColor = (n: number | null): string => (n == null ? "#94a3b8" : n >= 70 ? "#34d399" : n >= 40 ? "#fbbf24" : "#f87171");

async function initKpis(): Promise<void> {
  const strip = document.getElementById("kpi-strip");
  if (!strip) return;
  let k: Kpis;
  try { const r = await fetch("/api/dashboard/kpis"); if (!r.ok) throw new Error(String(r.status)); k = await r.json(); }
  catch { strip.style.display = "none"; return; }

  const tiles: string[] = [];
  const tile = (val: string | number | null, lbl: string, foot: string, href: string, color?: string): void => {
    tiles.push(`<a class="kpi" href="${href}"${color ? ` style="--accent:${color}"` : ""}>
      <div class="k-val"${color ? ` style="color:${color}"` : ""}>${val == null ? "—" : val}</div>
      <div class="k-lbl">${lbl}</div><div class="k-foot">${foot}</div></a>`);
  };

  tile(k.riskScore, t("dash.kpi.enterpriseRisk"), t("dash.kpi.enterpriseRisk.f"), "/exposure", riskColor(k.riskScore ?? 0));
  if (k.adversaryOpportunity) {
    const ao = k.adversaryOpportunity;
    const aoColor = ao.index >= 600 ? "#f87171" : ao.index >= 300 ? "#fbbf24" : "#34d399";
    const foot = ao.net == null ? t("dash.kpi.ao.f") : ao.net < 0 ? `▼ ${Math.abs(ao.net)} ${t("dash.kpi.ao.paid")}` : ao.net > 0 ? `▲ ${ao.net} ${t("dash.kpi.ao.accrued")}` : t("dash.kpi.ao.flat");
    tile(ao.index, t("dash.kpi.ao"), foot, "/adversary-opportunity", aoColor);
  }
  if (k.insurance) {
    tile(`${k.insurance.grade}`, t("dash.kpi.insurance"), `${k.insurance.score}/100 · ${k.insurance.gap} ${t("dash.kpi.gaps")}`, "/insurance-readiness", pctColor(k.insurance.score));
  }
  if (k.assets) {
    tile(k.assets.crownJewels, t("dash.kpi.crownJewels"), `${t("dash.kpi.of")} ${k.assets.total} ${t("dash.kpi.assets")}`, "/asset-management", "#7c83fd");
    tile(k.assets.criticalVulns, t("dash.kpi.assetsKev"), t("dash.kpi.assetsKev.f"), "/asset-management", badColor(k.assets.criticalVulns));
    tile(k.assets.internetFacing, t("dash.kpi.internetFacing"), t("dash.kpi.internetFacing.f"), "/asset-management", warnColor(k.assets.internetFacing));
    tile(k.assets.unbacked, t("dash.kpi.unbacked"), t("dash.kpi.unbacked.f"), "/asset-management", badColor(k.assets.unbacked));
  }
  if (k.identities) {
    tile(k.identities.privileged, t("dash.kpi.privIdentities"), t("dash.kpi.privIdentities.f"), "/identities", "#c084fc");
    tile(k.identities.orphaned, t("dash.kpi.orphanedNhi"), t("dash.kpi.orphanedNhi.f"), "/identities", warnColor(k.identities.orphaned));
    tile(k.identities.mfaGaps, t("dash.kpi.mfaGaps"), t("dash.kpi.mfaGaps.f"), "/identities", badColor(k.identities.mfaGaps));
  }
  if (k.incidents) {
    tile(k.incidents.criticalOpen, t("dash.kpi.openCritIncidents"), `${k.incidents.open} ${t("dash.kpi.openTotal")}`, "/incident-management", badColor(k.incidents.criticalOpen));
    tile(k.incidents.breached, t("dash.kpi.slaBreaches"), t("dash.kpi.slaBreaches.f"), "/incident-sla", warnColor(k.incidents.breached));
    tile(k.incidents.mttdMinutes != null ? (k.incidents.mttdMinutes < 90 ? `${k.incidents.mttdMinutes}m` : `${(k.incidents.mttdMinutes / 60).toFixed(1)}h`) : null, "MTTD", t("dash.kpi.mttd.f"), "/soc", k.incidents.mttdMinutes != null && k.incidents.mttdMinutes <= 60 ? "#34d399" : "#fbbf24");
    tile(k.incidents.mttrHours != null ? `${k.incidents.mttrHours}h` : null, "MTTR", t("dash.kpi.mttr.f"), "/soc");
  }
  if (k.compliance) {
    tile(k.compliance.completionRate != null ? `${k.compliance.completionRate}%` : null, t("dash.kpi.auditCompletion"), t("dash.kpi.auditCompletion.f"), "/compliance-management", pctColor(k.compliance.completionRate));
    tile(k.compliance.highOpen, t("dash.kpi.highFindings"), `${k.compliance.openFindings} ${t("dash.kpi.open")} · ${k.compliance.overdue} ${t("dash.kpi.overdue")}`, "/compliance-management", badColor(k.compliance.highOpen));
  }
  if (k.patch) {
    tile(k.patch.coverage != null ? `${k.patch.coverage}%` : null, t("dash.kpi.patchCoverage"), `${k.patch.instances} ${t("dash.kpi.assetCve")}`, "/patch-management", pctColor(k.patch.coverage));
    tile(k.patch.overdue, t("dash.kpi.overduePatches"), t("dash.kpi.overduePatches.f"), "/patch-management", badColor(k.patch.overdue));
    tile(k.patch.kevUnpatched, t("dash.kpi.unpatchedKev"), t("dash.kpi.unpatchedKev.f"), "/patch-management", badColor(k.patch.kevUnpatched));
  }
  if (k.risk) {
    const money = (n: number): string => { try { return new Intl.NumberFormat(lang(), { style: "currency", currency: k.risk!.currency || "EUR", maximumFractionDigits: 0, notation: "compact" }).format(n); } catch { return String(n); } };
    tile(k.risk.riskScore, t("dash.kpi.residualRisk"), `${k.risk.open} ${t("dash.kpi.openRisks")}`, "/risk-register", k.risk.riskScore >= 60 ? "#f87171" : k.risk.riskScore >= 35 ? "#fbbf24" : "#34d399");
    tile(k.risk.untreated, t("dash.kpi.untreatedRisks"), t("dash.kpi.untreatedRisks.f"), "/risk-register", badColor(k.risk.untreated));
    tile(k.risk.totalALE ? money(k.risk.totalALE) : "—", t("dash.kpi.annualizedExposure"), t("dash.kpi.annualizedExposure.f"), "/risk-register", "#f43f5e");
  }
  if (k.tid) {
    tile(k.tid.tidScore, t("dash.kpi.tidScore"), t("dash.kpi.tidScore.f"), "/threat-informed-defense", pctColor(k.tid.tidScore));
    tile(`${k.tid.detectRate}%`, t("dash.kpi.detectionCoverage"), `${k.tid.threatRelevant} ${t("dash.kpi.threatRelevantTechniques")}`, "/threat-informed-defense", pctColor(k.tid.detectRate));
    tile(k.tid.detectionFailed + k.tid.detectionRegressed, t("dash.kpi.falseCoverage"), t("dash.kpi.falseCoverage.f"), "/threat-informed-defense", badColor(k.tid.detectionFailed + k.tid.detectionRegressed));
    tile(k.tid.exposed, t("dash.kpi.exposedTechniques"), t("dash.kpi.exposedTechniques.f"), "/threat-informed-defense", badColor(k.tid.exposed));
  }
  if (k.pqcmm) {
    tile(`${k.pqcmm.maturityScore}%`, t("dash.kpi.quantumReadiness"), `${k.pqcmm.assessments} ${t("dash.kpi.assessedPqcmm")}`, "/pqcmm", pctColor(k.pqcmm.maturityScore));
    tile(k.pqcmm.quantumVulnerable, t("dash.kpi.quantumVulnerable"), t("dash.kpi.quantumVulnerable.f"), "/pqcmm", badColor(k.pqcmm.quantumVulnerable));
  }
  if (k.policy) {
    tile(`${k.policy.ackCoverage}%`, t("dash.kpi.policyAcceptance"), `${k.policy.requiringAck} ${t("dash.kpi.publishedAckRequired")}`, "/policy-management", pctColor(k.policy.ackCoverage));
    tile(k.policy.pendingAcks, t("dash.kpi.pendingAcks"), `${k.policy.fullyAcknowledged}/${k.policy.requiringAck} ${t("dash.kpi.fullyAccepted")}`, "/policy-management", warnColor(k.policy.pendingAcks));
  }
  if (k.policyCoverage) {
    tile(`${k.policyCoverage.coveragePct}%`, t("dash.kpi.policyCoverage"), `${k.policyCoverage.uncoveredCritical} ${t("dash.kpi.critUncovered")}`, "/policy-management", pctColor(k.policyCoverage.coveragePct));
  }
  if (k.accessGov) {
    tile(k.accessGov.sodViolations, t("dash.kpi.sodViolations"), `${k.accessGov.sodCritical} ${t("dash.kpi.critHigh")}`, "/access-governance", badColor(k.accessGov.sodViolations));
    tile(k.accessGov.pendingRequests, t("dash.kpi.accessRequests"), `${k.accessGov.jitActive} ${t("dash.kpi.jitActive")}`, "/access-governance", warnColor(k.accessGov.pendingRequests));
  }
  if (k.remediation) {
    tile(k.remediation.slaCompliance != null ? `${k.remediation.slaCompliance}%` : null, t("dash.kpi.remediationSla"), `${k.remediation.open} ${t("dash.kpi.openPlans")}`, "/exposure-remediation", pctColor(k.remediation.slaCompliance));
    tile(k.remediation.overdue, t("dash.kpi.remediationOverdue"), k.remediation.mttrHours != null ? `MTTR ${k.remediation.mttrHours < 48 ? k.remediation.mttrHours + "h" : Math.round(k.remediation.mttrHours / 24) + "d"}` : t("dash.kpi.pastSla"), "/exposure-remediation", badColor(k.remediation.overdue));
  }
  if (k.aware) {
    tile(k.aware.autonomousUngoverned, t("dash.kpi.ungovernedAgents"), `${k.aware.ungoverned}/${k.aware.agents} ${t("dash.kpi.ungoverned")}`, "/aware", badColor(k.aware.autonomousUngoverned));
  }
  if (k.crisis) {
    tile(k.crisis.readinessScore, t("dash.kpi.crisisReadiness"), t("dash.kpi.crisisReadiness.f"), "/crisis-management", pctColor(k.crisis.readinessScore));
    tile(`${k.crisis.scenarioCoverage}%`, t("dash.kpi.scenarioCoverage"), `${k.crisis.exercises} ${t("dash.kpi.exercisesRun")}`, "/crisis-management", pctColor(k.crisis.scenarioCoverage));
    tile(k.crisis.openActions, t("dash.kpi.improvementActions"), `${k.crisis.overdueActions} ${t("dash.kpi.overdue")} · ${k.crisis.scenariosNeverExercised} ${t("dash.kpi.untestedScenarios")}`, "/crisis-management", warnColor(k.crisis.openActions));
  }
  strip.innerHTML = tiles.join("");
}

// ── Global threat-level gauge (DEFCON / national-advisory style) ───────────────
interface ThreatLvl {
  level: number; label: string; score: number; color: string; windowDays: number;
  signals: Record<string, number>;
  contributors: { key: string; label: string; count: number; points: number }[];
}
const escapeHtml = (s: string): string => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));

async function initThreatLevel(): Promise<void> {
  const el = document.getElementById("threat-level");
  if (!el) return;
  let d: ThreatLvl;
  try { const r = await fetch("/api/dashboard/threat-level"); if (!r.ok) throw new Error(String(r.status)); d = await r.json(); }
  catch { el.style.display = "none"; return; }

  // 270° arc gauge (opening at the bottom), filled proportionally to score/100.
  const R = 44, CX = 54, CY = 52, START = 135, SWEEP = 270; // degrees (SVG y-down)
  const pol = (deg: number): [number, number] => {
    const a = (deg * Math.PI) / 180;
    return [CX + R * Math.cos(a), CY + R * Math.sin(a)];
  };
  const arc = (frac: number): string => {
    const f = Math.max(0, Math.min(1, frac));
    if (f <= 0) return "";
    const end = START + SWEEP * f;
    const [x1, y1] = pol(START), [x2, y2] = pol(end);
    const large = SWEEP * f > 180 ? 1 : 0;
    return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${R} ${R} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
  };
  const gauge =
    `<svg width="110" height="96" viewBox="0 0 108 96" class="tl-gauge" role="img" aria-label="Threat level ${escapeHtml(d.label)}">
      <path d="${arc(1)}" fill="none" stroke="#262b45" stroke-width="9" stroke-linecap="round"/>
      <path d="${arc(d.score / 100)}" fill="none" stroke="${d.color}" stroke-width="9" stroke-linecap="round"/>
      <text x="${CX}" y="49" text-anchor="middle" font-size="23" font-weight="800" fill="${d.color}">${d.score}</text>
      <text x="${CX}" y="64" text-anchor="middle" font-size="9" fill="#94a3b8">/ 100</text>
    </svg>`;

  // Contributor labels + band label come from the server as English enums/strings; localize them
  // client-side by key (the day-window numbers mirror the server constants: KEV/EPSS = windowDays, CTI = 30).
  const ds = t("dash.tl.dShort"); // "d" / " j"
  const cLabel = (c: ThreatLvl["contributors"][number]): string => {
    switch (c.key) {
      case "kevRecent": return `${t("dash.tl.c.kevRecent")} (KEV, ${d.windowDays}${ds})`;
      case "incidentsOpen": return t("dash.tl.c.incidentsOpen");
      case "epssRecent": return `${t("dash.tl.c.epssRecent")} (${d.windowDays}${ds})`;
      case "kevUnpatched": return t("dash.tl.c.kevUnpatched");
      case "threatReports": return `${t("dash.tl.c.threatReports")} (30${ds})`;
      case "intel": return `${t("dash.tl.c.intel")} (30${ds})`;
      default: return c.label;
    }
  };
  const bandLabel = t(`dash.tl.lvl.${d.label}`); // localized condition word (falls back to enum)
  const drivers = d.contributors.filter((c) => c.points > 0).slice(0, 4)
    .map((c) => `<span class="tl-chip">${escapeHtml(cLabel(c))} <b>${c.count}</b></span>`).join("");
  const driversHtml = drivers || `<span class="tl-chip">${escapeHtml(t("dash.tl.noSignalsPre"))} ${d.windowDays} ${escapeHtml(t("dash.tl.daysPost"))}</span>`;

  el.style.borderLeftColor = d.color;
  el.innerHTML =
    `${gauge}
     <div class="tl-meta">
       <div class="tl-label" style="color:${d.color}">${escapeHtml(bandLabel)} <span style="font-size:13px;color:#64748b;font-weight:600">· ${escapeHtml(t("dash.tl.level"))} ${d.level}/5</span></div>
       <div class="tl-sub">${escapeHtml(t("dash.tl.subPre"))} ${d.windowDays}${escapeHtml(t("dash.tl.subPost"))}</div>
       <div class="tl-drivers">${driversHtml}</div>
     </div>`;
  el.style.display = "flex";
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  initThreatLevel();
  initKpis();
  initRiskHistory();
  initRiskScore();
  initRiskBreakdown();
  initPostureRadar();
  initRiskHeatmap();
  initVuln();
  initFinancial();
  initRiskExposure();
  initFinancialHistory();
  initIncidents();
  initIncidentsByAsset();
  initTagCloud();
});
