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

// Security-posture KPI strip — aggregates the governance module summaries.
interface Kpis {
  riskScore: number | null;
  assets: { total: number; crownJewels: number; internetFacing: number; criticalVulns: number; unbacked: number; noOwner: number } | null;
  identities: { total: number; privileged: number; orphaned: number; mfaGaps: number } | null;
  incidents: { open: number; criticalOpen: number; breached: number; mttrHours: number | null } | null;
  compliance: { completionRate: number | null; openFindings: number; highOpen: number; overdue: number } | null;
  tid: { tidScore: number; detectRate: number; mitigateRate: number; testRate: number; detectionFailed: number; detectionRegressed: number; exposed: number; threatRelevant: number } | null;
  crisis: { readinessScore: number; exercises: number; completionRate: number | null; scenarioCoverage: number; openActions: number; overdueActions: number; scenariosNeverExercised: number } | null;
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

  tile(k.riskScore, "Enterprise risk", "risk × value", "/exposure", riskColor(k.riskScore ?? 0));
  if (k.assets) {
    tile(k.assets.crownJewels, "Crown jewels", `of ${k.assets.total} assets`, "/asset-management", "#7c83fd");
    tile(k.assets.criticalVulns, "Assets · KEV/critical", "open critical vulns", "/asset-management", badColor(k.assets.criticalVulns));
    tile(k.assets.internetFacing, "Internet-facing", "publicly exposed", "/asset-management", warnColor(k.assets.internetFacing));
    tile(k.assets.unbacked, "Unbacked critical", "critical · no backup", "/asset-management", badColor(k.assets.unbacked));
  }
  if (k.identities) {
    tile(k.identities.privileged, "Privileged identities", "admin / root / owner", "/identities", "#c084fc");
    tile(k.identities.orphaned, "Orphaned NHI", "no accountable owner", "/identities", warnColor(k.identities.orphaned));
    tile(k.identities.mfaGaps, "MFA gaps", "privileged · no MFA", "/identities", badColor(k.identities.mfaGaps));
  }
  if (k.incidents) {
    tile(k.incidents.criticalOpen, "Open critical incidents", `${k.incidents.open} open total`, "/incident-management", badColor(k.incidents.criticalOpen));
    tile(k.incidents.breached, "SLA / RTO breaches", "past target", "/incident-sla", warnColor(k.incidents.breached));
    tile(k.incidents.mttrHours != null ? `${k.incidents.mttrHours}h` : null, "MTTR", "mean time to resolve", "/incident-management");
  }
  if (k.compliance) {
    tile(k.compliance.completionRate != null ? `${k.compliance.completionRate}%` : null, "Audit completion", "audits completed", "/compliance-management", pctColor(k.compliance.completionRate));
    tile(k.compliance.highOpen, "High findings open", `${k.compliance.openFindings} open · ${k.compliance.overdue} overdue`, "/compliance-management", badColor(k.compliance.highOpen));
  }
  if (k.tid) {
    tile(k.tid.tidScore, "TID program score", "threat-weighted defence", "/threat-informed-defense", pctColor(k.tid.tidScore));
    tile(`${k.tid.detectRate}%`, "Detection coverage", `${k.tid.threatRelevant} threat-relevant techniques`, "/threat-informed-defense", pctColor(k.tid.detectRate));
    tile(k.tid.detectionFailed + k.tid.detectionRegressed, "False coverage / drift", "rules that didn't fire", "/threat-informed-defense", badColor(k.tid.detectionFailed + k.tid.detectionRegressed));
    tile(k.tid.exposed, "Exposed techniques", "high-threat · 0 defence", "/threat-informed-defense", badColor(k.tid.exposed));
  }
  if (k.crisis) {
    tile(k.crisis.readinessScore, "Crisis readiness", "completion × coverage", "/crisis-management", pctColor(k.crisis.readinessScore));
    tile(`${k.crisis.scenarioCoverage}%`, "Scenario coverage", `${k.crisis.exercises} exercise(s) run`, "/crisis-management", pctColor(k.crisis.scenarioCoverage));
    tile(k.crisis.openActions, "Improvement actions", `${k.crisis.overdueActions} overdue · ${k.crisis.scenariosNeverExercised} untested scenarios`, "/crisis-management", warnColor(k.crisis.openActions));
  }
  strip.innerHTML = tiles.join("");
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  initKpis();
  initRiskScore();
  initVuln();
  initFinancial();
  initRiskExposure();
  initFinancialHistory();
  initIncidents();
  initIncidentsByAsset();
  initTagCloud();
});
