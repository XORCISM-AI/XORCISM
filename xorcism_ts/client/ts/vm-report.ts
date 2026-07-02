/** vm-report.ts — VM Executive Report (/vm-report): risk & SLA posture trends + myth-busting.
 *  Reads /api/vm-report. Pure-SVG line charts (no chart lib). */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function nfmt(n: number): string { return n.toLocaleString(); }
// i18n: session-ui exposes the translator as window.t; fall back to the English default.
// Named `tr` because `t` is used locally in load() for the trend series.
function tr(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }

interface Delta { first: number | null; last: number | null; abs: number | null; pct: number | null; improving: boolean }

/** Trend badge: arrow by direction of change, colour by whether that direction is *good*. */
function trendBadge(d: Delta | undefined, points: number): string {
  if (!d || points < 2 || d.abs == null || d.abs === 0 || d.pct == null) return `<div class="trend tr-flat">${tr("vmr.noTrend", "— no trend yet")}</div>`;
  const arrow = d.abs < 0 ? "▼" : "▲";
  const cls = d.improving ? "tr-up" : "tr-dn";
  const sign = d.pct > 0 ? "+" : "";
  return `<div class="trend ${cls}">${arrow} ${sign}${d.pct}% <span class="muted" style="font-weight:400">${tr("vmr.vs", "vs")} ${points}${tr("vmr.dAgo", "d ago")}</span></div>`;
}

const card = (lbl: string, val: string, foot: string, trend: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>${trend}<div class="foot">${esc(foot)}</div></div>`;

/** Minimal SVG line + area chart over a series, reading numeric `key`. */
function lineChart(series: any[], key: string, color: string): string {
  const pts = series.map((s, i) => ({ i, v: s[key] })).filter((p) => typeof p.v === "number");
  if (pts.length < 2) return `<div class="muted" style="padding:18px 0;font-size:12px">${tr("vmr.notEnough", "Not enough history yet — snapshots accrue daily.")}</div>`;
  const W = 300, H = 80, pad = 6;
  const xs = pts.map((p) => p.i), vs = pts.map((p) => p.v as number);
  const xmin = Math.min(...xs), xmax = Math.max(...xs);
  let vmin = Math.min(...vs), vmax = Math.max(...vs);
  if (vmin === vmax) { vmin -= 1; vmax += 1; }
  const X = (i: number) => pad + ((i - xmin) / (xmax - xmin || 1)) * (W - 2 * pad);
  const Y = (v: number) => pad + (1 - (v - vmin) / (vmax - vmin)) * (H - 2 * pad);
  const line = pts.map((p, k) => `${k ? "L" : "M"}${X(p.i).toFixed(1)},${Y(p.v as number).toFixed(1)}`).join(" ");
  const area = `${line} L${X(xmax).toFixed(1)},${(H - pad).toFixed(1)} L${X(xmin).toFixed(1)},${(H - pad).toFixed(1)} Z`;
  const last = pts[pts.length - 1];
  const gid = "g" + key + Math.random().toString(36).slice(2, 7);
  return `<svg class="lc" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:80px;display:block">
    <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${color}" stop-opacity="0.28"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
    <path d="${area}" fill="url(#${gid})"/><path d="${line}" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke"/>
    <circle cx="${X(last.i).toFixed(1)}" cy="${Y(last.v as number).toFixed(1)}" r="3" fill="${color}"/></svg>`;
}

function chartPanel(title: string, sub: string, series: any[], key: string, color: string, fmt: (n: number) => string): string {
  const pts = series.map((s) => s[key]).filter((v) => typeof v === "number") as number[];
  const last = pts.length ? pts[pts.length - 1] : null, first = pts.length ? pts[0] : null;
  return `<div class="panel"><h3>${esc(title)}</h3><div class="ph">${esc(sub)}</div>
    <div style="font-size:22px;font-weight:700;color:${color};margin-bottom:4px">${last != null ? fmt(last) : "—"}</div>
    ${lineChart(series, key, color)}
    <div class="muted" style="font-size:11px;margin-top:6px">${first != null && last != null && pts.length >= 2 ? `${fmt(first)} → ${fmt(last)} ${tr("vmr.over", "over")} ${pts.length} ${tr("vmr.snapshots", "snapshots")}` : `${pts.length} ${tr("vmr.snapshots", "snapshots")}`}</div></div>`;
}

function load(): void {
  fetch("/api/vm-report").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    const p = d.posture, t = d.trend, pts = d.points;
    const cards = [
      card(tr("vmr.c.risk", "Risk-weighted exposure"), nfmt(p.riskExposure), tr("vmr.c.riskFoot", "open backlog risk score"), trendBadge(t.risk, pts), "#fb923c"),
      card(tr("vmr.c.open", "Open backlog"), nfmt(p.open), `${p.total} ${tr("vmr.total", "total")} · ${p.coverage ?? 0}% ${tr("vmr.remediated", "remediated")}`, trendBadge(t.open, pts), "#60a5fa"),
      card(tr("vmr.c.kev", "Known-exploited (KEV)"), nfmt(p.kevOpen), `${p.exploitableOpen} ${tr("vmr.exploitableOpen", "exploitable open")}`, trendBadge(t.kev, pts), p.kevOpen ? "#f87171" : "#4ade80"),
      card(tr("vmr.c.sla", "SLA compliance"), (p.slaCompliance ?? 0) + "%", `${p.overdue} ${tr("vmr.pastDue", "past due")}`, trendBadge(t.sla, pts), (p.slaCompliance ?? 0) >= 80 ? "#4ade80" : "#fbbf24"),
      card(tr("vmr.c.mttr", "MTTR"), p.mttrDays != null ? p.mttrDays + " d" : "—", tr("vmr.c.mttrFoot", "mean time to remediate"), trendBadge(t.mttr, pts), "#a78bfa"),
      card(tr("vmr.c.unowned", "Unowned"), nfmt(p.unassignedOpen), tr("vmr.c.unownedFoot", "open findings without an owner"), "", p.unassignedOpen ? "#fbbf24" : "#4ade80"),
    ].join("");

    const exec = `<div class="exec">${d.summary.map((s: string) => esc(s).replace(/(\d[\d,]*%?|\b\d+ days?\b)/g, "<b>$1</b>")).join("<br>")}</div>`;

    const charts = [
      chartPanel(tr("vmr.c.risk", "Risk-weighted exposure"), tr("vmr.ch.riskSub", "lower is better — the real signal"), d.series, "riskExposure", "#fb923c", nfmt),
      chartPanel(tr("vmr.c.open", "Open backlog"), tr("vmr.ch.openSub", "open findings over time"), d.series, "openCount", "#60a5fa", nfmt),
      chartPanel(tr("vmr.ch.slaPct", "SLA compliance %"), tr("vmr.ch.slaSub", "higher is better"), d.series, "slaCompliance", "#4ade80", (n) => n + "%"),
      chartPanel(tr("vmr.ch.kevOpen", "Known-exploited (KEV) open"), tr("vmr.ch.kevSub", "lower is better — actively attacked"), d.series, "kevOpen", "#f87171", nfmt),
    ].join("");

    const myths = d.myths.map((m: any) => `<div class="myth">
      <div class="m-head"><span class="x">✕</span><span class="m-myth">${esc(m.myth)}</span></div>
      <div class="m-real"><span class="ok">✓ ${tr("vmr.reality", "Reality")}</span><span>${esc(m.reality)}</span></div>
      <div class="m-stat">${esc(m.stat)}</div>
      <div class="m-foot"><span class="metric">${esc(m.metric)}</span><span class="ref">${esc(m.ref)}</span></div></div>`).join("");

    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">${tr("vmr.execSummary", "Executive summary")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none;font-weight:400">${tr("vmr.generated", "generated")} ${esc(String(d.generatedAt).slice(0, 16).replace("T", " "))}${pts >= 2 ? ` · ${pts} ${tr("vmr.dailySnaps", "daily snapshots")}` : ""}</span></div>${exec}
      <div class="sec">${tr("vmr.postureOverTime", "Risk & SLA posture over time")}</div>
      <div class="grid2">${charts}</div>
      <div class="sec">${tr("vmr.mythsVsReality", "Myths vs reality")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none;font-weight:400">${tr("vmr.debunked", "debunked with your own live numbers")}</span></div>
      <div class="mythgrid">${myths}</div>`;
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function toast(msg: string): void { const el = $("toast"); el.textContent = msg; el.className = "show"; setTimeout(() => { el.className = ""; }, 2200); }

/** Translate the static HTML chrome (title, subtitle, buttons) via the window.t global. */
function translateChrome(): void {
  const set = (sel: string, key: string, fb: string) => { const el = document.querySelector(sel); if (el) el.textContent = tr(key, fb); };
  set(".mw h1", "vmr.pageTitle", "Vulnerability Management — Executive Report");
  const sub = document.querySelector(".mw .sub");
  if (sub) sub.innerHTML = tr("vmr.pageSub", "A board-ready view of the vulnerability program: <b>risk &amp; SLA posture over time</b> (is risk actually going down?) and a <b>myths-vs-reality</b> briefing where the program's <b>own live numbers</b> debunk the misconceptions that keep VM ineffective — <i>“patch everything”</i>, <i>“CVSS = priority”</i>, <i>“100% patched = secure”</i>, and more.");
  const snap = $("btn-snap"); if (snap) { snap.innerHTML = `&#8635; ${tr("vmr.snapshot", "Snapshot")}`; snap.setAttribute("title", tr("vmr.snapshotTitle", "Recompute today's posture snapshot")); }
  const prn = $("btn-print"); if (prn) prn.innerHTML = `&#128424;&#65039; ${tr("vmr.printPdf", "Print / PDF")}`;
  const barTitle = document.querySelector(".topbar .title"); if (barTitle) barTitle.innerHTML = `&#128202; ${tr("vmr.barTitle", "VM Executive Report")}`;
}

document.addEventListener("DOMContentLoaded", () => {
  translateChrome();
  load();
  $("btn-print").addEventListener("click", () => window.print());
  $("btn-snap").addEventListener("click", () => {
    fetch("/api/vm-report/snapshot", { method: "POST" }).then((r) => r.json()).then(() => { toast(tr("vmr.snapCaptured", "Snapshot captured")); load(); }).catch(() => toast(tr("vmr.snapFailed", "Snapshot failed")));
  });
});
