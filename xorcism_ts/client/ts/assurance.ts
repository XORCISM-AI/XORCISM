/**
 * assurance.ts — Continuous control monitoring view (/assurance).
 * Renders the control posture computed live from telemetry by /api/assurance, plus per-framework
 * readiness (SOC 2 / ISO 27001 / NIST CSF), the posture trend over snapshots, and drift (what changed).
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface FwRef { fw: string; ref: string; }
interface Control { id: string; name: string; iso: string; nist: string; status: string; score: number; metric: string; evidence: string[]; frameworks?: FwRef[]; }
interface FrameworkReadiness { fw: string; label: string; readinessPct: number; proven: number; measurable: number; }
interface Drift { id: string; name: string; from: string; to: string; dir: "up" | "down"; }
interface Assurance {
  controls: Control[];
  stats: { total: number; proven: number; partial: number; gap: number; attest: number; provenPct: number };
  frameworks: FrameworkReadiness[]; trend: { at: string; pct: number }[]; drift: Drift[];
  evaluatedAt: string;
}

const statusLabel = (s: string): string => t("asr.st." + s) || s;
function statusColor(s: string): string { return s === "proven" ? "#22c55e" : s === "partial" ? "#f59e0b" : s === "gap" ? "#ef4444" : "#64748b"; }
function pctColor(p: number): string { return p >= 70 ? "#22c55e" : p >= 40 ? "#f59e0b" : "#ef4444"; }

function ctlCard(c: Control): string {
  const refs = c.frameworks && c.frameworks.length
    ? c.frameworks.map((f) => `${esc(f.fw === "soc2" ? "SOC 2" : f.fw === "iso27001" ? "ISO" : "NIST")} ${esc(f.ref)}`).join(" · ")
    : `ISO ${esc(c.iso)} · NIST ${esc(c.nist)}`;
  return `<div class="ctl">
    <div class="top">
      <span class="nm">${esc(c.name)}</span>
      <span class="refs">${refs}</span>
      <span class="badge b-${esc(c.status)}">${esc(statusLabel(c.status))}</span>
    </div>
    ${c.status !== "attest" ? `<div class="sbar"><i style="width:${c.score}%;background:${statusColor(c.status)}"></i></div>` : ""}
    <div class="metric">${esc(c.metric)}</div>
    ${c.evidence.length ? `<div class="evi">↳ ${c.evidence.map(esc).join(" · ")}</div>` : ""}
  </div>`;
}

// Per-framework readiness cards (the "you are N% SOC 2 ready" headline).
function fwRow(fws: FrameworkReadiness[]): string {
  if (!fws || !fws.length) return "";
  const card = (f: FrameworkReadiness): string => `<div class="fw">
    <div class="fw-top"><span class="fw-lbl">${esc(f.label)}</span><span class="fw-pct" style="color:${pctColor(f.readinessPct)}">${f.readinessPct}%</span></div>
    <div class="sbar"><i style="width:${f.readinessPct}%;background:${pctColor(f.readinessPct)}"></i></div>
    <div class="muted" style="font-size:11px;margin-top:3px">${fmt("asr.fwProven", { n: f.proven, m: f.measurable })}</div>
  </div>`;
  return `<div class="sect-h">${t("asr.fwTitle")}</div><div class="fw-grid">${fws.map(card).join("")}</div>`;
}

// Inline SVG sparkline of provenPct over the persisted snapshots.
function trendSpark(trend: { at: string; pct: number }[]): string {
  if (!trend || trend.length < 2) return "";
  const W = 280, H = 46, n = trend.length, max = 100;
  const pts = trend.map((p, i) => `${(i / (n - 1)) * W},${(H - (p.pct / max) * H).toFixed(1)}`).join(" ");
  const last = trend[n - 1].pct, delta = last - trend[0].pct;
  const dStr = delta === 0 ? "±0" : (delta > 0 ? "+" : "") + delta;
  return `<div class="sect-h">${t("asr.trendTitle")} <span class="muted" style="font-weight:400">· ${fmt("asr.trendDelta", { d: dStr, n })}</span></div>
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:46px;margin-bottom:14px">
      <polyline points="${pts}" fill="none" stroke="${pctColor(last)}" stroke-width="2" vector-effect="non-scaling-stroke"/>
    </svg>`;
}

// Drift = control objectives whose status changed vs the previous snapshot.
function driftBlock(drift: Drift[]): string {
  if (!drift || !drift.length) return `<div class="drift-ok">✓ ${t("asr.noDrift")}</div>`;
  const row = (d: Drift): string => `<div class="drift-row ${d.dir}">
    <span>${d.dir === "up" ? "▲" : "▼"}</span>
    <span class="nm">${esc(d.name)}</span>
    <span class="muted">${esc(statusLabel(d.from))} → ${esc(statusLabel(d.to))}</span>
    <span class="tag ${d.dir}">${d.dir === "up" ? t("asr.driftUp") : t("asr.driftDown")}</span>
  </div>`;
  return `<div class="sect-h">${t("asr.driftTitle")}</div>${drift.map(row).join("")}`;
}

async function load(): Promise<void> {
  let d: Assurance;
  try { const r = await fetch("/api/assurance"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("as-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("asr.loadFailed", { e: esc(e) })}</div>`; return; }
  const st = d.stats;
  const order: Record<string, number> = { proven: 0, partial: 1, gap: 2, attest: 3 };
  const controls = d.controls.slice().sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
  $("as-body").innerHTML = `
    <div class="as-hero">
      <span class="as-pct" style="color:${pctColor(st.provenPct)}">${st.provenPct}%</span>
      <div>
        <div class="as-bar"><i style="width:${st.provenPct}%;background:${pctColor(st.provenPct)}"></i></div>
        <div class="muted" style="font-size:12px;margin-top:4px">${t("asr.heroSub")}</div>
      </div>
    </div>
    <div class="tally" style="margin-bottom:16px">
      <span class="pill p-proven">${fmt("asr.tallyProven", { n: st.proven })}</span>
      <span class="pill p-partial">${fmt("asr.tallyPartial", { n: st.partial })}</span>
      <span class="pill p-gap">${fmt("asr.tallyGap", { n: st.gap })}</span>
      <span class="pill p-attest">${fmt("asr.tallyAttest", { n: st.attest })}</span>
    </div>
    ${fwRow(d.frameworks)}
    ${trendSpark(d.trend)}
    ${driftBlock(d.drift)}
    <div class="sect-h">${t("asr.controlsTitle")}</div>
    ${controls.map(ctlCard).join("")}
    <div class="muted" style="font-size:11px;margin-top:12px">${fmt("asr.evaluatedAt", { t: esc(d.evaluatedAt) })}</div>`;
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
