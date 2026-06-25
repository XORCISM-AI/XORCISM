/**
 * crocdigest.ts — "CROC standup": a daily digest of what changed and what to prioritise.
 *
 * Aggregates the highest-signal deltas across the platform (overdue/imminent regulatory deadlines,
 * ungoverned high-risk AI systems, open high/critical incidents, recent attack-surface drift, weak
 * Wi-Fi, exposure backlog) into one briefing with a headline, a prioritised action list and an
 * AI-style narrative (deterministic, offline-safe). Surfaced at /api/croc/digest and reusable by a
 * scheduled job. Read-only; best-effort per source so one missing DB never breaks the digest.
 */
import { getDb } from "./db";
import { regCalendar } from "./regobligations";
import { aiSystemDashboard } from "./aisystems";

interface Item { label: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; detail?: string }
interface Section { title: string; items: Item[] }

const safe = <T>(fn: () => T, dflt: T): T => { try { return fn(); } catch { return dflt; } };

export function generateDigest(tenant: number | null): any {
  const sections: Section[] = [];
  const priorities: { rank: number; action: string; why: string; severity: string }[] = [];
  let critical = 0, high = 0;
  const bump = (sev: string) => { if (sev === "Critical") critical++; else if (sev === "High") high++; };

  // ── Regulatory deadlines ──
  const reg = safe(() => regCalendar(tenant), null as any);
  if (reg) {
    const items: Item[] = [];
    const overdue = reg.obligations.filter((o: any) => o.effectiveStatus === "Overdue");
    const soon = reg.obligations.filter((o: any) => o.effectiveStatus === "Due soon");
    for (const o of overdue.slice(0, 5)) items.push({ label: `${o.regulation} ${o.reference} — ${o.title}`, severity: "High", detail: o.dueDate ? `due ${o.dueDate}` : "" });
    for (const o of soon.slice(0, 5)) items.push({ label: `${o.regulation} ${o.reference} — ${o.title}`, severity: "Medium", detail: o.daysUntil != null ? `in ${o.daysUntil}d` : "" });
    if (items.length) { sections.push({ title: "Regulatory deadlines", items }); items.forEach((i) => bump(i.severity)); }
    if (reg.summary.overdue) priorities.push({ rank: 0, action: `Close ${reg.summary.overdue} overdue regulatory obligation(s)`, why: "Past statutory deadline (DORA/NIS2/AI Act/CRA/GDPR)", severity: "High" });
    if (reg.summary.dueSoon) priorities.push({ rank: 0, action: `Prepare ${reg.summary.dueSoon} obligation(s) due within 30 days`, why: "Imminent regulatory deadline", severity: "Medium" });
  }

  // ── AI governance ──
  const ai = safe(() => aiSystemDashboard(tenant), null as any);
  if (ai) {
    const items: Item[] = ai.worklist.slice(0, 6).map((s: any) => ({ label: `${s.name} (${s.riskTier})`, severity: s.severity, detail: s.gaps[0] }));
    if (items.length) { sections.push({ title: "AI governance gaps", items }); items.forEach((i: Item) => bump(i.severity)); }
    if (ai.summary.highRisk && ai.summary.ungoverned) priorities.push({ rank: 0, action: `Govern ${Math.min(ai.summary.highRisk, ai.summary.ungoverned)} high-risk AI system(s)`, why: "EU AI Act high-risk without a governing framework/guardrails", severity: "High" });
  }

  // ── Open incidents ──
  const inc = safe(() => {
    const db = getDb("XINCIDENT");
    const cols = new Set((db.prepare('PRAGMA table_info("INCIDENT")').all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("Severity")) return [];
    const tw = cols.has("TenantID") && tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
    const args = cols.has("TenantID") && tenant != null ? [tenant] : [];
    return db.prepare(
      `SELECT IncidentName name, Severity sev, Status st FROM INCIDENT
       WHERE LOWER(COALESCE(Severity,'')) IN ('critical','high') AND LOWER(COALESCE(Status,'')) NOT IN ('closed','resolved','done') ${tw}
       ORDER BY CASE LOWER(Severity) WHEN 'critical' THEN 0 ELSE 1 END LIMIT 8`
    ).all(...args) as { name: string; sev: string; st: string }[];
  }, [] as { name: string; sev: string; st: string }[]);
  if (inc.length) {
    const items: Item[] = inc.map((i) => ({ label: i.name || "(incident)", severity: /crit/i.test(i.sev) ? "Critical" : "High", detail: i.st }));
    sections.push({ title: "Open high/critical incidents", items });
    items.forEach((i) => bump(i.severity));
    priorities.push({ rank: 0, action: `Drive ${inc.length} open high/critical incident(s) to closure`, why: "Active unresolved impact", severity: inc.some((i) => /crit/i.test(i.sev)) ? "Critical" : "High" });
  }

  // ── Attack-surface drift ──
  const drift = safe(() => {
    const xs = getDb("XORCISM");
    const has = xs.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='XSURFACESNAPSHOT'").get();
    if (!has) return null;
    const rows = xs.prepare("SELECT SnapshotJSON FROM XSURFACESNAPSHOT ORDER BY SnapshotID DESC LIMIT 1").all() as { SnapshotJSON: string }[];
    return rows.length ? 1 : null;
  }, null);
  if (drift) sections.push({ title: "Attack surface", items: [{ label: "Surface snapshots present — review /drift for added/removed exposures", severity: "Info" }] });

  // ── Exposure backlog (KEV-on-asset proxy) ──
  const exposures = safe(() => {
    const xs = getDb("XORCISM");
    const has = xs.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITY'").get();
    if (!has) return 0;
    const r = xs.prepare("SELECT COUNT(*) n FROM ASSETVULNERABILITY WHERE COALESCE(FalsePositive,0)=0 AND LOWER(COALESCE(Status,'')) NOT IN ('fixed','patched','resolved','closed')").get() as { n: number };
    return r.n;
  }, 0);
  if (exposures) priorities.push({ rank: 0, action: `Work the prioritised exposure backlog (${exposures} open finding(s))`, why: "Open asset↔vulnerability links", severity: exposures > 50 ? "High" : "Medium" });

  // rank priorities (Critical > High > Medium) and number them
  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  priorities.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);
  priorities.forEach((p, i) => { p.rank = i + 1; });

  const headline = critical
    ? `${critical} critical item(s) need attention today`
    : high
      ? `${high} high-priority item(s) on the board today`
      : priorities.length
        ? "Steady state — a few items to keep moving"
        : "All clear — no critical signals across the CROC";

  const narrative = buildNarrative(headline, sections, priorities);
  return { generatedAt: new Date().toISOString(), headline, narrative, criticalCount: critical, highCount: high, priorities, sections };
}

/** Deterministic, offline-safe narrative (no model dependency). */
function buildNarrative(headline: string, sections: Section[], priorities: any[]): string {
  const lines: string[] = [`**${headline}.**`];
  if (priorities.length) {
    lines.push("Today's priorities:");
    for (const p of priorities.slice(0, 5)) lines.push(`${p.rank}. ${p.action} — ${p.why}.`);
  }
  const reg = sections.find((s) => s.title === "Regulatory deadlines");
  if (reg?.items.length) lines.push(`On compliance, ${reg.items.length} regulatory item(s) are overdue or imminent — the soonest is "${reg.items[0].label}" (${reg.items[0].detail || "see calendar"}).`);
  const ai = sections.find((s) => s.title === "AI governance gaps");
  if (ai?.items.length) lines.push(`AI governance shows ${ai.items.length} system(s) with open gaps; "${ai.items[0].label}" is the most at-risk (${ai.items[0].detail || "review"}).`);
  const inc = sections.find((s) => s.title.includes("incidents"));
  if (inc?.items.length) lines.push(`${inc.items.length} high/critical incident(s) remain open and should be driven to closure.`);
  if (!sections.length) lines.push("No high-signal deltas were detected since the last review.");
  return lines.join("\n");
}
