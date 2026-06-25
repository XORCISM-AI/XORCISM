/**
 * siem.ts — SIEM-lite: log ingest → Sigma detection → ALERT → LOOPEVENT (/siem).
 *
 * Closes the detect→respond gap. Ingest log events (JSON), evaluate them against your Sigma rule
 * library (XTHREAT.SIGMARULE, reusing the sigma.ts parser/AST) plus a built-in baseline ruleset, and
 * raise XINCIDENT.ALERT for each match — which feeds incidents AND emits a LOOPEVENT so the
 * CROC loop / agentic orchestrator picks it up. Deterministic, in-process; no external SIEM needed.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { parseSigma, buildCond, attackTagsOf, type Cond } from "./sigma";
import { emitLoopEvent } from "./croc";

const now = (): string => new Date().toISOString();
const sevOf = (level: string): string => {
  const l = (level || "").toLowerCase();
  return l === "critical" ? "Critical" : l === "high" ? "High" : l === "medium" ? "Medium" : l === "low" ? "Low" : "Info";
};

export function ensureSiemTables(): void {
  getDb("XINCIDENT").exec(`
    CREATE TABLE IF NOT EXISTS SIEMEVENT (
      EventID INTEGER PRIMARY KEY, EventGUID TEXT, Source TEXT, Host TEXT, UserName TEXT,
      Raw TEXT, Matched INTEGER DEFAULT 0, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_siemevent_created ON SIEMEVENT(CreatedDate);
    CREATE INDEX IF NOT EXISTS ix_siemevent_tenant ON SIEMEVENT(TenantID);
  `);
}

// ── Built-in baseline ruleset (raw Sigma so it goes through the same parser) ──
const BUILTIN: string[] = [
  `title: Brute force - repeated failed logons\nlevel: high\ntags: [attack.t1110]\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel`,
  `title: Encoded PowerShell command\nlevel: high\ntags: [attack.t1059.001]\ndetection:\n  sel:\n    CommandLine|contains:\n      - ' -enc '\n      - ' -EncodedCommand'\n      - ' -ec '\n  condition: sel`,
  `title: Credential dumping (Mimikatz / LSASS)\nlevel: critical\ntags: [attack.t1003]\ndetection:\n  sel:\n    CommandLine|contains:\n      - 'sekurlsa'\n      - 'mimikatz'\n      - 'lsass.dmp'\n  condition: sel`,
  `title: Local account created / added to admins\nlevel: medium\ntags: [attack.t1136.001]\ndetection:\n  sel:\n    CommandLine|contains:\n      - 'net user /add'\n      - 'net localgroup administrators'\n  condition: sel`,
  `title: Suspicious recon utilities\nlevel: low\ntags: [attack.t1087]\ndetection:\n  sel:\n    CommandLine|contains:\n      - 'whoami /all'\n      - 'nltest /dclist'\n      - 'net group "domain admins"'\n  condition: sel`,
  `title: Ransomware shadow-copy deletion\nlevel: critical\ntags: [attack.t1490]\ndetection:\n  sel:\n    CommandLine|contains:\n      - 'vssadmin delete shadows'\n      - 'wbadmin delete catalog'\n      - 'bcdedit /set {default} recoveryenabled no'\n  condition: sel`,
];

interface Compiled { name: string; level: string; attack: string[]; cond: Cond }
let CACHE: { at: number; rules: Compiled[] } | null = null;

function compileRules(): Compiled[] {
  if (CACHE && Date.now() - CACHE.at < 60000) return CACHE.rules;
  const rules: Compiled[] = [];
  const add = (text: string): void => {
    try { const r = parseSigma(text); rules.push({ name: r.title || "Sigma rule", level: r.level || "medium", attack: attackTagsOf(r), cond: buildCond(r) }); } catch { /* skip bad rule */ }
  };
  for (const b of BUILTIN) add(b);
  try {
    const rows = getDb("XTHREAT").prepare("SELECT SigmaRuleName name, SigmaYaml yaml FROM SIGMARULE WHERE SigmaYaml IS NOT NULL AND SigmaYaml<>'' LIMIT 800").all() as { name: string; yaml: string }[];
    for (const r of rows) add(r.yaml);
  } catch { /* no sigma library */ }
  CACHE = { at: Date.now(), rules };
  return rules;
}

// ── event normalisation + Sigma evaluation ──
interface NEvent { fields: Record<string, string>; text: string; host: string; user: string; source: string; raw: any }
function normalize(e: any): NEvent {
  const fields: Record<string, string> = {};
  const parts: string[] = [];
  const walk = (o: any, prefix = ""): void => {
    if (o == null) return;
    if (typeof o !== "object") { parts.push(String(o)); if (prefix) fields[prefix.toLowerCase()] = String(o); return; }
    for (const [k, v] of Object.entries(o)) {
      if (v != null && typeof v === "object") walk(v, k);
      else { fields[k.toLowerCase()] = String(v ?? ""); parts.push(String(v ?? "")); }
    }
  };
  walk(e);
  return { fields, text: parts.join("  ").toLowerCase(), host: String(e.host ?? e.Computer ?? e.hostname ?? ""), user: String(e.user ?? e.User ?? e.TargetUserName ?? e.SubjectUserName ?? ""), source: String(e.source ?? e.Channel ?? "log"), raw: e };
}

const glob = (v: string): RegExp => new RegExp("^" + v.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");

function evalMatch(c: Extract<Cond, { op: "match" }>, ev: NEvent): boolean {
  const raw = ev.fields[c.field.toLowerCase()];
  const present = raw !== undefined && raw !== "";
  const test = (val: unknown): boolean => {
    if (val === null) return !present;
    if (!present) return false;
    const s = raw.toLowerCase(); const v = String(val).toLowerCase();
    if (c.mods.includes("contains")) return s.includes(v);
    if (c.mods.includes("startswith")) return s.startsWith(v);
    if (c.mods.includes("endswith")) return s.endsWith(v);
    if (c.mods.includes("re")) { try { return new RegExp(String(val), "i").test(raw); } catch { return false; } }
    if (c.mods.includes("gt")) return Number(raw) > Number(val);
    if (c.mods.includes("gte")) return Number(raw) >= Number(val);
    if (c.mods.includes("lt")) return Number(raw) < Number(val);
    if (c.mods.includes("lte")) return Number(raw) <= Number(val);
    if (v.includes("*") || v.includes("?")) return glob(v).test(raw);
    return s === v;
  };
  return c.mods.includes("all") ? c.values.every(test) : c.values.some(test);
}
function evalCond(c: Cond, ev: NEvent): boolean {
  switch (c.op) {
    case "true": return true;
    case "keyword": return c.values.some((v) => ev.text.includes(String(v).toLowerCase().replace(/^\*|\*$/g, "")));
    case "match": return evalMatch(c, ev);
    case "and": return c.items.every((i) => evalCond(i, ev));
    case "or": return c.items.some((i) => evalCond(i, ev));
    case "not": return !evalCond(c.item, ev);
  }
}

// ── ingest + detect ──
function raiseAlert(rule: Compiled, ev: NEvent, tenant: number | null): number | null {
  const xi = getDb("XINCIDENT");
  const cols = new Set((xi.prepare('PRAGMA table_info("ALERT")').all() as { name: string }[]).map((c) => c.name));
  const alertName = `${rule.name}${ev.host ? ` on ${ev.host}` : ""}`.slice(0, 300);
  const extId = `siem:${rule.name}:${ev.host}:${(ev.fields.commandline || ev.fields.eventid || ev.text).slice(0, 60)}`.slice(0, 200);
  // Idempotency by ExternalID where the column exists (db.ts adds it at boot), else by alert name.
  const dupe = (cols.has("ExternalID")
    ? xi.prepare("SELECT AlertID FROM ALERT WHERE DetectionSource='SIEM-lite' AND ExternalID=?").get(extId)
    : xi.prepare("SELECT AlertID FROM ALERT WHERE DetectionSource='SIEM-lite' AND AlertName=?").get(alertName)) as { AlertID: number } | undefined;
  if (dupe) return dupe.AlertID;
  const id = allocId(xi, "ALERT", "AlertID");
  const vals: Record<string, unknown> = {
    AlertID: id, AlertGUID: randomUUID(), AlertName: alertName,
    AlertDescription: `Sigma detection matched a log event${ev.user ? ` (user ${ev.user})` : ""}. Source: ${ev.source}.`,
    Severity: sevOf(rule.level), Status: "New", Category: "Detection", AttackTechniques: rule.attack.join(", ") || null,
    DetectionSource: "SIEM-lite", ServiceSource: "SIEM-lite", ExternalID: extId, CreatedDate: now(), TenantID: tenant,
  };
  const names = Object.keys(vals).filter((n) => cols.has(n));
  xi.prepare(`INSERT INTO ALERT (${names.join(",")}) VALUES (${names.map(() => "?").join(",")})`).run(...names.map((n) => vals[n]));
  // feed the loop → orchestrator
  try { emitLoopEvent({ type: "detection.sigma_match", source: "siem", summary: `${rule.name}${ev.host ? ` on ${ev.host}` : ""}`, severity: rule.level, tenant }); } catch { /* */ }
  return id;
}

export function ingestEvents(events: any[], tenant: number | null): { ingested: number; matched: number; alerts: { rule: string; severity: string; host: string; attack: string[] }[] } {
  ensureSiemTables();
  const rules = compileRules();
  const xi = getDb("XINCIDENT");
  const out = { ingested: 0, matched: 0, alerts: [] as { rule: string; severity: string; host: string; attack: string[] }[] };
  const seen = new Set<string>();
  const storeEv = xi.prepare("INSERT INTO SIEMEVENT (EventID, EventGUID, Source, Host, UserName, Raw, Matched, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)");
  const tx = xi.transaction(() => {
    let evId = allocId(xi, "SIEMEVENT", "EventID");
    for (const e of events.slice(0, 5000)) {
      const ev = normalize(e);
      let hit = false;
      for (const r of rules) {
        if (!evalCond(r.cond, ev)) continue;
        hit = true;
        const key = `${r.name}|${ev.host}|${(ev.fields.commandline || ev.fields.eventid || "").slice(0, 40)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        raiseAlert(r, ev, tenant);
        out.matched++;
        out.alerts.push({ rule: r.name, severity: sevOf(r.level), host: ev.host, attack: r.attack });
      }
      storeEv.run(evId++, randomUUID(), ev.source, ev.host, ev.user, JSON.stringify(ev.raw).slice(0, 4000), hit ? 1 : 0, now(), tenant);
      out.ingested++;
    }
  });
  tx();
  return out;
}

export function siemDashboard(tenant: number | null): any {
  ensureSiemTables();
  const xi = getDb("XINCIDENT");
  const tw = tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
  const args = tenant != null ? [tenant] : [];
  const events24 = (xi.prepare(`SELECT COUNT(*) n FROM SIEMEVENT WHERE CreatedDate >= datetime('now','-1 day') ${tw}`).get(...args) as { n: number })?.n ?? 0;
  const eventsTotal = (xi.prepare(`SELECT COUNT(*) n FROM SIEMEVENT WHERE 1=1 ${tw}`).get(...args) as { n: number })?.n ?? 0;
  const alerts = xi.prepare(
    `SELECT AlertID id, AlertName name, Severity severity, AttackTechniques attack, Status status, CreatedDate created
     FROM ALERT WHERE DetectionSource='SIEM-lite' ${tw} ORDER BY AlertID DESC LIMIT 50`
  ).all(...args) as any[];
  const bySev: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const a of alerts) bySev[a.severity] = (bySev[a.severity] || 0) + 1;
  const topRules = Object.values(xi.prepare(
    `SELECT AlertName name, COUNT(*) n FROM ALERT WHERE DetectionSource='SIEM-lite' ${tw} GROUP BY AlertName ORDER BY n DESC LIMIT 10`
  ).all(...args) as { name: string; n: number }[]);
  return {
    summary: { rulesLoaded: compileRules().length, builtinRules: BUILTIN.length, events24h: events24, eventsTotal, alerts: alerts.length, critical: bySev.Critical, high: bySev.High },
    bySev, alerts, topRules,
  };
}

/** A sample log batch (for the page's "Try sample" button). */
export const SAMPLE_LOGS = [
  { source: "Security", EventID: 4625, Computer: "ws-12", TargetUserName: "administrator", IpAddress: "203.0.113.9", message: "An account failed to log on (x14)" },
  { source: "Sysmon", EventID: 1, Computer: "ws-12", User: "alice", Image: "C:\\Windows\\System32\\powershell.exe", CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA..." },
  { source: "Sysmon", EventID: 1, Computer: "fs-01", User: "svc-backup", Image: "cmd.exe", CommandLine: "vssadmin delete shadows /all /quiet" },
  { source: "Sysmon", EventID: 1, Computer: "dc-01", User: "carol", Image: "net.exe", CommandLine: "net localgroup administrators evil /add" },
  { source: "Sysmon", EventID: 1, Computer: "ws-7", User: "bob", Image: "whoami.exe", CommandLine: "whoami /all" },
];
