/**
 * detectioneng.ts — Detection Engineering studio (the OrchiCyb "Detection Engineering" /
 * "Adaptive Cybersecurity Intelligence" module, implemented natively in XORCISM).
 *
 * From a single MITRE ATT&CK technique (optionally with an emulated-procedure context) it
 * generates production-ready detection logic across 12 platforms — Sigma, YARA, Microsoft
 * Sentinel (KQL), Splunk (SPL), Elastic (EQL), CrowdStrike Falcon LogScale (CQL), Microsoft
 * Defender XDR (KQL), Suricata, Snort, Falco, Sysmon and OSQuery. Generation is AI-first
 * (local Ollama, privacy-preserving) with a deterministic offline skeleton per platform, so it
 * always returns a usable starter rule even with no model. Generated rules can be saved into the
 * existing detection stores: Sigma → SIGMARULE, YARA → YARARULE, everything else → DETECTIONRULE.
 *
 * "Cyber Insights" turns the knowledge graph (ATT&CK + the detection stores + CTI) into contextual
 * observations: detection coverage, gaps, per-platform surface, and mitigation opportunities.
 *
 * Reuses ai.ts (ollamaChat/ollamaStatus) — the same pattern as purpleteam.suggestSigma.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";
import { ollamaChat, ollamaStatus, OLLAMA_MODEL } from "./ai";

export interface Platform { key: string; label: string; language: string; kind: string; store: "sigma" | "yara" | "detection"; ext: string }

/** The 12 detection platforms (OrchiCyb parity). `store` routes a saved rule to the right table. */
export const PLATFORMS: Platform[] = [
  { key: "sigma", label: "Sigma", language: "yaml", kind: "Generic SIEM", store: "sigma", ext: "yml" },
  { key: "yara", label: "YARA", language: "yara", kind: "File / memory", store: "yara", ext: "yar" },
  { key: "sentinel", label: "Microsoft Sentinel", language: "kql", kind: "SIEM", store: "detection", ext: "kql" },
  { key: "splunk", label: "Splunk", language: "spl", kind: "SIEM", store: "detection", ext: "spl" },
  { key: "elastic", label: "Elastic", language: "eql", kind: "SIEM", store: "detection", ext: "eql" },
  { key: "crowdstrike", label: "CrowdStrike Falcon LogScale", language: "cql", kind: "EDR", store: "detection", ext: "cql" },
  { key: "defender", label: "Microsoft Defender XDR", language: "kql", kind: "EDR / XDR", store: "detection", ext: "kql" },
  { key: "suricata", label: "Suricata", language: "suricata", kind: "Network IDS/IPS", store: "detection", ext: "rules" },
  { key: "snort", label: "Snort", language: "snort", kind: "Network IDS/IPS", store: "detection", ext: "rules" },
  { key: "falco", label: "Falco", language: "yaml", kind: "Runtime / container", store: "detection", ext: "yaml" },
  { key: "sysmon", label: "Sysmon", language: "xml", kind: "Host telemetry", store: "detection", ext: "xml" },
  { key: "osquery", label: "OSQuery", language: "sql", kind: "Host query", store: "detection", ext: "sql" },
];
const BY_KEY = new Map(PLATFORMS.map((p) => [p.key, p]));

export interface DetectContext { command?: string; executor?: string; platform?: string; telemetry?: string; description?: string }

/** Distinctive command tokens (binary + args), shell wrappers stripped (mirrors purpleteam.cmdTokens). */
function cmdTokens(command: string): string[] {
  const stripped = (command || "").replace(/^(cmd(\.exe)?\s+\/c\s+|powershell(\.exe)?\s+(-\w+\s+)*(-command\s+)?)/i, "").trim();
  return stripped.split(/\s+/).map((t) => t.replace(/['"]/g, "")).filter((t) => t.length >= 3 && !/^[-/]/.test(t)).slice(0, 4);
}
function domainsIn(text: string): string[] {
  const m = (text || "").match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) || [];
  return Array.from(new Set(m)).filter((d) => !/\.(exe|dll|ps1|bat|cmd|sys|txt|log)$/i.test(d)).slice(0, 3);
}
function esc(s: string): string { return (s || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!)); }

// ── per-platform deterministic offline skeletons ────────────────────────────────
// Each produces a usable STARTER rule for the technique; when a procedure command is supplied the
// selection is tuned to its concrete tokens, otherwise a CHANGE_ME placeholder marks what to fill.

function skSigma(id: string, name: string, ctx?: DetectContext): string {
  const toks = cmdTokens(ctx?.command || "");
  const isPs = /powershell|pwsh/i.test((ctx?.executor || "") + " " + (ctx?.command || ""));
  const logsource = isPs ? "  product: windows\n  category: ps_script" : "  category: process_creation\n  product: windows";
  const sel = toks.length
    ? `    CommandLine|contains|all:\n${toks.map((t) => `      - '${t}'`).join("\n")}`
    : `    Image|endswith: '\\CHANGE_ME.exe'   # TODO: concrete indicator for ${name}`;
  return `title: ${name} (${id})
id: ${randomUUID()}
status: experimental
description: Detects ${name} (${id}).
references:
  - https://attack.mitre.org/techniques/${id.replace(".", "/")}/
tags:
  - attack.${id.toLowerCase()}
logsource:
${logsource}
detection:
  selection:
${sel}
  condition: selection
falsepositives:
  - Legitimate administrative activity
level: medium`;
}

function skYara(id: string, name: string, ctx?: DetectContext): string {
  const toks = cmdTokens(ctx?.command || "");
  const strs = toks.length
    ? toks.map((t, i) => `        $s${i + 1} = "${t}" ascii wide nocase`).join("\n")
    : `        $s1 = "CHANGE_ME" ascii wide nocase   // TODO: concrete artifact for ${name}`;
  const rname = `Detect_${id.replace(/[.\-]/g, "_")}`;
  return `rule ${rname}
{
    meta:
        description = "Detects ${name} (${id})"
        author = "XORCISM Detection Engineering"
        reference = "https://attack.mitre.org/techniques/${id.replace(".", "/")}/"
        attack = "${id}"
    strings:
${strs}
    condition:
        any of them
}`;
}

function skSplunk(id: string, name: string, ctx?: DetectContext): string {
  const toks = cmdTokens(ctx?.command || "");
  const where = toks.length ? toks.map((t) => `Processes.process="*${t}*"`).join(" AND ") : `Processes.process="*CHANGE_ME*"`;
  return `\`\`\` ${name} (${id}) — Splunk SPL (Endpoint data model / Sysmon) \`\`\`
| tstats count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where ${where}
    by Processes.dest Processes.user Processes.process Processes.parent_process
| \`drop_dm_object_name(Processes)\`
| \`security_content_ctime(firstTime)\`
| \`security_content_ctime(lastTime)\``;
}

function skKql(id: string, name: string, ctx: DetectContext | undefined, table: string): string {
  const toks = cmdTokens(ctx?.command || "");
  const filt = toks.length
    ? toks.map((t) => `ProcessCommandLine has "${t}"`).join("\n    and ")
    : `ProcessCommandLine has "CHANGE_ME"   // TODO: concrete indicator for ${name}`;
  return `// ${name} (${id})
${table}
| where Timestamp > ago(1d)
| where ${filt}
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc`;
}

function skElastic(id: string, name: string, ctx?: DetectContext): string {
  const toks = cmdTokens(ctx?.command || "");
  const filt = toks.length ? toks.map((t) => `process.command_line : "*${t}*"`).join(" and ") : `process.command_line : "*CHANGE_ME*"`;
  return `/* ${name} (${id}) — Elastic EQL */
process where event.type == "start" and
  (${filt})`;
}

function skCql(id: string, name: string, ctx?: DetectContext): string {
  const toks = cmdTokens(ctx?.command || "");
  const filt = toks.length ? toks.map((t) => `CommandLine=/${t}/i`).join(" ") : `CommandLine=/CHANGE_ME/i`;
  return `// ${name} (${id}) — CrowdStrike Falcon LogScale (CQL)
#event_simpleName=ProcessRollup2
| ${filt}
| groupBy([ComputerName, UserName, FileName, CommandLine], function=count())`;
}

function skSuricata(id: string, name: string, ctx?: DetectContext): string {
  const doms = domainsIn((ctx?.command || "") + " " + (ctx?.telemetry || ""));
  if (doms.length) {
    return `alert dns any any -> any any (msg:"XORCISM ${name} ${id} suspicious domain ${doms[0]}"; dns.query; content:"${doms[0]}"; nocase; classtype:trojan-activity; reference:url,attack.mitre.org/techniques/${id.replace(".", "/")}/; sid:9${(parseInt(id.replace(/\D/g, "").slice(0, 6) || "100000", 10) % 900000) + 100000}; rev:1;)`;
  }
  return `alert http any any -> any any (msg:"XORCISM ${name} ${id} — TODO tune indicator"; flow:established,to_server; http.uri; content:"CHANGE_ME"; nocase; classtype:trojan-activity; reference:url,attack.mitre.org/techniques/${id.replace(".", "/")}/; sid:9${(parseInt(id.replace(/\D/g, "").slice(0, 6) || "100001", 10) % 900000) + 100000}; rev:1;)`;
}

function skSnort(id: string, name: string, ctx?: DetectContext): string {
  const doms = domainsIn((ctx?.command || "") + " " + (ctx?.telemetry || ""));
  const ind = doms[0] || "CHANGE_ME";
  return `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"XORCISM ${name} ${id} ${ind}"; flow:established,to_server; content:"${ind}"; nocase; classtype:trojan-activity; reference:url,attack.mitre.org/techniques/${id.replace(".", "/")}/; sid:9${(parseInt(id.replace(/\D/g, "").slice(0, 6) || "100002", 10) % 900000) + 100000}; rev:1;)`;
}

function skFalco(id: string, name: string, ctx?: DetectContext): string {
  const toks = cmdTokens(ctx?.command || "");
  const cond = toks.length ? toks.map((t) => `proc.cmdline contains "${t}"`).join(" and ") : `proc.name = "CHANGE_ME"`;
  return `- rule: ${name} (${id})
  desc: Detects ${name} (${id}) at container/host runtime.
  condition: spawned_process and (${cond})
  output: "${name} detected (command=%proc.cmdline user=%user.name container=%container.id ${id})"
  priority: WARNING
  tags: [attack.${id.toLowerCase()}, mitre]`;
}

function skSysmon(id: string, name: string, ctx?: DetectContext): string {
  const toks = cmdTokens(ctx?.command || "");
  const cond = toks.length
    ? toks.map((t) => `        <CommandLine condition="contains">${esc(t)}</CommandLine>`).join("\n")
    : `        <CommandLine condition="contains">CHANGE_ME</CommandLine> <!-- TODO: ${esc(name)} -->`;
  return `<!-- ${esc(name)} (${id}) — Sysmon config snippet (merge into ProcessCreate) -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="${id} ${esc(name)}" groupRelation="or">
      <ProcessCreate onmatch="include">
${cond}
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>`;
}

function skOsquery(id: string, name: string, ctx?: DetectContext): string {
  const toks = cmdTokens(ctx?.command || "");
  const where = toks.length ? toks.map((t) => `cmdline LIKE '%${t}%'`).join(" AND ") : `cmdline LIKE '%CHANGE_ME%'`;
  return `-- ${name} (${id}) — OSQuery (schedule in an ATT&CK pack)
SELECT p.pid, p.name, p.path, p.cmdline, u.username, p.parent
FROM processes p
LEFT JOIN users u ON p.uid = u.uid
WHERE ${where};`;
}

function offlineSkeleton(key: string, id: string, name: string, ctx?: DetectContext): string {
  switch (key) {
    case "sigma": return skSigma(id, name, ctx);
    case "yara": return skYara(id, name, ctx);
    case "splunk": return skSplunk(id, name, ctx);
    case "sentinel": return skKql(id, name, ctx, "DeviceProcessEvents");
    case "defender": return skKql(id, name, ctx, "DeviceProcessEvents");
    case "elastic": return skElastic(id, name, ctx);
    case "crowdstrike": return skCql(id, name, ctx);
    case "suricata": return skSuricata(id, name, ctx);
    case "snort": return skSnort(id, name, ctx);
    case "falco": return skFalco(id, name, ctx);
    case "sysmon": return skSysmon(id, name, ctx);
    case "osquery": return skOsquery(id, name, ctx);
    default: return `# No generator for ${key}`;
  }
}

// System prompt fragments so the AI returns ONLY the rule body for each platform.
const AI_SYS: Record<string, string> = {
  sigma: "Output ONLY a valid Sigma rule in YAML (title, id uuid, status: experimental, description, attack.<techid> tag, realistic logsource, detection selection with concrete indicators, condition, falsepositives, level). No prose, no code fences.",
  yara: "Output ONLY a valid YARA rule (rule name, meta with description/reference/attack, strings with concrete artifacts, condition). No prose, no code fences.",
  sentinel: "Output ONLY a Microsoft Sentinel KQL analytics query over the Microsoft 365 Defender / Sentinel schema (e.g. DeviceProcessEvents, SecurityEvent). Concrete filters, project useful columns. No prose, no code fences.",
  splunk: "Output ONLY a Splunk SPL search (prefer the Endpoint data model / tstats or Sysmon sourcetype). Concrete filters. No prose, no code fences.",
  elastic: "Output ONLY an Elastic EQL query (event categories like process/network). Concrete filters. No prose, no code fences.",
  crowdstrike: "Output ONLY a CrowdStrike Falcon LogScale (CQL) query over #event_simpleName events. Concrete filters and a groupBy. No prose, no code fences.",
  defender: "Output ONLY a Microsoft Defender XDR advanced-hunting KQL query (DeviceProcessEvents/DeviceNetworkEvents/DeviceFileEvents). Concrete filters, project columns. No prose, no code fences.",
  suricata: "Output ONLY a single valid Suricata rule line (alert ...; with msg, matching keywords, classtype, reference url to attack.mitre.org, a unique sid >= 9100000, rev:1). No prose, no code fences.",
  snort: "Output ONLY a single valid Snort rule line (alert ...; with msg, content, classtype, reference, unique sid >= 9100000, rev:1). No prose, no code fences.",
  falco: "Output ONLY a Falco rule in YAML (- rule/desc/condition/output/priority/tags with attack.<techid>). No prose, no code fences.",
  sysmon: "Output ONLY a Sysmon config XML snippet (a RuleGroup with a ProcessCreate/NetworkConnect include filter) that can be merged into a Sysmon configuration. No prose, no code fences.",
  osquery: "Output ONLY an OSQuery SQL statement selecting from the appropriate table(s) with a concrete WHERE clause. No prose, no code fences.",
};

function stripFences(s: string): string {
  return (s || "").replace(/^```[a-z0-9]*\s*/i, "").replace(/```\s*$/m, "").trim();
}

export interface GenResult { platform: string; label: string; language: string; kind: string; rule: string; offline: boolean; model: string }

/** Generate detection logic for a technique across the requested platforms (AI-first, offline fallback). */
export async function generateDetections(
  techId: string, techName: string, platformKeys: string[], ctx?: DetectContext, useAi = true,
): Promise<{ techId: string; techName: string; results: GenResult[]; aiReachable: boolean }> {
  const keys = (platformKeys && platformKeys.length ? platformKeys : PLATFORMS.map((p) => p.key)).filter((k) => BY_KEY.has(k));
  const status = useAi ? await ollamaStatus() : { reachable: false } as { reachable: boolean };
  const ctxLine = ctx && (ctx.command || ctx.telemetry)
    ? `\n\nEmulated procedure to tune the rule to (detect THIS, not a generic variant):`
      + (ctx.executor ? `\n- executor: ${ctx.executor}` : "")
      + (ctx.command ? `\n- command: ${ctx.command.slice(0, 300)}` : "")
      + (ctx.platform ? `\n- platform: ${ctx.platform}` : "")
      + (ctx.telemetry ? `\n- observed telemetry: ${ctx.telemetry.slice(0, 200)}` : "")
    : "";
  const results: GenResult[] = [];
  for (const key of keys) {
    const p = BY_KEY.get(key)!;
    const skel = offlineSkeleton(key, techId, techName, ctx);
    let rule = skel; let offline = true; let model = status.reachable ? "fallback" : "offline";
    if (status.reachable) {
      try {
        const sys = `You are a senior detection engineer. ${AI_SYS[key]}`;
        const user = `MITRE ATT&CK technique: ${techId} — ${techName}. Write a ${p.label} detection for it.${ctxLine}`;
        const out = stripFences(await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user }], 0.2));
        if (out && out.length > 15) { rule = out; offline = false; model = OLLAMA_MODEL; }
      } catch { /* keep skeleton */ }
    }
    results.push({ platform: key, label: p.label, language: p.language, kind: p.kind, rule, offline, model });
  }
  return { techId, techName, results, aiReachable: status.reachable };
}

// ── persistence ────────────────────────────────────────────────────────────────
function nowTs(): string { return new Date().toISOString().replace("T", " ").slice(0, 19); }

export interface SaveInput { platform: string; techId: string; techName: string; rule: string; description?: string; level?: string; author?: string }

/** Persist a generated rule into the right store (Sigma→SIGMARULE, YARA→YARARULE, else DETECTIONRULE). */
export function saveDetection(inp: SaveInput): { store: string; id: number } {
  const p = BY_KEY.get(inp.platform);
  if (!p) throw new Error("unknown platform");
  const db = getDb("XTHREAT");
  const ref = /^T\d{4}(\.\d{3})?$/i.test(inp.techId) ? `https://attack.mitre.org/techniques/${inp.techId.replace(".", "/")}/` : null;
  const attackTag = /^T\d{4}(\.\d{3})?$/i.test(inp.techId) ? inp.techId.toUpperCase() : "";
  const name = `${inp.techName} (${inp.techId}) — ${p.label}`.slice(0, 300);
  const desc = (inp.description || `Auto-generated ${p.label} detection for ${inp.techName} (${inp.techId}).`).slice(0, 2000);
  const author = (inp.author || "XORCISM Detection Engineering").slice(0, 120);
  if (p.store === "sigma") {
    const r = db.prepare(
      `INSERT INTO SIGMARULE (SigmaRuleGUID, SigmaRuleName, SigmaRuleDescription, SigmaYaml, Level, Status, Author, SigmaReference, AttackTags, CreatedDate)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
    ).run(randomUUID(), name, desc, inp.rule, inp.level || "medium", "experimental", author, ref, attackTag, nowTs());
    return { store: "SIGMARULE", id: Number(r.lastInsertRowid) };
  }
  if (p.store === "yara") {
    const r = db.prepare(
      `INSERT INTO YARARULE (YaraRuleGUID, YaraRuleName, YaraRuleDescription, YaraSource, Author, YaraReference, AttackTags, Status, CreatedDate)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    ).run(randomUUID(), name, desc, inp.rule, author, ref, attackTag, "experimental", nowTs());
    return { store: "YARARULE", id: Number(r.lastInsertRowid) };
  }
  const r = db.prepare(
    `INSERT INTO DETECTIONRULE (DetectionRuleGUID, Name, Description, Platform, Language, RuleText, AttackTags, Level, Status, Author, Source, Reference, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(randomUUID(), name, desc, p.label, p.language, inp.rule, attackTag, inp.level || "medium", "experimental", author, "Detection Engineering", ref, nowTs());
  return { store: "DETECTIONRULE", id: Number(r.lastInsertRowid) };
}

// ── Cyber Insights (auto-observations over the knowledge graph) ──────────────────
const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const TCODE = /T\d{4}(?:\.\d{3})?/gi;
function tagsToIds(rows: { AttackTags: string | null }[]): Set<string> {
  const s = new Set<string>();
  for (const r of rows) for (const m of (r.AttackTags || "").match(TCODE) || []) s.add(m.toUpperCase());
  return s;
}

export interface Insight { kind: string; severity: "info" | "low" | "medium" | "high"; title: string; detail: string; count?: number }
export interface InsightsResult {
  summary: { techniques: number; covered: number; coveragePct: number; sigma: number; yara: number; detection: number; platforms: number };
  byPlatform: { platform: string; count: number }[];
  topGaps: { attackId: string; name: string }[];
  insights: Insight[];
}

/** Analyse ATT&CK + the detection stores + CTI into contextual observations (OrchiCyb "Cyber Insights"). */
export function cyberInsights(): InsightsResult {
  const xt = getDb("XTHREAT"); // ATT&CK techniques + all detection stores live in XTHREAT
  const sigmaRows = has(xt, "SIGMARULE") ? xt.prepare("SELECT AttackTags FROM SIGMARULE").all() as { AttackTags: string | null }[] : [];
  const yaraRows = has(xt, "YARARULE") ? xt.prepare("SELECT AttackTags FROM YARARULE").all() as { AttackTags: string | null }[] : [];
  const detRows = has(xt, "DETECTIONRULE") ? xt.prepare("SELECT AttackTags FROM DETECTIONRULE").all() as { AttackTags: string | null }[] : [];
  const covered = new Set<string>([...tagsToIds(sigmaRows), ...tagsToIds(yaraRows), ...tagsToIds(detRows)]);
  // normalise sub-techniques to their parent for coverage against base techniques too
  for (const id of Array.from(covered)) if (id.includes(".")) covered.add(id.split(".")[0]);

  const techniques = has(xt, "ATTACKTECHNIQUE")
    ? (xt.prepare("SELECT AttackID AS id, Name AS name FROM ATTACKTECHNIQUE WHERE AttackID LIKE 'T%' AND COALESCE(Deprecated,0)=0").all() as { id: string; name: string }[])
    : [];
  const total = techniques.length;
  const coveredTechniques = techniques.filter((t) => covered.has(t.id.toUpperCase()));
  const coveragePct = total ? Math.round((coveredTechniques.length / total) * 100) : 0;

  // per-platform detection surface
  const byPlatform: { platform: string; count: number }[] = [];
  const nSigma = sigmaRows.length, nYara = yaraRows.length;
  if (nSigma) byPlatform.push({ platform: "Sigma", count: nSigma });
  if (nYara) byPlatform.push({ platform: "YARA", count: nYara });
  if (has(xt, "DETECTIONRULE")) {
    for (const r of xt.prepare("SELECT Platform AS p, COUNT(*) AS c FROM DETECTIONRULE GROUP BY Platform ORDER BY c DESC").all() as { p: string; c: number }[]) {
      byPlatform.push({ platform: r.p || "?", count: r.c });
    }
  }

  // top coverage gaps — prefer techniques referenced by CTI/threat activity, else any uncovered
  const referenced = new Set<string>();
  for (const tbl of ["THREATREPORT", "INTELEXCHANGE", "HUNT", "HYPOTHESIS"]) {
    if (has(xt, tbl)) {
      try {
        for (const r of xt.prepare(`SELECT AttackTags FROM ${tbl}`).all() as { AttackTags: string | null }[])
          for (const m of (r.AttackTags || "").match(TCODE) || []) referenced.add(m.toUpperCase());
      } catch { /* table without AttackTags */ }
    }
  }
  const byId = new Map(techniques.map((t) => [t.id.toUpperCase(), t.name] as const));
  const refGaps = Array.from(referenced).filter((id) => !covered.has(id) && byId.has(id));
  const gapPool = refGaps.length ? refGaps : techniques.filter((t) => !covered.has(t.id.toUpperCase())).map((t) => t.id.toUpperCase());
  const topGaps = gapPool.slice(0, 12).map((id) => ({ attackId: id, name: byId.get(id) || id }));

  // mitigation opportunity: techniques with a mapped ATT&CK mitigation
  const nMit = has(xt, "ATTACKMITIGATION") ? (xt.prepare("SELECT COUNT(*) AS c FROM ATTACKMITIGATION").get() as { c: number }).c : 0;

  const insights: Insight[] = [];
  if (total) {
    const gapN = total - coveredTechniques.length;
    insights.push({
      kind: "coverage", severity: coveragePct < 25 ? "high" : coveragePct < 60 ? "medium" : "low",
      title: `Detection coverage ${coveragePct}% of ATT&CK techniques`,
      detail: `${coveredTechniques.length}/${total} techniques have ≥1 detection rule (Sigma, YARA or a platform rule). ${gapN} remain uncovered — generate detections for them from this studio.`,
      count: gapN,
    });
  }
  if (refGaps.length) {
    insights.push({
      kind: "priority-gap", severity: "high",
      title: `${refGaps.length} techniques seen in your CTI have no detection`,
      detail: `These techniques appear in your threat reports / intel / hunts but have no rule yet — the highest-value gaps to close first: ${refGaps.slice(0, 6).map((id) => `${id} (${byId.get(id) || "?"})`).join(", ")}.`,
      count: refGaps.length,
    });
  }
  if (byPlatform.length) {
    const dominant = byPlatform[0];
    const thin = PLATFORMS.filter((p) => !byPlatform.some((b) => b.platform === p.label)).map((p) => p.label);
    insights.push({
      kind: "surface", severity: thin.length > 6 ? "medium" : "low",
      title: `Detection surface skewed toward ${dominant.platform}`,
      detail: `Most rules target ${dominant.platform} (${dominant.count}). Platforms with no saved rules yet: ${thin.slice(0, 8).join(", ") || "none"}. Diversify to catch the same technique across telemetry sources.`,
      count: thin.length,
    });
  }
  if (nMit) {
    insights.push({
      kind: "mitigation", severity: "info",
      title: `${nMit} ATT&CK mitigations available to pair with detections`,
      detail: "For every detection you deploy, map the corresponding ATT&CK mitigation so alerts come with a remediation. See /threat-informed-defense for the detect+mitigate worklist.",
      count: nMit,
    });
  }
  if (!insights.length) {
    insights.push({ kind: "empty", severity: "info", title: "No detection data yet", detail: "Import MITRE ATT&CK and generate/save some detections to unlock coverage insights.", count: 0 });
  }

  return {
    summary: { techniques: total, covered: coveredTechniques.length, coveragePct, sigma: nSigma, yara: nYara, detection: detRows.length, platforms: byPlatform.length },
    byPlatform, topGaps, insights,
  };
}
