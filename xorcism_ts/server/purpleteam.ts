/**
 * purpleteam.ts — Purple-team detection-coverage loop.
 *
 * Closes the loop between offense and defense: take an attack-chain run, map each tool
 * to the MITRE ATT&CK technique it exercises, then check the **Sigma rule library**
 * (XTHREAT.SIGMARULE, the detection inventory) for a rule that covers it. Techniques
 * with ≥1 rule are "detected"; the rest are gaps. For a gap, draft the missing Sigma
 * rule with the local AI (deterministic skeleton fallback). The ATT&CK coverage you
 * see is therefore evidence-based — backed by real detection content, not "we own a tool".
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";
import { getRun, getRunSteps } from "./chain";
import { ollamaChat, ollamaStatus, OLLAMA_MODEL } from "./ai";

interface Tech { id: string; name: string }
// Connector → the ATT&CK technique(s) it exercises (base techniques for coverage matching).
const CONNECTOR_ATTACK: Record<string, Tech[]> = {
  nmap: [{ id: "T1046", name: "Network Service Discovery" }],
  masscan: [{ id: "T1046", name: "Network Service Discovery" }], rustscan: [{ id: "T1046", name: "Network Service Discovery" }],
  naabu: [{ id: "T1046", name: "Network Service Discovery" }], netdiscover: [{ id: "T1046", name: "Network Service Discovery" }], zmap: [{ id: "T1046", name: "Network Service Discovery" }],
  subfinder: [{ id: "T1590", name: "Gather Victim Network Information" }], amass: [{ id: "T1590", name: "Gather Victim Network Information" }], sublist3r: [{ id: "T1590", name: "Gather Victim Network Information" }],
  theharvester: [{ id: "T1589", name: "Gather Victim Identity Information" }, { id: "T1590", name: "Gather Victim Network Information" }],
  spiderfoot: [{ id: "T1589", name: "Gather Victim Identity Information" }],
  shodan: [{ id: "T1596", name: "Search Open Technical Databases" }], censys: [{ id: "T1596", name: "Search Open Technical Databases" }], fofa: [{ id: "T1596", name: "Search Open Technical Databases" }], netlas: [{ id: "T1596", name: "Search Open Technical Databases" }],
  "have-i-been-pwned": [{ id: "T1589", name: "Gather Victim Identity Information" }], holehe: [{ id: "T1589", name: "Gather Victim Identity Information" }], dehashed: [{ id: "T1589", name: "Gather Victim Identity Information" }], "hudson-rock": [{ id: "T1589", name: "Gather Victim Identity Information" }],
  httpx: [{ id: "T1595", name: "Active Scanning" }],
  whatweb: [{ id: "T1592", name: "Gather Victim Host Information" }], wappalyzer: [{ id: "T1592", name: "Gather Victim Host Information" }],
  nikto: [{ id: "T1595", name: "Active Scanning" }, { id: "T1190", name: "Exploit Public-Facing Application" }],
  nuclei: [{ id: "T1595", name: "Active Scanning" }, { id: "T1190", name: "Exploit Public-Facing Application" }],
  wapiti: [{ id: "T1190", name: "Exploit Public-Facing Application" }], w3af: [{ id: "T1190", name: "Exploit Public-Facing Application" }], arachni: [{ id: "T1190", name: "Exploit Public-Facing Application" }],
  wpscan: [{ id: "T1190", name: "Exploit Public-Facing Application" }], wpprobe: [{ id: "T1190", name: "Exploit Public-Facing Application" }], joomscan: [{ id: "T1190", name: "Exploit Public-Facing Application" }],
  sqlmap: [{ id: "T1190", name: "Exploit Public-Facing Application" }], dalfox: [{ id: "T1190", name: "Exploit Public-Facing Application" }], xsstrike: [{ id: "T1190", name: "Exploit Public-Facing Application" }], commix: [{ id: "T1190", name: "Exploit Public-Facing Application" }],
  gobuster: [{ id: "T1595", name: "Active Scanning" }], feroxbuster: [{ id: "T1595", name: "Active Scanning" }], ffuf: [{ id: "T1595", name: "Active Scanning" }], katana: [{ id: "T1595", name: "Active Scanning" }],
  "metasploit-scan": [{ id: "T1046", name: "Network Service Discovery" }],
  metasploit: [{ id: "T1210", name: "Exploitation of Remote Services" }, { id: "T1190", name: "Exploit Public-Facing Application" }],
  crackmapexec: [{ id: "T1110", name: "Brute Force" }, { id: "T1021", name: "Remote Services" }], netexec: [{ id: "T1110", name: "Brute Force" }, { id: "T1021", name: "Remote Services" }],
  kerbrute: [{ id: "T1110", name: "Brute Force" }], medusa: [{ id: "T1110", name: "Brute Force" }], "thc-hydra": [{ id: "T1110", name: "Brute Force" }], ncrack: [{ id: "T1110", name: "Brute Force" }],
  responder: [{ id: "T1557", name: "Adversary-in-the-Middle" }],
  impacket: [{ id: "T1021", name: "Remote Services" }, { id: "T1569", name: "System Services" }], "evil-winrm": [{ id: "T1021", name: "Remote Services" }],
  mimikatz: [{ id: "T1003", name: "OS Credential Dumping" }], lazagne: [{ id: "T1003", name: "OS Credential Dumping" }],
  bloodhound: [{ id: "T1482", name: "Domain Trust Discovery" }, { id: "T1087", name: "Account Discovery" }], sharphound: [{ id: "T1087", name: "Account Discovery" }],
  sslyze: [{ id: "T1595", name: "Active Scanning" }], "testssl-sh": [{ id: "T1595", name: "Active Scanning" }],
};

export interface CoverageTech { id: string; name: string; connectors: string[]; rules: number; sampleRules: string[]; covered: boolean }
export interface ChainCoverage {
  run: { ChainRunID: number; PlaybookName: string; SeedTarget: string } | null;
  techniques: CoverageTech[];
  stats: { total: number; covered: number; gaps: number; coveragePct: number };
}

/** ATT&CK detection-coverage of a chain run, against the Sigma rule library. */
export function chainCoverage(runId: number): ChainCoverage {
  const run = getRun(runId);
  if (!run) return { run: null, techniques: [], stats: { total: 0, covered: 0, gaps: 0, coveragePct: 0 } };
  const steps = getRunSteps(runId);
  const connectors = [...new Set(steps.map((s) => s.Connector))];
  // technique → connectors that exercised it
  const techMap = new Map<string, { name: string; connectors: Set<string> }>();
  for (const c of connectors) for (const t of CONNECTOR_ATTACK[c] || []) {
    const e = techMap.get(t.id) ?? techMap.set(t.id, { name: t.name, connectors: new Set() }).get(t.id)!;
    e.connectors.add(c);
  }
  const xt = getDb("XTHREAT");
  const techniques: CoverageTech[] = [...techMap.entries()].map(([id, e]) => {
    let rules = 0; let sampleRules: string[] = [];
    try {
      rules = (xt.prepare("SELECT COUNT(*) n FROM SIGMARULE WHERE UPPER(AttackTags) LIKE ?").get(`%${id}%`) as { n: number }).n;
      sampleRules = (xt.prepare("SELECT SigmaRuleName FROM SIGMARULE WHERE UPPER(AttackTags) LIKE ? AND SigmaRuleName IS NOT NULL ORDER BY SigmaRuleID LIMIT 3").all(`%${id}%`) as { SigmaRuleName: string }[]).map((r) => r.SigmaRuleName);
    } catch { /* SIGMARULE absent */ }
    return { id, name: e.name, connectors: [...e.connectors], rules, sampleRules, covered: rules > 0 };
  }).sort((a, b) => Number(a.covered) - Number(b.covered) || a.id.localeCompare(b.id)); // gaps first
  const covered = techniques.filter((t) => t.covered).length;
  const total = techniques.length;
  return { run: { ChainRunID: run.ChainRunID, PlaybookName: run.PlaybookName, SeedTarget: run.SeedTarget }, techniques, stats: { total, covered, gaps: total - covered, coveragePct: total ? Math.round((covered / total) * 100) : 0 } };
}

/** The emulated procedure + observed telemetry, so a drafted rule is tuned to what the test
 *  actually did on the endpoint (rather than a generic technique guess). */
export interface SigmaContext { command?: string; executor?: string; platform?: string; outcome?: string; detectedBy?: string; telemetry?: string }

/** Distinctive command tokens (binary + args), with shell wrappers stripped. */
function cmdTokens(command: string): string[] {
  const stripped = command.replace(/^(cmd(\.exe)?\s+\/c\s+|powershell(\.exe)?\s+(-\w+\s+)*(-command\s+)?)/i, "").trim();
  return stripped.split(/\s+/).map((t) => t.replace(/['"]/g, "")).filter((t) => t.length >= 3 && !/^[-/]/.test(t)).slice(0, 3);
}

function skeletonSigma(id: string, name: string, ctx?: SigmaContext): string {
  const attackTag = `attack.${id.toLowerCase()}`;
  const tpath = id.replace(/\./, "/");
  const cmd = (ctx?.command || "").replace(/^#.*$/m, "").trim();
  const toks = cmd ? cmdTokens(cmd) : [];
  const isPs = /powershell|pwsh/i.test((ctx?.executor || "") + " " + cmd);
  const logsource = isPs ? "  product: windows\n  category: ps_script" : "  category: process_creation\n  product: windows";
  const selection = toks.length
    ? `    CommandLine|contains|all:\n${toks.map((t) => `      - '${t}'`).join("\n")}`
    : `    # TODO: define concrete indicators for ${name}\n    CommandLine|contains:\n      - 'CHANGE_ME'`;
  const desc = cmd
    ? `Detects the emulated procedure for ${name} (${id}): ${cmd.slice(0, 90)}`
    : `Auto-generated starter rule to detect ${name}. Tune the selection and log source to your environment.`;
  return `title: Detection for ${name} (${id})
id: ${randomUUID()}
status: experimental
description: ${desc}
references:
  - https://attack.mitre.org/techniques/${tpath}/
tags:
  - ${attackTag}
logsource:
${logsource}
detection:
  selection:
${selection}
  condition: selection
falsepositives:
  - Legitimate administrative activity
level: medium`;
}

/** Draft a Sigma rule for an uncovered technique. AI when available, skeleton otherwise. When a
 *  `ctx` (emulated procedure + telemetry) is given, the rule is tuned to detect THAT procedure. */
export async function suggestSigma(techId: string, techName: string, ctx?: SigmaContext): Promise<{ yaml: string; model: string; offline: boolean; tuned: boolean }> {
  const tuned = !!(ctx && (ctx.command || ctx.telemetry));
  const skel = skeletonSigma(techId, techName, ctx);
  const status = await ollamaStatus();
  if (status.reachable) {
    const sys = "You are a detection engineer. Output ONLY a valid Sigma rule in YAML (no prose, no code fences) that detects the given MITRE ATT&CK technique. Include title, id (a uuid), status: experimental, description, the attack.<techid> tag, a realistic logsource, a detection selection with concrete indicators, condition, falsepositives, and level. When an emulated procedure is given, base the selection on its concrete artifacts (the exact process/command-line/registry/event), not a generic variant.";
    const ctxLine = tuned
      ? `\n\nIt was emulated on this endpoint with the EXACT procedure below — tune the selection to detect THIS, not a generic variant:`
        + (ctx!.executor ? `\n- executor: ${ctx!.executor}` : "")
        + (ctx!.command ? `\n- command: ${ctx!.command.slice(0, 300)}` : "")
        + (ctx!.platform ? `\n- platform: ${ctx!.platform}` : "")
        + (ctx!.outcome ? `\n- last emulation outcome: ${ctx!.outcome}${ctx!.detectedBy ? ` (via ${ctx!.detectedBy})` : ""}` : "")
        + (ctx!.telemetry ? `\n- observed telemetry: ${ctx!.telemetry.slice(0, 200)}` : "")
      : "";
    const user = `Technique: ${techId} — ${techName}. Write a Sigma rule to detect it.${ctxLine}`;
    try {
      let yaml = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user }], 0.2);
      yaml = yaml.replace(/^```ya?ml?\s*/i, "").replace(/```$/m, "").trim();
      if (/^title:/im.test(yaml)) return { yaml, model: OLLAMA_MODEL, offline: false, tuned };
    } catch { /* fall back to skeleton */ }
  }
  return { yaml: skel, model: status.reachable ? "fallback" : "offline", offline: true, tuned };
}
