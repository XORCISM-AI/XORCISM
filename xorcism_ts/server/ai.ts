/**
 * ai.ts — Integration of a local LLM (Ollama) with lightweight RAG over XORCISM data.
 *
 * Config (environment variables, never entered in the UI):
 *   OLLAMA_URL    base of the Ollama API (default http://localhost:11434)
 *   OLLAMA_MODEL  model to use           (default llama3.1:8b)
 *
 * No data leaves the machine: everything goes through the local Ollama server.
 */
import { getDb, assetRiskExposure, extractCves } from "./db";
import { getRun, getRunSteps } from "./chain";
import { topExposures } from "./fusion";
import { attackPathGraph } from "./attackpath";

const OLLAMA_URL = (process.env.OLLAMA_URL || "http://localhost:11434").replace(/\/$/, "");
export const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama3.1:8b";

interface ChatMsg { role: "system" | "user" | "assistant"; content: string }

export async function ollamaChat(messages: ChatMsg[], temperature = 0.2, timeoutMs = 90000): Promise<string> {
  const r = await fetch(`${OLLAMA_URL}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: OLLAMA_MODEL, messages, stream: false, options: { temperature } }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!r.ok) throw new Error(`Ollama HTTP ${r.status}`);
  const data = (await r.json()) as { message?: { content?: string }; error?: string };
  if (data.error) throw new Error(data.error);
  return (data.message?.content || "").trim();
}

export async function ollamaStatus(): Promise<{ reachable: boolean; url: string; model: string; models: string[] }> {
  try {
    // short timeout so "is the local AI up?" fails fast (offline fallback) instead of hanging
    const r = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(2500) });
    if (!r.ok) return { reachable: false, url: OLLAMA_URL, model: OLLAMA_MODEL, models: [] };
    const d = (await r.json()) as { models?: { name: string }[] };
    return { reachable: true, url: OLLAMA_URL, model: OLLAMA_MODEL, models: (d.models || []).map((m) => m.name) };
  } catch {
    return { reachable: false, url: OLLAMA_URL, model: OLLAMA_MODEL, models: [] };
  }
}

const STOPWORDS = new Set([
  "what", "which", "most", "current", "threat", "threats", "organisation", "organization",
  "cyber", "impacting", "impact", "there", "about", "with", "from", "that", "this", "your",
  "our", "are", "the", "for", "and", "how", "should", "could", "would", "have",
]);

/** Fetches the relevant RAG context from XORCISM (best-effort, each block isolated). */
export function buildThreatContext(question: string): { text: string; sources: string[] } {
  const blocks: string[] = [];
  const sources: string[] = [];
  const kw = Array.from(
    new Set((question || "").toLowerCase().split(/[^a-z0-9.]+/).filter((w) => w.length >= 4 && !STOPWORDS.has(w)))
  ).slice(0, 6);

  // 1) KEV vulnerabilities (actively exploited) present on the org's assets (cross-database join).
  try {
    const xo = getDb("XORCISM");
    const xv = getDb("XVULNERABILITY");
    const avs = xo.prepare("SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL").all() as { AssetID: number; VulnerabilityID: unknown }[];
    if (avs.length) {
      const kevRows = xv.prepare("SELECT VULReferentialID, VULReferential FROM VULNERABILITY WHERE KEV=1").all() as { VULReferentialID: unknown; VULReferential: string }[];
      const kevName = new Map(kevRows.map((r) => [String(r.VULReferentialID), r.VULReferential]));
      const hits = avs.filter((a) => kevName.has(String(a.VulnerabilityID)));
      if (hits.length) {
        const names = new Map((xo.prepare("SELECT AssetID, AssetName FROM ASSET").all() as { AssetID: number; AssetName: string }[]).map((r) => [r.AssetID, r.AssetName]));
        const list = hits.slice(0, 25).map((h) => `- ${names.get(h.AssetID) || `asset#${h.AssetID}`}: ${kevName.get(String(h.VulnerabilityID))}`);
        blocks.push(`KEV (known-exploited) vulnerabilities on the organisation's assets [${hits.length} total]:\n${list.join("\n")}`);
        sources.push("KEV×assets");
      }
    }
  } catch { /* skip */ }

  // 2) Most exposed assets (RiskScore × FinancialValue).
  try {
    const exp = assetRiskExposure(10);
    if (exp.assets.length) {
      blocks.push("Highest-exposure assets (RiskScore × FinancialValue):\n" +
        exp.assets.slice(0, 10).map((a) => `- ${a.name} (risk ${a.risk}, value ${a.value})`).join("\n"));
      sources.push("risk-exposure");
    }
  } catch { /* skip */ }

  // 3) MITRE ATT&CK techniques matching the question's keywords.
  try {
    if (kw.length) {
      const xt = getDb("XTHREAT");
      const where = kw.map(() => "Name LIKE ?").join(" OR ");
      const rows = xt.prepare(`SELECT DISTINCT AttackID, Name FROM ATTACKTECHNIQUE WHERE ${where} LIMIT 15`).all(...kw.map((k) => `%${k}%`)) as { AttackID: string; Name: string }[];
      if (rows.length) {
        blocks.push("Relevant MITRE ATT&CK techniques:\n" + rows.map((r) => `- ${r.AttackID} ${r.Name}`).join("\n"));
        sources.push("ATT&CK");
      }
    }
  } catch { /* skip */ }

  // 4) Observed hunts + current hypotheses.
  try {
    const xt = getDb("XTHREAT");
    const hunts = xt.prepare("SELECT HuntName, HuntStatus, AttackTags FROM HUNT ORDER BY HuntID DESC LIMIT 10").all() as { HuntName: string; HuntStatus: string; AttackTags: string }[];
    if (hunts.length) {
      blocks.push("Recent threat hunts:\n" + hunts.map((h) => `- [${h.HuntStatus || "?"}] ${h.HuntName} (ATT&CK: ${h.AttackTags || "-"})`).join("\n"));
      sources.push("hunts");
    }
    const hyp = xt.prepare("SELECT HypothesisName FROM HYPOTHESIS ORDER BY HypothesisID DESC LIMIT 8").all() as { HypothesisName: string }[];
    if (hyp.length) {
      blocks.push("Current hunt hypotheses:\n" + hyp.map((h) => `- ${h.HypothesisName}`).join("\n"));
      sources.push("hypotheses");
    }
  } catch { /* skip */ }

  return { text: blocks.join("\n\n"), sources };
}

/** "Ask the threat model": RAG over XORCISM + local LLM. */
export async function askThreatModel(question: string): Promise<{ answer: string; sources: string[]; model: string }> {
  const { text, sources } = buildThreatContext(question);
  const system =
    "You are a cyber threat intelligence analyst for this organisation (its data comes from the XORCISM platform). " +
    "Answer concisely with prioritised, actionable recommendations. Rely on the provided CONTEXT (the organisation's own data) " +
    "over generic knowledge, and explicitly say when relevant data is missing. Never invent asset names or CVEs that are not in the CONTEXT.";
  const user = `Question: ${question}\n\nCONTEXT (from XORCISM):\n${text || "(no organisation-specific data retrieved)"}`;
  const answer = await ollamaChat([{ role: "system", content: system }, { role: "user", content: user }]);
  return { answer, sources, model: OLLAMA_MODEL };
}

/** Suggested answer to a questionnaire question (OCIL). Human-in-the-loop. */
export async function suggestOcilAnswer(question: string, description?: string): Promise<{ answer: string; model: string }> {
  const system =
    "You are a security & compliance assistant helping answer a security/OCIL questionnaire. " +
    "Propose a clear, concise answer. If the question expects yes / no / not-applicable, state the recommended response " +
    "and a one-sentence justification. Keep it under 120 words. This is a draft for human review.";
  const user = `Questionnaire question: ${question}` + (description ? `\nAdditional context: ${description}` : "");
  const answer = await ollamaChat([{ role: "system", content: system }, { role: "user", content: user }]);
  return { answer, model: OLLAMA_MODEL };
}

// ── CTI agents (NexusBrief-style): report enrichment, vuln triage, brief builder ──

/** Enriches a THREATREPORT with an AI analyst note + extracted CVEs; persists AiSummary/CveTags. */
export async function enrichThreatReport(reportId: number): Promise<{ summary: string; cves: string[]; model: string }> {
  const xt = getDb("XTHREAT");
  const r = xt.prepare("SELECT ThreatReportName, ThreatReportDescription FROM THREATREPORT WHERE ThreatReportID = ?")
    .get(reportId) as { ThreatReportName?: string; ThreatReportDescription?: string } | undefined;
  if (!r) throw new Error(`THREATREPORT #${reportId} introuvable`);
  const text = `${r.ThreatReportName || ""}\n${r.ThreatReportDescription || ""}`.trim();
  const cves = extractCves(text);
  const system =
    "You are a CTI analyst. From the threat report below, write a tight analyst note (max 120 words) covering: " +
    "Targeting/sector; Threat type (actor / malware / vulnerability / campaign); Recommended actions. " +
    "Be factual, do not invent IOCs or CVEs not present in the text. Plain text, no preamble.";
  const summary = await ollamaChat([{ role: "system", content: system }, { role: "user", content: text.slice(0, 6000) }]);
  try {
    const cols = new Set((xt.prepare(`PRAGMA table_info("THREATREPORT")`).all() as { name: string }[]).map((c) => c.name));
    if (cols.has("AiSummary")) xt.prepare("UPDATE THREATREPORT SET AiSummary = ? WHERE ThreatReportID = ?").run(summary.slice(0, 4000), reportId);
    if (cols.has("CveTags") && cves.length) xt.prepare("UPDATE THREATREPORT SET CveTags = ? WHERE ThreatReportID = ?").run(cves.join(","), reportId);
  } catch { /* persistence best-effort */ }
  return { summary, cves, model: OLLAMA_MODEL };
}

/**
 * Summarize a batch of threat-feed items into a concise CTI digest. Uses the local LLM (Ollama)
 * when reachable, else falls back to a deterministic digest so the feature always returns something.
 */
export async function feedDigest(
  items: { title?: string; summary?: string; source?: string; date?: string }[],
  focus?: string,
): Promise<{ digest: string; cves: string[]; items: number; model: string; ai: boolean }> {
  const clean = (items || []).filter((i) => i && (i.title || i.summary)).slice(0, 60)
    .map((i) => ({ title: String(i.title || "").slice(0, 240), summary: String(i.summary || "").slice(0, 300), source: String(i.source || "").slice(0, 60) }));
  const corpus = clean.map((i) => `${i.source ? `[${i.source}] ` : ""}${i.title}${i.summary ? ` — ${i.summary}` : ""}`).join("\n");
  const cves = extractCves(corpus);
  if (!clean.length) return { digest: "No feed items to summarize.", cves: [], items: 0, model: "deterministic", ai: false };

  try {
    const system =
      "You are a senior CTI analyst. From the threat-intel headlines below, write a concise daily digest in Markdown (max ~180 words): " +
      "1) the 3-5 dominant themes; 2) notable threats, actors, malware and CVEs explicitly mentioned; 3) 2-3 recommended defender actions. " +
      "Be factual — do not invent CVEs, actors or IOCs that are not in the text. No preamble." + (focus ? ` Emphasize: ${focus}.` : "");
    const digest = await ollamaChat([{ role: "system", content: system }, { role: "user", content: corpus.slice(0, 7000) }], 0.3, 60000);
    return { digest, cves, items: clean.length, model: OLLAMA_MODEL, ai: true };
  } catch {
    return { digest: _deterministicDigest(clean, cves), cves, items: clean.length, model: "deterministic (Ollama unreachable)", ai: false };
  }
}

function _deterministicDigest(items: { title: string; summary: string; source: string }[], cves: string[]): string {
  const bySource: Record<string, number> = {};
  for (const i of items) if (i.source) bySource[i.source] = (bySource[i.source] || 0) + 1;
  const blob = items.map((i) => `${i.title} ${i.summary}`).join(" ").toLowerCase();
  const KW: [string, RegExp][] = [["Ransomware", /ransomware|lockbit|ransom|extortion/], ["Phishing", /phish|spoof|smish|bec\b/],
    ["Vulnerability/exploit", /vulnerab|exploit|cve-|zero[- ]?day|0-day|rce\b|patch/], ["APT/nation-state", /\bapt\b|nation|state-sponsored|espionage/],
    ["Malware", /malware|trojan|loader|stealer|backdoor|botnet|rat\b/], ["Data breach", /breach|leak|exposed|data theft/],
    ["Supply chain", /supply.?chain|dependency|npm|pypi/], ["Cloud/identity", /cloud|azure|aws|okta|identity|oauth|saas/]];
  const themes = KW.filter(([, re]) => re.test(blob)).map(([k]) => k);
  const topSrc = Object.entries(bySource).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([s, n]) => `${s} (${n})`);
  const lines = [
    `**CTI digest — ${items.length} items** (offline summary; start Ollama for an AI digest).`, "",
    themes.length ? `**Dominant themes:** ${themes.join(", ")}.` : "",
    cves.length ? `**CVEs mentioned (${cves.length}):** ${cves.slice(0, 12).join(", ")}${cves.length > 12 ? "…" : ""}.` : "",
    topSrc.length ? `**Most active sources:** ${topSrc.join(", ")}.` : "",
    "", "**Latest headlines:**",
    ...items.slice(0, 8).map((i) => `- ${i.source ? `[${i.source}] ` : ""}${i.title}`),
  ];
  return lines.filter((l) => l !== "").join("\n");
}

/** Vulnerability-triage agent: assembles KEV/EPSS/CPE/asset context for a CVE, then an LLM assessment. */
export async function triageVulnerability(input: { cve?: string; vulnerabilityId?: number }): Promise<{ assessment: string; context: string; model: string }> {
  const xv = getDb("XVULNERABILITY");
  let row: Record<string, unknown> | undefined;
  if (input.vulnerabilityId) {
    row = xv.prepare("SELECT * FROM VULNERABILITY WHERE VulnerabilityID = ?").get(input.vulnerabilityId) as Record<string, unknown> | undefined;
  } else if (input.cve) {
    row = xv.prepare("SELECT * FROM VULNERABILITY WHERE UPPER(VULReferential) = UPPER(?) LIMIT 1").get(input.cve) as Record<string, unknown> | undefined;
  }
  const cve = String(input.cve || row?.VULReferential || "").trim();
  const vid = Number(input.vulnerabilityId || row?.VulnerabilityID || 0);
  const lines: string[] = [`CVE / reference: ${cve || "(unknown)"}`];
  if (row) {
    lines.push(`Known-Exploited (KEV): ${row.KEV ? "YES — in CISA KEV catalog" : "no"}`);
    if (row.EPSS != null && row.EPSS !== "") lines.push(`EPSS exploit probability: ${row.EPSS}`);
    if (row.Exploited) lines.push("Flagged exploited in the wild");
    if (row.VULExploitable || row.EasilyExploitable) lines.push("Flagged exploitable" + (row.EasilyExploitable ? " (easily)" : ""));
    const desc = String(row.VULName || row.VULDescription || row.VULTechnicalDescription || "").trim();
    if (desc) lines.push(`Description: ${desc.slice(0, 600)}`);
  } else {
    lines.push("(not found in the local VULNERABILITY catalogue)");
  }
  try {
    if (vid) {
      const xo = getDb("XORCISM");
      const assets = (xo.prepare(
        "SELECT DISTINCT a.AssetName AS n FROM ASSETVULNERABILITY av JOIN ASSET a ON a.AssetID = av.AssetID WHERE av.VulnerabilityID = ? AND a.AssetName IS NOT NULL LIMIT 25"
      ).all(vid) as { n: string }[]).map((x) => x.n);
      lines.push(assets.length ? `Affected assets in inventory (${assets.length}): ${assets.join(", ")}` : "No assets currently linked to this vulnerability in the inventory.");
    }
  } catch { /* asset exposure best-effort */ }
  const context = lines.join("\n");
  const system =
    "You are a vulnerability-triage analyst. Using only the CONTEXT, produce: " +
    "1) Risk verdict (Critical / High / Medium / Low) with a one-line rationale grounded in KEV / EPSS / asset exposure; " +
    "2) Exploitation status; 3) Affected products / assets; 4) Prioritised next steps. " +
    "Max 160 words. Do not invent data absent from CONTEXT.";
  const assessment = await ollamaChat([{ role: "system", content: system }, { role: "user", content: `CONTEXT:\n${context}` }]);
  return { assessment, context, model: OLLAMA_MODEL };
}

/** Intelligence-brief builder: drafts a Markdown brief from selected (or latest) THREATREPORTs. */
export async function buildIntelBrief(reportIds: number[], focus?: string): Promise<{ brief: string; sources: string[]; model: string }> {
  const xt = getDb("XTHREAT");
  const ids = (reportIds || []).filter((n) => Number.isFinite(n)).slice(0, 30);
  const sources: string[] = [];
  const blocks: string[] = [];
  const take = (rows: Record<string, unknown>[]): void => {
    rows.forEach((r, i) => {
      if (r.ThreatReportReference) sources.push(String(r.ThreatReportReference));
      blocks.push(`[${i + 1}] ${String(r.ThreatReportName || "(untitled)")}\n${String(r.ThreatReportDescription || "").slice(0, 1000)}` +
        (r.CveTags ? `\nCVEs: ${String(r.CveTags)}` : ""));
    });
  };
  if (ids.length) {
    const ph = ids.map(() => "?").join(",");
    take(xt.prepare(`SELECT ThreatReportName, ThreatReportDescription, ThreatReportReference, CveTags FROM THREATREPORT WHERE ThreatReportID IN (${ph})`).all(...ids) as Record<string, unknown>[]);
  } else {
    take(xt.prepare("SELECT ThreatReportName, ThreatReportDescription, ThreatReportReference, CveTags FROM THREATREPORT ORDER BY ThreatReportID DESC LIMIT 15").all() as Record<string, unknown>[]);
  }
  const system =
    "You are a senior CTI analyst writing an intelligence brief for a security team. Output Markdown with sections: " +
    "## Executive summary, ## Key developments (bullets, cite sources as [n]), ## Notable CVEs, ## Recommended actions. " +
    "Be concise and factual; use only the provided REPORTS and cite them by their [n]. Max 400 words.";
  const user = `${focus ? `FOCUS: ${focus}\n\n` : ""}REPORTS:\n${blocks.join("\n\n")}`;
  const brief = await ollamaChat([{ role: "system", content: system }, { role: "user", content: user.slice(0, 12000) }]);
  return { brief, sources: [...new Set(sources)], model: OLLAMA_MODEL };
}

// ── Red/blue copilots over the closed-loop data ───────────────────────────────
interface Sev { Severity: string | null; FindingName: string }
function flat(steps: { FactsJSON: string | null }[]): { services: any[]; vulns: any[]; leaks: any[]; hosts: Set<string>; emails: Set<string>; tech: Set<string> } {
  const o = { services: [] as any[], vulns: [] as any[], leaks: [] as any[], hosts: new Set<string>(), emails: new Set<string>(), tech: new Set<string>() };
  for (const s of steps) {
    let f: any = {}; try { f = JSON.parse(s.FactsJSON || "{}"); } catch { /* */ }
    for (const x of f.services || []) o.services.push(x);
    for (const x of f.vulns || []) o.vulns.push(x);
    for (const x of f.leaks || []) o.leaks.push(x);
    for (const x of f.hosts || []) o.hosts.add(String(x));
    for (const x of f.emails || []) o.emails.add(String(x));
    for (const x of f.tech || []) o.tech.add(String(x));
  }
  return o;
}

/** AI attack-chain analyst: red+blue read-out of a tool-chaining run. Falls back to a
 *  deterministic data summary when the local AI is offline. */
export async function analyzeAttackChain(runId: number): Promise<{ analysis: string; model: string; offline: boolean }> {
  const run = getRun(runId);
  if (!run) throw new Error("run not found");
  const steps = getRunSteps(runId);
  const tools = [...new Set(steps.map((s) => s.Connector))];
  const f = flat(steps);
  const findings = getDb("XCOMPLIANCE").prepare(
    "SELECT Severity, FindingName FROM AUDITFINDING WHERE AuditID=? ORDER BY CASE LOWER(COALESCE(Severity,'')) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
  ).all(run.AuditID) as Sev[];
  const crit = findings.filter((x) => /critical|high/i.test(x.Severity || ""));
  const context =
    `Playbook: ${run.PlaybookName}\nSeed: ${run.SeedTarget} (mode: ${run.Mode})\n` +
    `Steps: ${steps.length} · Tools: ${tools.join(", ")}\n` +
    `Discovered: ${f.hosts.size} hosts, ${f.emails.size} emails, ${f.services.length} services` +
    (f.tech.size ? `, tech: ${[...f.tech].slice(0, 8).join(", ")}` : "") + "\n" +
    `Findings (${findings.length}):\n${findings.slice(0, 25).map((x) => `- [${x.Severity || "?"}] ${x.FindingName}`).join("\n")}`;

  const det = [
    `### Attack-chain analysis — ${run.PlaybookName}`,
    `Data summary — local AI unavailable.\n`,
    `**Seed** \`${run.SeedTarget}\` (${run.Mode}) · **${steps.length}** steps · **${findings.length}** findings · tools: ${tools.join(", ")}.`,
    f.hosts.size || f.emails.size ? `\n**Recon surface:** ${f.hosts.size} hosts, ${f.emails.size} emails discovered.` : "",
    `\n**Critical/high findings (${crit.length}):**\n${(crit.length ? crit : findings).slice(0, 12).map((x) => `- [${x.Severity || "?"}] ${x.FindingName}`).join("\n") || "- none"}`,
    `\n**Recommended actions:** patch the critical/high findings above first; segment any internet-exposed host that reaches sensitive services; rotate/protect any leaked credentials; add detections for the techniques used (${tools.join(", ")}).`,
  ].filter(Boolean).join("\n");
  const status = await ollamaStatus();
  if (status.reachable) {
    const sys =
      "You are a senior penetration tester and purple-team analyst. Given an attack-chain run, write a concise Markdown analysis with sections: " +
      "## What the attacker achieved (the critical path), ## Most serious findings (and why), ## Recommended next offensive steps, ## Top defensive actions & detections (map to MITRE ATT&CK techniques and D3FEND where relevant). Be specific, prioritized, and under 400 words.";
    try {
      const analysis = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: context.slice(0, 12000) }], 0.3);
      if (analysis) return { analysis, model: OLLAMA_MODEL, offline: false };
    } catch { /* slow/failed model → fall back to det */ }
  }
  return { analysis: det, model: status.reachable ? "fallback" : "offline", offline: true };
}

/** AI exposure briefing: CISO-level read-out of the fusion worklist + attack paths.
 *  Falls back to a deterministic summary when the local AI is offline. */
export async function exposureBrief(tenant: number | null): Promise<{ brief: string; model: string; offline: boolean }> {
  const top = topExposures(tenant, 15).results;
  const ap = attackPathGraph(tenant);
  const kev = top.filter((t) => t.kev).length, withExp = top.filter((t) => t.exploits > 0).length;
  const context =
    `Top exposures (priority/score · signals):\n${top.slice(0, 12).map((t) => `- ${t.ref}: prio ${t.priority}/score ${t.score} (KEV=${t.kev ? "yes" : "no"}, exploits=${t.exploits}, EPSS=${t.epss != null ? (t.epss * 100).toFixed(0) + "%" : "-"}, ${t.assets} assets)`).join("\n")}\n\n` +
    `Attack surface: ${ap.stats.entries} internet-exposed assets, ${ap.stats.jewels} crown jewels, ${ap.stats.pathsFound} attack paths to crown jewels.\n` +
    `Top choke points: ${ap.chokepoints.slice(0, 3).map((c) => `${c.label} (${c.paths} paths)`).join(", ") || "none"}.`;

  const top5 = top.slice(0, 5).map((t) => `- **${t.ref}** — priority ${t.priority}${t.kev ? " · ⚠️ KEV" : ""}${t.exploits ? ` · ${t.exploits} public exploit(s)` : ""} (${t.assets} asset${t.assets > 1 ? "s" : ""})`);
  const choke = ap.chokepoints[0];
  const det = [
    `### Exposure briefing`,
    `Data summary — local AI unavailable.\n`,
    `Across the prioritized worklist: **${kev}** known-exploited (KEV), **${withExp}** with public exploits.`,
    `\n**Top risks:**\n${top5.join("\n") || "- none"}`,
    `\n**Attack surface:** ${ap.stats.entries} internet-exposed assets → ${ap.stats.pathsFound} path(s) to ${ap.stats.jewels} crown jewel(s).`,
    choke ? `\n**Highest-leverage fix:** segment/patch **${choke.label}** — it sits on ${choke.paths} attack path(s) to crown jewels.` : "",
    `\n**Prioritized actions:** 1) remediate the KEV + public-exploit vulnerabilities above; 2) reduce the internet-exposed surface; 3) segment the top choke point to break crown-jewel paths.`,
  ].filter(Boolean).join("\n");
  const status = await ollamaStatus();
  if (status.reachable) {
    const sys =
      "You are a CISO security advisor. From the exposure worklist and attack-path data, write a concise executive Markdown briefing with sections: " +
      "## Bottom line, ## Biggest risks (plain language, name the CVEs), ## Crown-jewel attack paths, ## The single highest-leverage fix (choke point), ## Prioritized actions. Under 350 words.";
    try {
      const brief = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: context.slice(0, 12000) }], 0.3);
      if (brief) return { brief, model: OLLAMA_MODEL, offline: false };
    } catch { /* slow/failed model → fall back to det */ }
  }
  return { brief: det, model: status.reachable ? "fallback" : "offline", offline: true };
}
