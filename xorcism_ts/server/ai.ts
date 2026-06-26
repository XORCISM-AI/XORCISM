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
import { crocDashboard, riskHunting } from "./croc";
import { boardReport } from "./boardreport";

const OLLAMA_URL = (process.env.OLLAMA_URL || "http://localhost:11434").replace(/\/$/, "");
export const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama3.1:8b";
export const OLLAMA_EMBED_MODEL = process.env.OLLAMA_EMBED_MODEL || "nomic-embed-text";

interface ChatMsg { role: "system" | "user" | "assistant"; content: string }

/** Local embeddings via Ollama (`/api/embeddings`). Returns null if unavailable, so callers
 *  fall back to keyword overlap — nothing leaves the machine. Used for semantic retrieval
 *  (e.g. cross-framework control mapping). Caps the batch; embeds sequentially (small model). */
export async function embedTexts(texts: string[], timeoutMs = 30000): Promise<number[][] | null> {
  const out: number[][] = [];
  try {
    for (const t of texts.slice(0, 256)) {
      const r = await fetch(`${OLLAMA_URL}/api/embeddings`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: OLLAMA_EMBED_MODEL, prompt: String(t || "").slice(0, 2000) }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!r.ok) return null;
      const d = (await r.json()) as { embedding?: number[] };
      if (!Array.isArray(d.embedding) || !d.embedding.length) return null;
      out.push(d.embedding);
    }
    return out;
  } catch { return null; }
}

/** Cosine similarity of two equal-length vectors. */
export function cosine(a: number[], b: number[]): number {
  let dot = 0, na = 0, nb = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  return na && nb ? dot / (Math.sqrt(na) * Math.sqrt(nb)) : 0;
}

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

/** The configured AI provider (env-driven, never entered in the UI). Local Ollama is the privacy-first
 *  default; an org can point XORCISM at an OpenAI-compatible / Anthropic / Azure backend via env.
 *  XOR_AI_PROVIDER=ollama|openai|anthropic|azure (default: inferred from which keys are set). */
export function aiProviderInfo(): { provider: string; model: string; url: string; local: boolean; configured: boolean } {
  const explicit = (process.env.XOR_AI_PROVIDER || "").toLowerCase().trim();
  const hasOpenAI = !!(process.env.OPENAI_API_KEY || process.env.XOR_OPENAI_KEY);
  const hasAnthropic = !!(process.env.ANTHROPIC_API_KEY || process.env.XOR_ANTHROPIC_KEY);
  const hasAzure = !!(process.env.AZURE_OPENAI_KEY || process.env.AZURE_OPENAI_ENDPOINT);
  const provider = explicit || (hasOpenAI ? "openai" : hasAnthropic ? "anthropic" : hasAzure ? "azure" : "ollama");
  if (provider === "openai")
    return { provider: "OpenAI-compatible", model: process.env.XOR_OPENAI_MODEL || "gpt-4o-mini", url: process.env.OPENAI_BASE_URL || "https://api.openai.com/v1", local: false, configured: hasOpenAI };
  if (provider === "anthropic")
    return { provider: "Anthropic", model: process.env.XOR_ANTHROPIC_MODEL || "claude-3-5-sonnet", url: "https://api.anthropic.com", local: false, configured: hasAnthropic };
  if (provider === "azure")
    return { provider: "Azure OpenAI", model: process.env.AZURE_OPENAI_DEPLOYMENT || "gpt-4o-mini", url: process.env.AZURE_OPENAI_ENDPOINT || "", local: false, configured: hasAzure };
  return { provider: "Ollama (local)", model: OLLAMA_MODEL, url: OLLAMA_URL, local: true, configured: true };
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

/**
 * Reason ACROSS the CROC continuous-defense loop (detect → decide → act → learn, + expose & identity).
 * Pulls a live cross-lifecycle snapshot and asks the local model to CONNECT the stages — which detection
 * exploits which exposure, which exposure reaches a crown jewel, where the loop is stuck. Deterministic
 * cross-stage fallback when Ollama is offline. Nothing leaves the machine.
 */
export async function lifecycleReasoning(tenant: number | null): Promise<{ reasoning: string; model: string; offline: boolean }> {
  const dash = crocDashboard(tenant);
  const hunt = riskHunting(tenant);
  const s = dash.summary || {};
  const fb = dash.feedback || {};
  const rwa = (dash.riskWeightedAlerts || []).slice(0, 6);
  const hotExp = (hunt.exposures || []).filter((e: any) => e.hot).slice(0, 6);
  const agentic = (hunt.agentic || []).slice(0, 5);
  const res = dash.resilience || [];
  const first = res[0], last = res[res.length - 1];

  const context = [
    `# CROC loop snapshot (tenant ${tenant ?? "global"})`,
    `Loop health: ${s.loopHealth} | machine-speed ${s.machineSpeedPct}% (${s.autoDecided} auto-decided of ${s.eventsToday} events/24h) | median latency ${s.medianLatencyMs}ms | direction CROC→SOC ${s.crocToSoc} / SOC→CROC ${s.socToCroc}`,
    ``,
    `## DETECT — risk-weighted SOC queue`,
    rwa.map((a: any) => `- [w${a.riskWeight}] ${a.severity} ${a.name}${a.attack ? " (" + a.attack + ")" : ""}`).join("\n") || "- (no open alerts)",
    `Techniques in recent incidents: ${(fb.techniquesSeen || []).join(", ") || "none"}. Actively-attacked exposures: ${fb.matchingExposures || 0} of ${fb.totalExposures || 0}.`,
    ``,
    `## DECIDE / ACT — what the loop fired (24h)`,
    `tickets opened ${s.ticketsOpened || 0}, IAM constraints ${s.iamActions || 0}, pushed to ITSM ${s.externalTickets || 0}.`,
    (dash.feed || []).slice(0, 6).map((e: any) => `- ${e.type} [${e.severity}] → ${e.decided || "→ human"}`).join("\n"),
    ``,
    `## EXPOSE — actively-attacked + reachable`,
    hotExp.map((e: any) => `- ${e.ref} prio ${e.priority}${e.kev ? " KEV" : ""}${e.exploits ? ` ${e.exploits}exp` : ""} on ${e.assets} asset(s)${e.reach ? ` [${e.reach}]` : ""}`).join("\n") || "- none hot",
    `Attack paths to crown jewels: ${hunt.summary?.attackPaths || 0} (reachable jewels ${hunt.summary?.reachableJewels || 0}); exposures on a path: ${hunt.summary?.onAttackPath || 0}. Choke points: ${(hunt.chokepoints || []).slice(0, 3).map((c: any) => `${c.label} (${c.paths})`).join(", ") || "none"}.`,
    ``,
    `## IDENTITY — over-scoped non-human`,
    agentic.map((a: any) => `- ${a.name} (${(a.why || []).join("/")})`).join("\n") || "- none flagged",
    ``,
    `## LEARN — resilience over time (${res.length} day(s))`,
    last ? `latest: machine-speed ${last.machineSpeedPct}%, actively-attacked backlog ${last.backlog}, enterprise score ${last.score}${first && first !== last ? ` | trend from machine-speed ${first.machineSpeedPct}%, backlog ${first.backlog}` : ""}` : "no history yet",
  ].join("\n");

  const det = lifecycleDet(dash, hunt);
  const status = await ollamaStatus();
  if (status.reachable) {
    const sys =
      "You are XORCISM's CROC reasoning copilot. You reason ACROSS a continuous defense loop with stages DETECT → DECIDE → ACT → LEARN, plus EXPOSE and IDENTITY context. " +
      "Do NOT just summarize each stage. CONNECT them: does a current detection exploit a top exposure? does an exposure reach a crown jewel or sit on an internet entry / choke point? is an over-scoped identity a lateral-move path? Is the loop STUCK (deciding but not acting, acting while the backlog still grows, one-directional, or still)? " +
      "Output concise Markdown with these sections: ## The one thing (2-3 sentences — the dominant cross-stage story), ## Connections across the loop (2-4 bullets, each linking >=2 stages and citing the data), ## Where the loop is stuck, ## Next move (one concrete specific action). Cite CVE / asset / technique names from the data. Under 320 words.";
    try {
      const reasoning = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: context.slice(0, 14000) }], 0.3);
      if (reasoning) return { reasoning, model: OLLAMA_MODEL, offline: false };
    } catch { /* slow/failed model → deterministic */ }
  }
  return { reasoning: det, model: status.reachable ? "fallback" : "offline", offline: true };
}

/** Deterministic cross-stage reasoning (offline fallback) — finds real connections, not a data dump. */
function lifecycleDet(dash: any, hunt: any): string {
  const s = dash.summary || {}, fb = dash.feedback || {};
  const conns: string[] = [];
  if ((fb.matchingExposures || 0) > 0)
    conns.push(`**DETECT ↔ EXPOSE:** ${fb.matchingExposures} of ${fb.totalExposures} estate exposures are actively attacked right now (${(fb.techniquesSeen || []).slice(0, 3).join(", ") || "techniques seen in incidents"}) — the SOC queue and the exposure worklist are looking at the same threat.`);
  const reachHot = (hunt.exposures || []).find((e: any) => e.hot && e.reach);
  if (reachHot)
    conns.push(`**EXPOSE ↔ ATTACK-PATH:** ${reachHot.ref} is actively-attacked AND its asset is ${reachHot.reach === "entry" ? "an internet entry point" : reachHot.reach === "jewel" ? "a crown jewel" : reachHot.reach === "choke" ? "a choke point" : "on a path to a crown jewel"} — a live, reachable hole.`);
  if ((hunt.agentic || []).length)
    conns.push(`**IDENTITY ↔ LATERAL-MOVE:** ${hunt.agentic.length} over-scoped non-human identit${hunt.agentic.length > 1 ? "ies" : "y"} (e.g. ${hunt.agentic[0].name}) could be abused to pivot once an adversary lands.`);

  const stuck: string[] = [];
  if (s.loopHealth !== "moving") stuck.push(s.loopHealth === "still" ? "the loop is **STILL** — no events crossed in the last hour (a diagram, not a loop)" : "the loop is **one-directional** — intelligence crosses only one way (a handoff, not a loop)");
  if ((s.autoDecided || 0) > 0 && ((s.ticketsOpened || 0) + (s.iamActions || 0) + (s.externalTickets || 0)) === 0)
    stuck.push("the loop **DECIDES but does not ACT** — policies fired but no ticket / constraint / ITSM push landed (enforcement not configured or disarmed)");
  const res = dash.resilience || []; const f = res[0], l = res[res.length - 1];
  if (f && l && f !== l && (l.backlog || 0) > (f.backlog || 0))
    stuck.push(`the **LEARN** signal shows the actively-attacked backlog **growing** (${f.backlog}→${l.backlog}) — the loop is acting but not keeping up`);

  let next = "Keep the loop moving — wire an exposure or incident event so intelligence crosses both ways.";
  if (reachHot) next = `Remediate or escalate **${reachHot.ref}** — it is the live, reachable hole on a crown-jewel path.`;
  else if ((s.autoDecided || 0) > 0 && ((s.ticketsOpened || 0) + (s.iamActions || 0)) === 0) next = "Arm enforcement — configure a ticketing / Teams / IAM destination so decided actions actually fire.";
  else if ((hunt.agentic || []).length) next = `Constrain **${hunt.agentic[0].name}** — strip its standing privilege before it becomes a lateral-move path.`;
  else { const choke = (hunt.chokepoints || [])[0]; if (choke) next = `Harden / segment **${choke.label}** — it sits on ${choke.paths} attack path(s) to crown jewels.`; }

  return [
    `### Reasoning across the loop`,
    `_Data-driven cross-stage analysis — local AI unavailable._\n`,
    `**The one thing:** loop health is **${s.loopHealth || "?"}** at **${s.machineSpeedPct || 0}% machine-speed**; ${(fb.matchingExposures || 0) > 0 ? `${fb.matchingExposures} exposure(s) are under live attack` : "no exposures are under live attack right now"}, and ${hunt.summary?.onAttackPath || 0} exposure(s) sit on a path to a crown jewel.`,
    `\n**Connections across the loop:**\n${conns.map((c) => "- " + c).join("\n") || "- No strong cross-stage connections detected yet."}`,
    `\n**Where the loop is stuck:**\n${stuck.map((c) => "- " + c).join("\n") || "- Nothing obvious — the loop is moving in both directions."}`,
    `\n**Next move:** ${next}`,
  ].join("\n");
}

// ── CTI-Expert: AI-orchestrated OSINT investigation (port of the cti-expert skill to local AI) ──
export interface CtiFinding { technique: string; phase: string; finding: string; reliability: string; severity: string }
export interface CtiObservable { type: string; value: string }
export interface CtiInvestigationResult {
  summary: string; brief: string; exposureScore: number; severity: string;
  findings: CtiFinding[]; observables: CtiObservable[]; recommendations: string[];
  attackTags: string[]; model: string; offline: boolean;
}

/** Best-effort extraction of the first JSON object from an LLM reply (tolerates ```json fences / prose). */
function _extractJson(s: string): any | null {
  if (!s) return null;
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const body = fence ? fence[1] : s;
  const i = body.indexOf("{"); const j = body.lastIndexOf("}");
  if (i < 0 || j <= i) return null;
  try { return JSON.parse(body.slice(i, j + 1)); } catch { return null; }
}

const _SEV_RANK: Record<string, number> = { MINOR: 1, NOTABLE: 2, HIGH: 3, CRITICAL: 4 };
function _severityFromScore(n: number): string {
  return n >= 80 ? "CRITICAL" : n >= 55 ? "HIGH" : n >= 30 ? "NOTABLE" : "MINOR";
}

/**
 * Run an OSINT/CTI investigation against `target` (of type `kind`: domain/email/username/ip/
 * person/org/phone/crypto), using the local LLM as the analyst (cti-expert methodology:
 * Acquire→Enrich→Assess→Deliver, A–F source reliability, 0–100 exposure score, STIX observables).
 * `plan` is the deterministic technique plan (which XORCISM connectors apply to this target type);
 * `context` is any XORCISM-side enrichment (what we already know about the target). Degrades to a
 * deterministic methodology scaffold when Ollama is unreachable so the feature always returns. */
export async function ctiInvestigate(
  target: string, kind: string, plan: { id: string; name: string; phase: string; connector?: string }[], context: string
): Promise<CtiInvestigationResult> {
  const targetObs: CtiObservable = { type: kind, value: target };
  // exposure heuristic: surface size by target type × breadth of applicable techniques
  const base: Record<string, number> = { domain: 45, email: 50, username: 40, ip: 42, person: 55, org: 48, phone: 38, crypto: 35 };
  const detScore = Math.max(10, Math.min(95, (base[kind] ?? 40) + Math.min(20, plan.length)));
  const detFindings: CtiFinding[] = plan.map((t) => ({
    technique: t.name, phase: t.phase,
    finding: `Planned ${t.phase.toLowerCase()} technique — run ${t.connector ? `the \`${t.connector}\` connector` : "the matching XORCISM connector"} to collect.`,
    reliability: "F", severity: "NOTABLE",
  }));
  const det: CtiInvestigationResult = {
    summary: `## INTSUM — ${kind} \`${target}\`\n\n_Local AI unavailable — investigation **plan** only (run the listed connectors, then re-run for analysis)._\n\n`
      + `**Planned techniques (${plan.length})** across Acquire→Enrich→Assess→Deliver:\n`
      + plan.map((t) => `- **${t.phase}** · ${t.name}${t.connector ? ` → \`${t.connector}\`` : ""}`).join("\n"),
    brief: `OSINT investigation of ${kind} "${target}" scoped to ${plan.length} techniques. Heuristic exposure ${detScore}/100 (${_severityFromScore(detScore)}). Run the planned connectors to collect, then re-run with the local AI for graded findings.`,
    exposureScore: detScore, severity: _severityFromScore(detScore),
    findings: detFindings, observables: [targetObs], recommendations: [
      "Run the planned XORCISM OSINT connectors (sherlock/maigret/holehe/theHarvester/subfinder…) to collect.",
      "Corroborate each finding with a second source before grading reliability above C.",
      "Export confirmed IOCs as STIX 2.1 observables and link them to the affected assets.",
    ], attackTags: [], model: "deterministic (Ollama unreachable)", offline: true,
  };

  const status = await ollamaStatus();
  if (!status.reachable) return det;

  const sys =
    "You are CTI-Expert, a senior cyber-threat-intelligence & OSINT analyst. Investigate the given target using the supplied technique plan "
    + "(phases: Acquire, Enrich, Assess, Deliver). Grade each finding's source reliability A-F (A=confirmed by multiple independent sources, "
    + "F=uncorroborated) and severity CRITICAL/HIGH/NOTABLE/MINOR. Produce an exposure-risk score 0-100. Be realistic about what OSINT typically "
    + "reveals for this target type; do NOT invent specific private data. Output ONLY a JSON object with keys: "
    + "exposureScore (int), severity (CRITICAL|HIGH|NOTABLE|MINOR), summary (Markdown INTSUM), brief (<=120 words exec summary), "
    + "findings (array of {technique, phase, finding, reliability, severity}), observables (array of {type, value} - STIX-style IOCs, "
    + "include the target), recommendations (array of strings), attackTags (array of MITRE ATT&CK technique IDs like T1589).";
  const user = `Target: ${target}\nType: ${kind}\n\nPlanned techniques:\n`
    + plan.map((t) => `- [${t.phase}] ${t.name}${t.connector ? ` (connector: ${t.connector})` : ""}`).join("\n")
    + (context ? `\n\nWhat XORCISM already knows about this target:\n${context.slice(0, 6000)}` : "");
  try {
    const raw = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user }], 0.3, 120000);
    const j = _extractJson(raw);
    if (j && (j.summary || Array.isArray(j.findings))) {
      let score = Number(j.exposureScore); if (!Number.isFinite(score)) score = detScore;
      score = Math.max(0, Math.min(100, Math.round(score)));
      const sev = _SEV_RANK[String(j.severity || "").toUpperCase()] ? String(j.severity).toUpperCase() : _severityFromScore(score);
      const findings: CtiFinding[] = Array.isArray(j.findings) ? j.findings.slice(0, 60).map((f: any) => ({
        technique: String(f.technique || "").slice(0, 120), phase: String(f.phase || "Assess").slice(0, 20),
        finding: String(f.finding || "").slice(0, 1000),
        reliability: /^[A-F]$/i.test(String(f.reliability || "")) ? String(f.reliability).toUpperCase() : "C",
        severity: _SEV_RANK[String(f.severity || "").toUpperCase()] ? String(f.severity).toUpperCase() : "NOTABLE",
      })) : detFindings;
      const obsRaw: CtiObservable[] = Array.isArray(j.observables) ? j.observables.map((o: any) => ({
        type: String(o.type || "unknown").slice(0, 40), value: String(o.value || "").slice(0, 400),
      })).filter((o: CtiObservable) => o.value) : [];
      const observables = [targetObs, ...obsRaw].filter((o, i, a) => a.findIndex((x) => x.value === o.value) === i).slice(0, 80);
      const recs: string[] = Array.isArray(j.recommendations) ? j.recommendations.map((x: any) => String(x).slice(0, 400)).filter(Boolean).slice(0, 20) : det.recommendations;
      const tags: string[] = Array.isArray(j.attackTags) ? j.attackTags.map((x: any) => String(x).trim()).filter((x: string) => /^TA?\d{3,4}/i.test(x)).slice(0, 30) : [];
      return {
        summary: String(j.summary || det.summary).slice(0, 20000),
        brief: String(j.brief || det.brief).slice(0, 4000),
        exposureScore: score, severity: sev, findings, observables, recommendations: recs,
        attackTags: tags, model: OLLAMA_MODEL, offline: false,
      };
    }
  } catch { /* slow/failed model → deterministic */ }
  return { ...det, model: "fallback (AI returned no JSON)" };
}

// ── Policy drafting — local AI fills POLICY.PolicyContent ─────────────────────
/** Strips markdown/code-fence/document wrappers the model sometimes adds, leaving body HTML. */
function sanitizePolicyHtml(s: string): string {
  let h = (s || "").trim();
  h = h.replace(/^```(?:html)?\s*/i, "").replace(/```\s*$/i, "").trim();
  h = h.replace(/<!DOCTYPE[^>]*>/gi, "").replace(/<\/?(?:html|head|body)[^>]*>/gi, "").trim();
  // If the model returned plain text (no tags), wrap paragraphs.
  if (!/<\w+[^>]*>/.test(h)) h = h.split(/\n{2,}/).map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");
  return h.slice(0, 12000);
}
/** Deterministic, sensible policy skeleton when Ollama is unavailable. */
function policyTemplateHtml(name: string, scope: string, category?: string, framework?: string): string {
  const sc = scope || "all employees, contractors, systems and information assets of the organization";
  const fw = framework ? ` aligned with ${framework}` : "";
  return [
    `<h4>1. Purpose</h4><p>This ${category ? category.toLowerCase() + " " : ""}policy${fw} establishes the requirements and expectations for <b>${name}</b>, to protect the confidentiality, integrity and availability of organizational information and to support business objectives and regulatory obligations.</p>`,
    `<h4>2. Scope</h4><p>This policy applies to ${sc}.</p>`,
    `<h4>3. Policy Statements</h4><ul>` +
      `<li>Access to information and systems is granted on a least-privilege, need-to-know basis and reviewed periodically.</li>` +
      `<li>All users are responsible for safeguarding credentials and reporting suspected security incidents promptly.</li>` +
      `<li>Information is classified and handled according to its sensitivity, with appropriate controls applied throughout its lifecycle.</li>` +
      `<li>Systems are configured to approved secure baselines and kept current with security updates.</li>` +
      `<li>Changes affecting security posture follow a documented review and approval process.</li>` +
      `<li>Compliance with this policy is monitored, measured and reported to management.</li>` +
    `</ul>`,
    `<h4>4. Roles &amp; Responsibilities</h4><ul>` +
      `<li><b>Executive management</b> — sponsors the policy and allocates resources.</li>` +
      `<li><b>Information Security / CISO</b> — maintains, communicates and enforces the policy.</li>` +
      `<li><b>Asset &amp; system owners</b> — implement controls within their areas.</li>` +
      `<li><b>All personnel</b> — comply with the policy and complete required awareness training.</li>` +
    `</ul>`,
    `<h4>5. Compliance &amp; Enforcement</h4><p>Violations may result in disciplinary action up to and including termination, and where applicable, legal action. Exceptions require documented risk acceptance approved by the CISO.</p>`,
    `<h4>6. Review &amp; Revision</h4><p>This policy is reviewed at least annually, or upon significant changes to the threat landscape, business or regulatory environment.</p>`,
  ].join("");
}
export async function draftPolicy(opts: { name?: string; description?: string; scope?: string; category?: string; framework?: string }): Promise<{ content: string; model: string; offline: boolean }> {
  const name = (opts.name || "Information Security Policy").trim();
  const scope = (opts.scope || "").trim();
  const ctx = [opts.description, opts.category && `Category: ${opts.category}`, opts.framework && `Framework: ${opts.framework}`, scope && `Scope: ${scope}`].filter(Boolean).join("\n");
  const det = policyTemplateHtml(name, scope, opts.category, opts.framework);
  const status = await ollamaStatus();
  if (status.reachable) {
    const sys =
      "You are a GRC policy author. Write a concise, professional corporate information-security policy as clean HTML " +
      "(use <h4> for section headings, <p> for paragraphs, <ul><li> for lists — NO markdown, NO code fences, NO <html>/<head>/<body> tags). " +
      "Include these sections in order: Purpose, Scope, Policy Statements (5–8 concrete, auditable requirements), Roles & Responsibilities, Compliance & Enforcement, Review & Revision. Under 500 words.";
    try {
      const html = sanitizePolicyHtml(await ollamaChat([{ role: "system", content: sys }, { role: "user", content: `Policy title: ${name}\n${ctx || "(no extra context)"}` }], 0.4));
      if (html && html.length > 40) return { content: html, model: OLLAMA_MODEL, offline: false };
    } catch { /* fall back */ }
  }
  return { content: det, model: status.reachable ? "fallback" : "offline", offline: true };
}

// ── Crisis-scenario drafting — local AI generates CRISISSCENARIO.Description (HTML) ──
export async function draftCrisisScenario(opts: { name?: string; scenarioType?: string; severity?: string; objectives?: string; threatActor?: string }): Promise<{ content: string; model: string; offline: boolean }> {
  const esc = (s: string): string => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));
  const name = (opts.name || "Crisis scenario").trim();
  const type = (opts.scenarioType || "").trim();
  const sev = (opts.severity || "").trim();
  const ctx = [type && `Type: ${type}`, sev && `Severity: ${sev}`, opts.objectives && `Objectives: ${opts.objectives}`, opts.threatActor && `Threat actor: ${opts.threatActor}`].filter(Boolean).join("\n");
  const det =
    `<p><b>${esc(name)}</b>${type ? ` — a ${esc(type.toLowerCase())} crisis scenario` : ""}${sev ? ` (severity: ${esc(sev)})` : ""}.</p>` +
    `<p>This tabletop exercise simulates an escalating ${type ? esc(type.toLowerCase()) : "cyber"} crisis that forces the crisis-management team to detect, triage and respond under time pressure while protecting business-critical operations${opts.threatActor ? `, with <b>${esc(opts.threatActor)}</b> as the threat actor` : ""}.</p>` +
    `<p><b>Objectives:</b> ${opts.objectives ? esc(opts.objectives) : "validate detection &amp; escalation, decision-making under pressure, internal/external communications (incl. regulators), and business continuity / recovery."}</p>` +
    `<p><b>Expected response:</b> activate the crisis team and incident-response plan, assess impact and the regulatory notification clock, coordinate legal &amp; communications, contain and recover, then run an after-action review.</p>`;
  const status = await ollamaStatus();
  if (status.reachable) {
    const sys =
      "You are a crisis-management / tabletop-exercise designer. Write a concise scenario Description as clean HTML " +
      "(use <p> paragraphs and at most one short <ul><li> list — NO markdown, NO code fences, NO <html>/<body>). " +
      "Cover: the situation/inject narrative, the business impact, the exercise objectives, and the expected crisis-team response (escalation, comms, regulators, recovery, after-action). Under 250 words.";
    try {
      const html = sanitizePolicyHtml(await ollamaChat([{ role: "system", content: sys }, { role: "user", content: `Scenario: ${name}\n${ctx || "(no extra context)"}` }], 0.5));
      if (html && html.length > 40) return { content: html, model: OLLAMA_MODEL, offline: false };
    } catch { /* fall back */ }
  }
  return { content: det, model: status.reachable ? "fallback" : "offline", offline: true };
}

// ── Board narrative — exec summary for the board report (Likelihood × Impact, business language) ──
export async function boardNarrative(tenant: number | null): Promise<{ narrative: string; model: string; offline: boolean }> {
  const r = boardReport(tenant);
  const context =
    `Security posture: ${r.posture.score}/100 (grade ${r.posture.grade}, ${r.posture.verdict}); underlying enterprise-risk index ${r.posture.enterpriseRisk}.\n` +
    `Trend: ${r.trend.direction} ${r.trend.deltaPct >= 0 ? "+" : ""}${r.trend.deltaPct}% over ~${r.trend.rangeDays} days (posture ${r.trend.startScore}→${r.trend.currentScore}).\n` +
    `Critical assets: ${r.criticalAssets.atRisk}/${r.criticalAssets.total} crown jewels at risk (${r.criticalAssets.pctAtRisk}%), ${r.criticalAssets.pathsFound} attack paths from ${r.criticalAssets.entries} exposed footholds.\n` +
    `Top risks:\n${r.risks.map((x) => `- ${x.ref} (priority ${x.priority}${x.kev ? ", KEV" : ""}${x.exploits ? ", public exploit" : ""}, ${x.assets} assets): ${x.whyItMatters}`).join("\n") || "- none"}\n` +
    `Highest-leverage remediation: ${r.remediation.map((x) => `${x.label} (${x.paths} paths)`).join("; ") || "none dominant"}.\n` +
    `Financial exposure (ALE): ${r.financial.aleTotal ? "$" + r.financial.aleTotal.toLocaleString() : "not quantified"}.\n` +
    `Resources: ${r.resources.openIncidents} open incidents${r.resources.mttrHours != null ? `, MTTR ${r.resources.mttrHours}h` : ""}; compliance ${r.resources.compliance.completionPct}% with ${r.resources.compliance.openFindings} open high/critical findings.`;

  const det = [
    `### Board cyber-risk read-out`,
    `*Data summary — local AI unavailable.*\n`,
    `**Bottom line:** Security posture is **${r.posture.score}/100 (grade ${r.posture.grade} — ${r.posture.verdict})**, and ${r.trend.rangeDays ? `**${r.trend.direction}** (${r.trend.deltaPct >= 0 ? "+" : ""}${r.trend.deltaPct}% over ~${r.trend.rangeDays} days)` : "now baselined for trending"}.`,
    `\n**Are our critical assets safe?** ${r.criticalAssets.total ? `${r.criticalAssets.pctAtRisk}% of crown jewels (${r.criticalAssets.atRisk}/${r.criticalAssets.total}) are reachable by a modeled attack path.` : "Tag business-critical assets to quantify crown-jewel risk."}`,
    `\n**What are the risks?**\n${r.risks.slice(0, 5).map((x) => `- **${x.ref}** — ${x.whyItMatters}`).join("\n") || "- none"}`,
    `\n**Where do we get the most risk reduction for the least cost?** ${r.remediation[0] ? `Harden the choke point **${r.remediation[0].label}** (${r.remediation[0].paths} paths) and remediate the KEV/public-exploit items above.` : "Keep burning down the prioritized worklist."}`,
    r.financial.aleTotal ? `\n**Financial exposure (Likelihood × Impact):** ~$${r.financial.aleTotal.toLocaleString()} annualized loss expectancy across the open risk register.` : "",
    `\n**Are we improving?** ${r.questions.find((q) => q.q.startsWith("How are we"))?.a || ""}`,
  ].filter(Boolean).join("\n");

  const status = await ollamaStatus();
  if (status.reachable) {
    const sys =
      "You are a CISO briefing a Board of Directors. Translate the technical risk data into a concise, business-language Markdown read-out — frame risk as Likelihood × Impact, avoid jargon and raw vulnerability counts, focus on critical business assets and whether posture is improving. " +
      "Sections: ## Bottom line, ## Are our critical assets safe, ## What are the biggest risks (name the CVEs in plain terms), ## Highest-leverage action, ## Are our investments paying off (the trend). Under 380 words.";
    try {
      const narrative = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: context.slice(0, 12000) }], 0.3);
      if (narrative) return { narrative, model: OLLAMA_MODEL, offline: false };
    } catch { /* fall back */ }
  }
  return { narrative: det, model: status.reachable ? "fallback" : "offline", offline: true };
}
