/**
 * hunting.ts — Threat Hunting domain/capability.
 *
 * Reads the HUNT / HUNTATTACK / HUNTIOC, IOC and XTHREAT (ATT&CK technique,
 * threat actor, hypothesis) tables to drive a hunting overview, and exposes an
 * AI hunt assistant backed by the local LLM agent (Ollama) in ./ai.
 *
 * No data leaves the machine: the agent runs through the local Ollama server.
 */
import crypto from "crypto";
import { getDb } from "./db";
import { ollamaChat, OLLAMA_MODEL } from "./ai";

function nowTs(): string {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

const STOPWORDS = new Set([
  "what", "which", "most", "current", "threat", "threats", "hunt", "hunting", "actor",
  "technique", "techniques", "detect", "detection", "with", "from", "that", "this", "your",
  "our", "are", "the", "for", "and", "how", "should", "could", "would", "have", "about",
]);

/** Extracts up to 6 search keywords (or ATT&CK IDs) from a focus string. */
function keywords(focus: string): string[] {
  const raw = (focus || "").toLowerCase();
  const ids = (raw.match(/t\d{4}(?:\.\d{3})?/g) || []); // ATT&CK technique IDs
  const words = raw.split(/[^a-z0-9.]+/).filter((w) => w.length >= 4 && !STOPWORDS.has(w));
  return Array.from(new Set([...ids, ...words])).slice(0, 6);
}

// ── Overview ────────────────────────────────────────────────────────────────

export interface HuntingOverview {
  stats: {
    hunts: number;
    iocs: number;
    hypotheses: number;
    techniquesHunted: number;
    sigmaRules: number;
  };
  huntsByStatus: { status: string; count: number }[];
  iocsByType: { type: string; count: number }[];
  recentHunts: {
    HuntID: number; HuntName: string; HuntStatus: string; HuntDate: string;
    HuntTool: string; AttackTags: string; HuntFindings: string;
    techCount: number; iocCount: number;
  }[];
  recentIocs: { IOCID: number; IOCName: string; IOCtype: string; Pattern: string; Confidence: number }[];
  hypotheses: { HypothesisID: number; HypothesisName: string; ConfidenceLevel: string }[];
  topTechniques: { AttackID: string; Name: string; count: number }[];
}

/** Aggregates the hunting picture from the XTHREAT database (best-effort, each block isolated). */
export function huntingOverview(): HuntingOverview {
  const xt = getDb("XTHREAT");
  const one = <T>(sql: string, def: T): T => {
    try { return (xt.prepare(sql).get() as { v: T })?.v ?? def; } catch { return def; }
  };
  const many = <T>(sql: string): T[] => {
    try { return xt.prepare(sql).all() as T[]; } catch { return []; }
  };

  return {
    stats: {
      hunts: one<number>("SELECT COUNT(*) AS v FROM HUNT", 0),
      iocs: one<number>("SELECT COUNT(*) AS v FROM IOC", 0),
      hypotheses: one<number>("SELECT COUNT(*) AS v FROM HYPOTHESIS", 0),
      techniquesHunted: one<number>("SELECT COUNT(DISTINCT AttackID) AS v FROM HUNTATTACK", 0),
      sigmaRules: one<number>("SELECT COUNT(*) AS v FROM SIGMARULE", 0),
    },
    huntsByStatus: many<{ status: string; count: number }>(
      "SELECT COALESCE(NULLIF(TRIM(HuntStatus),''),'(unset)') AS status, COUNT(*) AS count " +
      "FROM HUNT GROUP BY status ORDER BY count DESC, status"),
    iocsByType: many<{ type: string; count: number }>(
      "SELECT COALESCE(NULLIF(TRIM(IOCtype),''),'indicator') AS type, COUNT(*) AS count " +
      "FROM IOC GROUP BY type ORDER BY count DESC, type LIMIT 12"),
    recentHunts: many(
      "SELECT h.HuntID, COALESCE(h.HuntName,'') AS HuntName, COALESCE(h.HuntStatus,'') AS HuntStatus, " +
      "COALESCE(h.HuntDate,'') AS HuntDate, COALESCE(h.HuntTool,'') AS HuntTool, " +
      "COALESCE(h.AttackTags,'') AS AttackTags, COALESCE(h.HuntFindings,'') AS HuntFindings, " +
      "(SELECT COUNT(*) FROM HUNTATTACK a WHERE a.HuntID=h.HuntID) AS techCount, " +
      "(SELECT COUNT(*) FROM HUNTIOC i WHERE i.HuntID=h.HuntID) AS iocCount " +
      "FROM HUNT h ORDER BY h.HuntID DESC LIMIT 12"),
    recentIocs: many(
      "SELECT IOCID, COALESCE(IOCName,'') AS IOCName, COALESCE(IOCtype,'indicator') AS IOCtype, " +
      "COALESCE(Pattern,'') AS Pattern, COALESCE(Confidence,0) AS Confidence " +
      "FROM IOC ORDER BY IOCID DESC LIMIT 12"),
    hypotheses: many(
      "SELECT HypothesisID, COALESCE(HypothesisName,'') AS HypothesisName, " +
      "COALESCE(ConfidenceLevel,'') AS ConfidenceLevel FROM HYPOTHESIS ORDER BY HypothesisID DESC LIMIT 10"),
    topTechniques: many<{ AttackID: string; Name: string; count: number }>(
      "SELECT a.AttackID AS AttackID, COALESCE(t.Name,'') AS Name, COUNT(*) AS count " +
      "FROM HUNTATTACK a LEFT JOIN ATTACKTECHNIQUE t ON t.AttackID=a.AttackID " +
      "GROUP BY a.AttackID ORDER BY count DESC, a.AttackID LIMIT 12"),
  };
}

// ── AI hunt assistant (RAG over HUNT / IOC / XTHREAT + local LLM agent) ────────

/** Builds the RAG context for a hunt focus from HUNT, IOC and XTHREAT tables. */
export function buildHuntContext(focus: string): { text: string; sources: string[] } {
  const xt = getDb("XTHREAT");
  const kw = keywords(focus);
  const blocks: string[] = [];
  const sources: string[] = [];
  const like = (cols: string[]): { where: string; args: string[] } => {
    const parts: string[] = [];
    const args: string[] = [];
    for (const k of kw) for (const c of cols) { parts.push(`${c} LIKE ?`); args.push(`%${k}%`); }
    return { where: parts.length ? parts.join(" OR ") : "1=1", args };
  };

  // 1) ATT&CK techniques matching the focus — with detection guidance + data sources.
  try {
    if (kw.length) {
      const { where, args } = like(["Name", "AttackID", "Description"]);
      const rows = xt.prepare(
        `SELECT AttackID, Name, COALESCE(Detection,'') AS Detection, COALESCE(DataSources,'') AS DataSources, ` +
        `COALESCE(Platforms,'') AS Platforms FROM ATTACKTECHNIQUE WHERE Deprecated=0 AND (${where}) LIMIT 12`
      ).all(...args) as { AttackID: string; Name: string; Detection: string; DataSources: string; Platforms: string }[];
      if (rows.length) {
        blocks.push("Relevant MITRE ATT&CK techniques (with detection/data sources):\n" + rows.map((r) =>
          `- ${r.AttackID} ${r.Name}` +
          (r.DataSources ? `\n    data sources: ${r.DataSources.slice(0, 200)}` : "") +
          (r.Detection ? `\n    detection: ${r.Detection.slice(0, 300)}` : "")).join("\n"));
        sources.push("ATT&CK");
      }
    }
  } catch { /* skip */ }

  // 2) Threat actors matching the focus.
  try {
    if (kw.length) {
      const { where, args } = like(["ThreatActorName", "ThreatActorDescription", "country"]);
      const rows = xt.prepare(
        `SELECT ThreatActorName, COALESCE(ThreatActorDescription,'') AS d, COALESCE(country,'') AS country ` +
        `FROM THREATACTOR WHERE ${where} LIMIT 8`
      ).all(...args) as { ThreatActorName: string; d: string; country: string }[];
      if (rows.length) {
        blocks.push("Known threat actors matching the focus:\n" + rows.map((r) =>
          `- ${r.ThreatActorName}${r.country ? ` (${r.country})` : ""}: ${r.d.slice(0, 180)}`).join("\n"));
        sources.push("threat-actors");
      }
    }
  } catch { /* skip */ }

  // 3) IOCs matching the focus (or most recent if no keyword hit).
  try {
    let rows: { IOCName: string; IOCtype: string; Pattern: string }[] = [];
    if (kw.length) {
      const { where, args } = like(["IOCName", "IOCDescription", "Pattern", "Labels"]);
      rows = xt.prepare(
        `SELECT COALESCE(IOCName,'') AS IOCName, COALESCE(IOCtype,'indicator') AS IOCtype, ` +
        `COALESCE(Pattern,'') AS Pattern FROM IOC WHERE ${where} LIMIT 15`
      ).all(...args) as typeof rows;
    }
    if (!rows.length) {
      rows = xt.prepare(
        "SELECT COALESCE(IOCName,'') AS IOCName, COALESCE(IOCtype,'indicator') AS IOCtype, " +
        "COALESCE(Pattern,'') AS Pattern FROM IOC ORDER BY IOCID DESC LIMIT 10"
      ).all() as typeof rows;
    }
    if (rows.length) {
      blocks.push("IOCs to pivot on:\n" + rows.map((r) =>
        `- [${r.IOCtype}] ${r.IOCName}${r.Pattern ? ` ${r.Pattern.slice(0, 120)}` : ""}`).join("\n"));
      sources.push("IOC");
    }
  } catch { /* skip */ }

  // 4) Existing hunts + open hypotheses (avoid duplicating effort).
  try {
    const hunts = xt.prepare(
      "SELECT HuntName, COALESCE(HuntStatus,'?') AS HuntStatus, COALESCE(AttackTags,'') AS AttackTags " +
      "FROM HUNT ORDER BY HuntID DESC LIMIT 8").all() as { HuntName: string; HuntStatus: string; AttackTags: string }[];
    if (hunts.length) {
      blocks.push("Existing hunts (do not duplicate):\n" + hunts.map((h) =>
        `- [${h.HuntStatus}] ${h.HuntName}${h.AttackTags ? ` (ATT&CK: ${h.AttackTags})` : ""}`).join("\n"));
      sources.push("hunts");
    }
    const hyp = xt.prepare("SELECT HypothesisName FROM HYPOTHESIS ORDER BY HypothesisID DESC LIMIT 6")
      .all() as { HypothesisName: string }[];
    if (hyp.length) {
      blocks.push("Current hunt hypotheses:\n" + hyp.map((h) => `- ${h.HypothesisName}`).join("\n"));
      sources.push("hypotheses");
    }
  } catch { /* skip */ }

  return { text: blocks.join("\n\n"), sources };
}

/** AI hunt assistant: builds a structured, actionable hunt package for a focus. */
export async function generateHunt(focus: string): Promise<{ plan: string; sources: string[]; model: string }> {
  const { text, sources } = buildHuntContext(focus);
  const system =
    "You are a senior threat hunter. From the analyst's FOCUS, produce a concrete, structured threat-hunting " +
    "package grounded in the provided CONTEXT (the organisation's own XORCISM data: ATT&CK techniques with " +
    "detection guidance and data sources, threat actors, existing hunts/hypotheses and IOCs). " +
    "Return Markdown with exactly these sections:\n" +
    "1. **Hypothesis** — one testable sentence.\n" +
    "2. **ATT&CK techniques** — bullet list, each starting with the technique ID (e.g. T1059.001).\n" +
    "3. **Data sources / log sources** — what telemetry to query.\n" +
    "4. **Detection logic** — pseudo-query or Sigma-style logic; you may give a SPL, KQL or EQL snippet.\n" +
    "5. **IOCs / pivots** — concrete indicators to chase (prefer those in the CONTEXT).\n" +
    "6. **Next steps & expected findings**.\n" +
    "Prefer techniques, actors and IOCs that appear in the CONTEXT; explicitly say when relevant data is missing. " +
    "Never invent IOCs or asset names absent from the CONTEXT. Be concise and operational.";
  const user = `FOCUS: ${focus}\n\nCONTEXT (from XORCISM HUNT / IOC / ATT&CK / threat actors):\n${text || "(no organisation-specific data retrieved)"}`;
  const plan = await ollamaChat([{ role: "system", content: system }, { role: "user", content: user }]);
  return { plan, sources, model: OLLAMA_MODEL };
}

// ── Persist a generated hunt into the HUNT table (+ HUNTATTACK links) ─────────

export interface SaveHuntInput {
  name: string;
  description?: string;
  status?: string;
  tool?: string;
  findings?: string;
  source?: string;
  techniques?: string[]; // ATT&CK IDs, e.g. ["T1059", "T1071.001"]
}

/** Inserts a HUNT row and its HUNTATTACK technique links. Returns the new HuntID + link count. */
export function saveHunt(input: SaveHuntInput): { huntId: number; links: number } {
  const xt = getDb("XTHREAT");
  const techniques = Array.from(new Set(
    (input.techniques || [])
      .map((s) => String(s).trim().toUpperCase())
      .filter((s) => /^T\d{4}(\.\d{3})?$/.test(s))
  ));
  const attackTags = techniques.join(", ");

  const tx = xt.transaction(() => {
    const huntId = ((xt.prepare("SELECT COALESCE(MAX(HuntID),0) AS m FROM HUNT").get() as { m: number }).m) + 1;
    xt.prepare(
      "INSERT INTO HUNT (HuntID, HuntGUID, HuntName, HuntDescription, CreatedDate, HuntStatus, HuntTool, " +
      "AttackTags, HuntFindings, HuntSource) VALUES (?,?,?,?,?,?,?,?,?,?)"
    ).run(
      huntId, crypto.randomUUID(), input.name.slice(0, 300), (input.description || "").slice(0, 8000), nowTs(),
      (input.status || "Proposed").slice(0, 60), (input.tool || "").slice(0, 200),
      attackTags, (input.findings || "").slice(0, 8000), (input.source || "AI hunt assistant").slice(0, 200)
    );
    let links = 0;
    let nextLinkId = ((xt.prepare("SELECT COALESCE(MAX(HuntAttackID),0) AS m FROM HUNTATTACK").get() as { m: number }).m);
    const ins = xt.prepare(
      "INSERT OR IGNORE INTO HUNTATTACK (HuntAttackID, HuntID, AttackID, CreatedDate) VALUES (?,?,?,?)"
    );
    for (const aid of techniques) {
      nextLinkId += 1;
      const info = ins.run(nextLinkId, huntId, aid, nowTs());
      if (info.changes) links += 1; else nextLinkId -= 1;
    }
    return { huntId, links };
  });
  return tx();
}
