/**
 * reportmapper.ts — Report ATT&CK Mapper (native MITRE TRAM parity, /report-mapper).
 *
 * TRAM (Threat Report ATT&CK Mapper) uses NLP to map the sentences of a finished CTI report to
 * MITRE ATT&CK techniques with a confidence score. This implements the same capability natively:
 * split a report into sentences and map each to ATT&CK techniques with two engines —
 *   • keyword engine  : a curated lexicon of distinctive TTP phrases + verbatim technique-name
 *                       matches over XTHREAT.ATTACKTECHNIQUE (deterministic, offline, always on);
 *   • AI engine       : the local model (Ollama) proposes mappings, validated against the ATT&CK
 *                       catalogue — merged over the keyword baseline when a model is reachable.
 *
 * Accepted mappings are saved to THREATREPORT + REPORTMAPPING and can be exported as an ATT&CK
 * Navigator layer. Reuses ai.ts (same pattern as detectioneng.ts / purpleteam.ts).
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";
import { ollamaChat, ollamaStatus, OLLAMA_MODEL } from "./ai";

export interface TechMapping { attackId: string; name: string; confidence: number; source: string }
export interface MappedSentence { order: number; text: string; mappings: TechMapping[] }
export interface MapResult {
  sentences: MappedSentence[];
  summary: { sentences: number; mapped: number; techniques: number; engine: string; aiReachable: boolean };
}

// ── ATT&CK catalogue (id → canonical name), loaded from XTHREAT.ATTACKTECHNIQUE ──
function catalogue(): Map<string, string> {
  const m = new Map<string, string>();
  try {
    const db = getDb("XTHREAT");
    if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'").get()) {
      for (const r of db.prepare("SELECT AttackID AS id, Name AS name FROM ATTACKTECHNIQUE WHERE AttackID LIKE 'T%'").all() as { id: string; name: string }[])
        m.set(r.id.toUpperCase(), r.name);
    }
  } catch { /* empty catalogue */ }
  return m;
}

// Curated lexicon of distinctive TTP phrases → technique id + weight (specificity). Multi-word
// phrases score higher. Covers the common techniques TRAM's default model targets.
const LEXICON: { re: RegExp; id: string; w: number }[] = [
  { re: /spear.?phishing link|phishing link/i, id: "T1566.002", w: 0.9 },
  { re: /(spear.?phishing|phishing)[^.!?]{0,80}\b(link|url)\b|\b(link|url)\b[^.!?]{0,80}(spear.?phishing|phishing)/i, id: "T1566.002", w: 0.82 },
  { re: /spear.?phishing attachment|malicious attachment|weaponized document/i, id: "T1566.001", w: 0.9 },
  { re: /(spear.?phishing|phishing)[^.!?]{0,80}\b(attachment|document|\.docx?|\.xlsx?|\.pdf)\b/i, id: "T1566.001", w: 0.8 },
  { re: /spear.?phishing|phishing e-?mail|phishing campaign/i, id: "T1566", w: 0.82 },
  { re: /macro|vba|malicious document|maldoc/i, id: "T1566.001", w: 0.6 },
  { re: /powershell|pwsh|-enc |encodedcommand/i, id: "T1059.001", w: 0.9 },
  { re: /\bcmd\.exe|command shell|batch script/i, id: "T1059.003", w: 0.75 },
  { re: /wscript|cscript|jscript|vbscript/i, id: "T1059.005", w: 0.7 },
  { re: /python script|\.py\b/i, id: "T1059.006", w: 0.55 },
  { re: /obfuscat|base64|encoded (payload|command|string)|packed/i, id: "T1027", w: 0.7 },
  { re: /scheduled task|schtasks|cron job/i, id: "T1053.005", w: 0.85 },
  { re: /registry run key|run key|currentversion\\\\run|startup folder/i, id: "T1547.001", w: 0.85 },
  { re: /new service|creates? a service|service persistence/i, id: "T1543.003", w: 0.8 },
  { re: /wmi|windows management instrumentation/i, id: "T1047", w: 0.8 },
  { re: /rundll32/i, id: "T1218.011", w: 0.85 },
  { re: /regsvr32/i, id: "T1218.010", w: 0.85 },
  { re: /mshta/i, id: "T1218.005", w: 0.85 },
  { re: /lsass|sekurlsa|credential dump/i, id: "T1003.001", w: 0.85 },
  { re: /mimikatz/i, id: "T1003", w: 0.8 },
  { re: /ntds\.dit|ntds/i, id: "T1003.003", w: 0.85 },
  { re: /keylog/i, id: "T1056.001", w: 0.8 },
  { re: /brute.?force|password spray/i, id: "T1110", w: 0.8 },
  { re: /pass.the.hash/i, id: "T1550.002", w: 0.85 },
  { re: /kerberoast/i, id: "T1558.003", w: 0.9 },
  { re: /golden ticket/i, id: "T1558.001", w: 0.9 },
  { re: /remote desktop|\brdp\b/i, id: "T1021.001", w: 0.8 },
  { re: /\bsmb\b|admin\$|c\$ share|windows admin shares/i, id: "T1021.002", w: 0.75 },
  { re: /ssh\b/i, id: "T1021.004", w: 0.6 },
  { re: /psexec|remote service/i, id: "T1569.002", w: 0.75 },
  { re: /lateral move/i, id: "T1021", w: 0.65 },
  { re: /net user .*\/add|create.* account|new local account/i, id: "T1136.001", w: 0.8 },
  { re: /disable.* (antivirus|defender|security)|tamper.* protection/i, id: "T1562.001", w: 0.85 },
  { re: /clear.* (event )?logs|wevtutil|delete.* logs/i, id: "T1070.001", w: 0.85 },
  { re: /vssadmin.* delete|delete.* shadow (copies|copy)|shadow copy deletion/i, id: "T1490", w: 0.9 },
  { re: /ransomware|encrypt.* files|files were encrypted|data encrypted for impact/i, id: "T1486", w: 0.85 },
  { re: /dns tunnel|dns (for )?c2|dns exfil/i, id: "T1071.004", w: 0.85 },
  { re: /https? (beacon|c2|command and control)|web protocol|http c2/i, id: "T1071.001", w: 0.7 },
  { re: /command and control|c2 (server|channel|infrastructure)|beacon/i, id: "T1071", w: 0.65 },
  { re: /exfiltrat.* over .*(c2|command and control|channel)/i, id: "T1041", w: 0.85 },
  { re: /exfiltrat|data theft|stole? data/i, id: "T1041", w: 0.6 },
  { re: /cloud storage|dropbox|mega\.nz|exfil.* to .*cloud/i, id: "T1567.002", w: 0.8 },
  { re: /discovery of|enumerat.* (systems|network|accounts|hosts)|system information discovery/i, id: "T1082", w: 0.6 },
  { re: /whoami|net group|net localgroup|account discovery/i, id: "T1087", w: 0.7 },
  { re: /net view|network share discovery|port scan|network scan/i, id: "T1046", w: 0.7 },
  { re: /uac bypass|bypass.* user account control/i, id: "T1548.002", w: 0.85 },
  { re: /token (manipulation|impersonation)|steal.* token/i, id: "T1134", w: 0.8 },
  { re: /process injection|inject.* into .*process|hollowing/i, id: "T1055", w: 0.8 },
  { re: /dll side.?load|dll search order/i, id: "T1574.002", w: 0.85 },
  { re: /living off the land|lolbin|lolbas/i, id: "T1218", w: 0.6 },
  { re: /web shell|webshell/i, id: "T1505.003", w: 0.9 },
  { re: /valid accounts|stolen credentials|compromised account/i, id: "T1078", w: 0.65 },
];

function clamp(n: number): number { return Math.max(0, Math.min(0.98, n)); }

export function splitSentences(text: string): string[] {
  return (text || "")
    .replace(/\r/g, "")
    .split(/(?<=[.!?])\s+(?=[A-Z0-9"'])|\n+/)
    .map((s) => s.trim())
    .filter((s) => s.length >= 20 && /[a-z]/i.test(s))
    .slice(0, 300);
}

/** Deterministic keyword/name matching of one sentence against the ATT&CK catalogue + lexicon. */
function keywordMap(sentence: string, cat: Map<string, string>): TechMapping[] {
  const found = new Map<string, number>(); // id -> confidence
  const low = sentence.toLowerCase();
  for (const { re, id, w } of LEXICON) {
    if (re.test(sentence)) found.set(id, Math.max(found.get(id) ?? 0, w));
  }
  // verbatim technique-name match (names ≥ 8 chars to avoid noise) → solid confidence
  for (const [id, name] of cat) {
    if (name && name.length >= 8 && low.includes(name.toLowerCase()))
      found.set(id, Math.max(found.get(id) ?? 0, 0.8));
  }
  return Array.from(found.entries())
    .map(([id, c]) => ({ attackId: id, name: cat.get(id) || id, confidence: clamp(c), source: "keyword" }))
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 5);
}

function stripFences(s: string): string { return (s || "").replace(/^```[a-z]*\s*/i, "").replace(/```\s*$/m, "").trim(); }

/** Ask the local model to map sentences → techniques; returns order→mappings, validated vs catalogue. */
async function aiMap(sentences: string[], cat: Map<string, string>): Promise<Map<number, TechMapping[]>> {
  const out = new Map<number, TechMapping[]>();
  const numbered = sentences.map((s, i) => `${i}: ${s}`).join("\n");
  const sys = "You are a CTI analyst mapping threat-report sentences to MITRE ATT&CK techniques. "
    + "Return ONLY a JSON array (no prose, no code fences) of objects "
    + "{\"sentence\": <int index>, \"attackId\": \"Txxxx[.yyy]\", \"confidence\": <0..1>}. "
    + "Only include a mapping when the sentence clearly describes that technique. Use real ATT&CK ids.";
  const user = `Map these sentences (each prefixed by its index):\n${numbered}`;
  let raw = "";
  try { raw = stripFences(await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user }], 0.1, 120000)); }
  catch { return out; }
  let arr: unknown;
  try { arr = JSON.parse(raw); } catch {
    const m = raw.match(/\[[\s\S]*\]/); if (!m) return out;
    try { arr = JSON.parse(m[0]); } catch { return out; }
  }
  if (!Array.isArray(arr)) return out;
  for (const it of arr) {
    if (!it || typeof it !== "object") continue;
    const o = it as Record<string, unknown>;
    const idx = Number(o.sentence);
    const aid = String(o.attackId ?? o.attack_id ?? "").trim().toUpperCase();
    const conf = Number(o.confidence);
    if (!Number.isInteger(idx) || idx < 0 || idx >= sentences.length) continue;
    if (!/^T\d{4}(\.\d{3})?$/.test(aid)) continue;
    if (!cat.has(aid)) continue; // validate against the imported catalogue
    const list = out.get(idx) ?? [];
    list.push({ attackId: aid, name: cat.get(aid) || aid, confidence: clamp(Number.isFinite(conf) ? conf : 0.6), source: "ai" });
    out.set(idx, list);
  }
  return out;
}

function mergeMappings(base: TechMapping[], extra: TechMapping[]): TechMapping[] {
  const by = new Map<string, TechMapping>();
  for (const m of [...base, ...extra]) {
    const cur = by.get(m.attackId);
    if (!cur || m.confidence > cur.confidence) by.set(m.attackId, m);
  }
  return Array.from(by.values()).sort((a, b) => b.confidence - a.confidence);
}

/** Map a report's text to ATT&CK techniques. Keyword baseline always; AI merged when reachable. */
export async function mapReport(text: string, useAi = true): Promise<MapResult> {
  const cat = catalogue();
  const sents = splitSentences(text);
  const status = useAi ? await ollamaStatus() : { reachable: false } as { reachable: boolean };
  const ai = status.reachable ? await aiMap(sents, cat) : new Map<number, TechMapping[]>();
  const sentences: MappedSentence[] = sents.map((t, i) => ({
    order: i, text: t, mappings: mergeMappings(keywordMap(t, cat), ai.get(i) ?? []),
  }));
  const techniques = new Set<string>();
  let mapped = 0;
  for (const s of sentences) { if (s.mappings.length) mapped++; for (const m of s.mappings) techniques.add(m.attackId); }
  return {
    sentences,
    summary: {
      sentences: sentences.length, mapped, techniques: techniques.size,
      engine: status.reachable ? "keyword+ai" : "keyword", aiReachable: status.reachable,
    },
  };
}

// ── persistence ─────────────────────────────────────────────────────────────
function nowTs(): string { return new Date().toISOString().replace("T", " ").slice(0, 19); }

export interface SaveInput { name: string; reference?: string; text?: string; source?: string; mlModel?: string;
  sentences: { order: number; text: string; disposition?: string; mappings: { attackId: string; name?: string; confidence?: number }[] }[]; }

/** Save a mapped report → THREATREPORT (idempotent by source+reference) + REPORTMAPPING (rebuilt). */
export function saveReportMapping(inp: SaveInput): { reportId: number; mappings: number } {
  const db = getDb("XTHREAT");
  const source = (inp.source || "Report Mapper").slice(0, 100);
  const ref = (inp.reference || `report-mapper:${randomUUID()}`).slice(0, 400);
  const name = (inp.name || "Untitled report").slice(0, 300);
  const desc = (inp.text || "").slice(0, 4000) || null;
  const ai = inp.mlModel ? `Mapped by ${inp.mlModel}` : null;
  const hasAttack = !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'").get();

  const existing = db.prepare("SELECT ThreatReportID FROM THREATREPORT WHERE ThreatReportSource=? AND ThreatReportReference=?").get(source, ref) as { ThreatReportID: number } | undefined;
  let reportId: number;
  if (existing) {
    reportId = existing.ThreatReportID;
    db.prepare("UPDATE THREATREPORT SET ThreatReportName=?, ThreatReportDescription=?, AiSummary=? WHERE ThreatReportID=?").run(name, desc, ai, reportId);
    db.prepare("DELETE FROM REPORTMAPPING WHERE ThreatReportID=?").run(reportId);
  } else {
    const r = db.prepare(
      `INSERT INTO THREATREPORT (ThreatReportGUID, ThreatReportName, ThreatReportDescription, ThreatReportSource, ThreatReportReference, AiSummary, CreatedDate)
       VALUES (?,?,?,?,?,?,?)`,
    ).run(randomUUID(), name, desc, source, ref, ai, nowTs());
    reportId = Number(r.lastInsertRowid);
  }
  const insMap = db.prepare(
    `INSERT INTO REPORTMAPPING (ReportMappingGUID, ThreatReportID, AttackID, AttackTechniqueID, TechniqueName, Confidence, Sentence, SentenceOrder, Disposition, Source, MlModel, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
  );
  const techId = db.prepare("SELECT AttackTechniqueID AS id FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1");
  let n = 0;
  const tx = db.transaction(() => {
    for (const s of inp.sentences || []) {
      for (const m of s.mappings || []) {
        const aid = String(m.attackId || "").toUpperCase();
        if (!/^T\d{4}(\.\d{3})?$/.test(aid)) continue;
        const tid = hasAttack ? ((techId.get(aid) as { id: number } | undefined)?.id ?? null) : null;
        insMap.run(randomUUID(), reportId, aid, tid, (m.name || aid).slice(0, 200),
          typeof m.confidence === "number" ? Math.round(m.confidence * 10000) / 10000 : null,
          (s.text || "").slice(0, 2000), Number.isInteger(s.order) ? s.order : null,
          s.disposition || "accept", inp.source || "Report Mapper", inp.mlModel || null, nowTs());
        n++;
      }
    }
  });
  tx();
  return { reportId, mappings: n };
}

export interface MappedReport { id: number; name: string; source: string; created: string | null; mappings: number; techniques: number }

/** List saved reports that have ATT&CK mappings (for the studio + coverage). */
export function getMappedReports(limit = 100): MappedReport[] {
  const db = getDb("XTHREAT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='REPORTMAPPING'").get()) return [];
  return db.prepare(
    `SELECT r.ThreatReportID AS id, r.ThreatReportName AS name, r.ThreatReportSource AS source,
            r.CreatedDate AS created, COUNT(m.ReportMappingID) AS mappings, COUNT(DISTINCT m.AttackID) AS techniques
     FROM THREATREPORT r JOIN REPORTMAPPING m ON m.ThreatReportID = r.ThreatReportID
     GROUP BY r.ThreatReportID ORDER BY r.ThreatReportID DESC LIMIT ?`,
  ).all(limit) as MappedReport[];
}

/** Export an ATT&CK Navigator layer for a saved report (max confidence per technique → score). */
export function navigatorLayer(reportId: number): Record<string, unknown> | null {
  const db = getDb("XTHREAT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='REPORTMAPPING'").get()) return null;
  const rep = db.prepare("SELECT ThreatReportName AS name FROM THREATREPORT WHERE ThreatReportID=?").get(reportId) as { name: string } | undefined;
  if (!rep) return null;
  const rows = db.prepare(
    "SELECT AttackID AS id, MAX(Confidence) AS conf FROM REPORTMAPPING WHERE ThreatReportID=? GROUP BY AttackID",
  ).all(reportId) as { id: string; conf: number | null }[];
  const techniques = rows.map((r) => ({
    techniqueID: r.id, score: Math.round((r.conf ?? 0.5) * 100), enabled: true,
    comment: "Mapped from report by XORCISM Report Mapper",
  }));
  return {
    name: `TRAM — ${rep.name}`.slice(0, 120), versions: { attack: "15", navigator: "5.0.0", layer: "4.5" },
    domain: "enterprise-attack", description: `ATT&CK techniques mapped from "${rep.name}".`,
    techniques, gradient: { colors: ["#ffe766", "#ff6666"], minValue: 0, maxValue: 100 },
    legendItems: [], sorting: 3, hideDisabled: true,
  };
}
