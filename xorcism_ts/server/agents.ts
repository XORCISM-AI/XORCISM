/**
 * agents.ts — "XOR" endpoint agent store (enhanced EDR).
 * XAGENT.db database:
 *   XAGENT       — enrolled endpoints (token, OS, last contact, linked asset)
 *   XAGENTEVENT  — reported events (AV detection, hunting hit, EDR, compliance)
 *   XAGENTJOB    — commands sent to the agent ("run a scan" from ASSET)
 *   XIOC         — indicators of compromise (fed by CTI: XTHREAT, OTX/AlienVault
 *                  connectors, feeds, STIX/TAXII) served to the agents
 */
import Database from "better-sqlite3";
import path from "path";
import crypto from "crypto";

const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";
const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
const nowSql = () => new Date().toISOString().replace("T", " ").slice(0, 19);

let db: Database.Database | null = null;
export function getAgentDb(): Database.Database {
  if (db) return db;
  db = new Database(path.join(DB_DIR, "XAGENT.db"));
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.exec(`
    CREATE TABLE IF NOT EXISTS XAGENT(
      AgentID INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL, asset_name TEXT,
      os TEXT, platform TEXT, version TEXT, ip TEXT, fqdn TEXT,
      status TEXT DEFAULT 'enrolled', enrolled_at TEXT, last_seen TEXT, intel_seen INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS XAGENTEVENT(
      EventID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT, type TEXT, severity TEXT, title TEXT, detail TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS XAGENTJOB(
      AgentJobID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT NOT NULL, kind TEXT NOT NULL, params TEXT,
      status TEXT DEFAULT 'pending', created_at TEXT, started_at TEXT, finished_at TEXT,
      result_summary TEXT, created_by INTEGER);
    CREATE TABLE IF NOT EXISTS XIOC(
      IOCID INTEGER PRIMARY KEY AUTOINCREMENT,
      ioc_type TEXT NOT NULL, value TEXT NOT NULL, source TEXT, threat TEXT,
      created_at TEXT, UNIQUE(ioc_type, value));
    CREATE TABLE IF NOT EXISTS FORENSICTRIAGE(
      TriageID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT, asset_name TEXT, host_os TEXT, collected_at TEXT,
      summary TEXT, artifacts TEXT, flag_count INTEGER DEFAULT 0, created_at TEXT);
    CREATE INDEX IF NOT EXISTS ix_agentevent_agent ON XAGENTEVENT(agent);
    CREATE INDEX IF NOT EXISTS ix_agentjob_agent ON XAGENTJOB(agent, status);
    CREATE INDEX IF NOT EXISTS ix_forensictriage_agent ON FORENSICTRIAGE(agent);
  `);
  return db;
}

export interface Agent {
  AgentID: number; name: string; asset_name: string | null; os: string | null;
  platform: string | null; version: string | null; ip: string | null; fqdn: string | null;
  status: string; enrolled_at: string | null; last_seen: string | null;
}

/** Enrols (or re-enrols) an endpoint and returns a token (shown to the agent once). */
export function enrollAgent(name: string, info: Record<string, string>): { token: string; agentId: number } {
  const d = getAgentDb();
  const token = crypto.randomBytes(24).toString("hex");
  const existing = d.prepare("SELECT AgentID FROM XAGENT WHERE name=?").get(name) as { AgentID: number } | undefined;
  if (existing) {
    d.prepare(`UPDATE XAGENT SET token_hash=?, os=?, platform=?, version=?, ip=?, fqdn=?, asset_name=?,
               status='enrolled', last_seen=? WHERE AgentID=?`)
      .run(sha256(token), info.os ?? null, info.platform ?? null, info.version ?? null,
           info.ip ?? null, info.fqdn ?? null, name, nowSql(), existing.AgentID);
    return { token, agentId: existing.AgentID };
  }
  const r = d.prepare(`INSERT INTO XAGENT(name, token_hash, asset_name, os, platform, version, ip, fqdn, enrolled_at, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(name, sha256(token), name, info.os ?? null, info.platform ?? null, info.version ?? null,
         info.ip ?? null, info.fqdn ?? null, nowSql(), nowSql());
  return { token, agentId: Number(r.lastInsertRowid) };
}

export function agentByToken(token: string): Agent | undefined {
  return getAgentDb().prepare("SELECT * FROM XAGENT WHERE token_hash=?").get(sha256(token)) as Agent | undefined;
}
export function touchAgent(name: string): void {
  getAgentDb().prepare("UPDATE XAGENT SET last_seen=?, status='online' WHERE name=?").run(nowSql(), name);
}
export function listAgents(): Agent[] {
  return getAgentDb().prepare("SELECT AgentID,name,asset_name,os,platform,version,ip,fqdn,status,enrolled_at,last_seen FROM XAGENT ORDER BY name").all() as Agent[];
}

export function addAgentEvent(agent: string, ev: { type: string; severity?: string; title?: string; detail?: unknown }): void {
  getAgentDb().prepare("INSERT INTO XAGENTEVENT(agent,type,severity,title,detail,created_at) VALUES (?,?,?,?,?,?)")
    .run(agent, ev.type, ev.severity ?? "info", ev.title ?? "", JSON.stringify(ev.detail ?? null), nowSql());
}
export function listAgentEvents(limit = 100, agent?: string): unknown[] {
  const d = getAgentDb();
  return agent
    ? d.prepare("SELECT * FROM XAGENTEVENT WHERE agent=? ORDER BY EventID DESC LIMIT ?").all(agent, limit)
    : d.prepare("SELECT * FROM XAGENTEVENT ORDER BY EventID DESC LIMIT ?").all(limit);
}

export interface ForensicBundle {
  os?: string; collectedAt?: string;
  summary?: Record<string, unknown>; flags?: { category: string; detail: string; severity?: string }[];
  artifacts?: Record<string, unknown>;
}
/** Persist a forensic-triage bundle posted by the agent (live DFIR snapshot). The full
 *  artifacts blob + a counts/flags summary are stored in FORENSICTRIAGE; the caller also
 *  emits a forensic_triage agent event so it surfaces in the events feed. */
export function storeForensicTriage(agent: string, asset: string | null, bundle: ForensicBundle): { triageId: number; flags: number } {
  const d = getAgentDb();
  const flags = Array.isArray(bundle.flags) ? bundle.flags : [];
  const r = d.prepare(
    "INSERT INTO FORENSICTRIAGE(agent,asset_name,host_os,collected_at,summary,artifacts,flag_count,created_at) VALUES (?,?,?,?,?,?,?,?)",
  ).run(agent, asset, bundle.os ?? null, bundle.collectedAt ?? nowSql(),
    JSON.stringify(bundle.summary ?? {}), JSON.stringify(bundle.artifacts ?? {}), flags.length, nowSql());
  return { triageId: Number(r.lastInsertRowid), flags: flags.length };
}
export function listForensicTriage(limit = 50, agent?: string): unknown[] {
  const d = getAgentDb();
  const sel = "TriageID,agent,asset_name,host_os,collected_at,summary,flag_count,created_at"; // omit the big artifacts blob in lists
  return agent
    ? d.prepare(`SELECT ${sel} FROM FORENSICTRIAGE WHERE agent=? ORDER BY TriageID DESC LIMIT ?`).all(agent, limit)
    : d.prepare(`SELECT ${sel} FROM FORENSICTRIAGE ORDER BY TriageID DESC LIMIT ?`).all(limit);
}
export function getForensicTriage(id: number): unknown {
  return getAgentDb().prepare("SELECT * FROM FORENSICTRIAGE WHERE TriageID=?").get(id);
}

/** "Run a scan" command for an agent (from the ASSET window). */
export function createAgentJob(agent: string, kind: string, params: unknown, userId: number | null): number {
  const r = getAgentDb().prepare("INSERT INTO XAGENTJOB(agent,kind,params,created_at,created_by) VALUES (?,?,?,?,?)")
    .run(agent, kind, JSON.stringify(params ?? {}), nowSql(), userId);
  return Number(r.lastInsertRowid);
}
/** Pending jobs for an agent → moved to 'sent'. */
export function claimAgentJobs(agent: string): { AgentJobID: number; kind: string; params: string }[] {
  const d = getAgentDb();
  const rows = d.prepare("SELECT AgentJobID,kind,params FROM XAGENTJOB WHERE agent=? AND status='pending' ORDER BY AgentJobID")
    .all(agent) as { AgentJobID: number; kind: string; params: string }[];
  for (const r of rows) d.prepare("UPDATE XAGENTJOB SET status='sent', started_at=? WHERE AgentJobID=?").run(nowSql(), r.AgentJobID);
  return rows;
}
export function finishAgentJob(id: number, summary: string): void {
  getAgentDb().prepare("UPDATE XAGENTJOB SET status='done', finished_at=?, result_summary=? WHERE AgentJobID=?")
    .run(nowSql(), summary, id);
}
export function listAgentJobs(agent?: string, limit = 50): unknown[] {
  const d = getAgentDb();
  return agent
    ? d.prepare("SELECT * FROM XAGENTJOB WHERE agent=? ORDER BY AgentJobID DESC LIMIT ?").all(agent, limit)
    : d.prepare("SELECT * FROM XAGENTJOB ORDER BY AgentJobID DESC LIMIT ?").all(limit);
}

// ── IOC (threat intelligence served to the agents) ───────────────────────────────
export function upsertIocs(iocs: { ioc_type: string; value: string; source?: string; threat?: string }[]): number {
  const d = getAgentDb();
  const ins = d.prepare("INSERT OR IGNORE INTO XIOC(ioc_type,value,source,threat,created_at) VALUES (?,?,?,?,?)");
  let n = 0;
  const tx = d.transaction(() => {
    for (const i of iocs) {
      if (!i.ioc_type || !i.value) continue;
      n += ins.run(i.ioc_type.toLowerCase(), String(i.value).trim(), i.source ?? null, i.threat ?? null, nowSql()).changes;
    }
  });
  tx();
  return n;
}
export function listIocs(): { ioc_type: string; value: string; threat: string | null }[] {
  return getAgentDb().prepare("SELECT ioc_type,value,threat FROM XIOC").all() as { ioc_type: string; value: string; threat: string | null }[];
}
export function iocCount(): number {
  return (getAgentDb().prepare("SELECT COUNT(*) c FROM XIOC").get() as { c: number }).c;
}
