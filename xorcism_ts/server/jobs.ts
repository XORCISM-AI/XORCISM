/**
 * jobs.ts — Connector job queue (XJOB.db), shared with the Python runner.
 * The web server creates jobs (status 'queued'); the Python worker claims them,
 * runs, parses, imports and updates the status/log.
 */

import Database from "better-sqlite3";
import path from "path";
import crypto from "crypto";

const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";

function sha256(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

let db: Database.Database | null = null;

export function getJobDb(): Database.Database {
  if (db) return db;
  db = new Database(path.join(DB_DIR, "XJOB.db"));
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.exec(
    `CREATE TABLE IF NOT EXISTS XJOB(
       JobID INTEGER PRIMARY KEY AUTOINCREMENT,
       connector TEXT NOT NULL, params TEXT, target TEXT, engagement_id INTEGER,
       status TEXT NOT NULL DEFAULT 'queued', user_id INTEGER,
       created_at TEXT, started_at TEXT, finished_at TEXT,
       exit_code INTEGER, log TEXT, result_summary TEXT, error TEXT);
     CREATE TABLE IF NOT EXISTS XENGAGEMENT(
       EngagementID INTEGER PRIMARY KEY AUTOINCREMENT,
       name TEXT NOT NULL, scope TEXT, active INTEGER DEFAULT 1,
       roe TEXT, created_at TEXT, created_by INTEGER);
     CREATE TABLE IF NOT EXISTS XWORKER(
       WorkerID INTEGER PRIMARY KEY AUTOINCREMENT,
       name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL,
       kind TEXT DEFAULT 'remote', capabilities TEXT, status TEXT DEFAULT 'idle',
       last_seen TEXT, created_at TEXT, created_by INTEGER);
     CREATE TABLE IF NOT EXISTS XSCHEDULE(
       ScheduleID INTEGER PRIMARY KEY AUTOINCREMENT,
       connector TEXT NOT NULL, params TEXT, target TEXT, engagement_id INTEGER,
       worker TEXT, cron TEXT NOT NULL, enabled INTEGER DEFAULT 1,
       created_at TEXT, created_by INTEGER, last_run_at TEXT, last_job_id INTEGER, run_count INTEGER DEFAULT 0)`
  );
  // Best-effort migrations (older XJOB databases)
  const cols = (db.prepare(`PRAGMA table_info("XJOB")`).all() as { name: string }[]).map((c) => c.name);
  for (const [c, def] of [["engagement_id", "INTEGER"], ["worker", "TEXT"], ["result_json", "TEXT"]] as const) {
    if (!cols.includes(c)) {
      try { db.prepare(`ALTER TABLE "XJOB" ADD COLUMN ${c} ${def}`).run(); } catch { /* ignore */ }
    }
  }
  return db;
}

export interface Engagement {
  EngagementID: number;
  name: string;
  scope: string | null;   // JSON array of host/CIDR/domain
  active: number;
  roe: string | null;
  created_at: string | null;
}

export function listEngagements(activeOnly = false): Engagement[] {
  const sql = activeOnly
    ? "SELECT * FROM XENGAGEMENT WHERE active=1 ORDER BY EngagementID DESC"
    : "SELECT * FROM XENGAGEMENT ORDER BY active DESC, EngagementID DESC";
  return getJobDb().prepare(sql).all() as Engagement[];
}

export function getEngagement(id: number): Engagement | undefined {
  return getJobDb().prepare("SELECT * FROM XENGAGEMENT WHERE EngagementID=?").get(id) as Engagement | undefined;
}

export function createEngagement(name: string, scope: string[], roe: string, userId: number): number {
  const info = getJobDb()
    .prepare("INSERT INTO XENGAGEMENT (name, scope, active, roe, created_at, created_by) VALUES (?,?,1,?,?,?)")
    .run(name, JSON.stringify(scope), roe || null, nowSql(), userId);
  return Number(info.lastInsertRowid);
}

export function setEngagementActive(id: number, active: boolean): void {
  getJobDb().prepare("UPDATE XENGAGEMENT SET active=? WHERE EngagementID=?").run(active ? 1 : 0, id);
}

/**
 * Creates or refreshes (by unique name) an engagement's scope/ROE and activates it.
 * Used by the Pentesting module to keep one backing ROE engagement per audit
 * rather than proliferating engagements on every scan.
 */
export function upsertEngagementByName(name: string, scope: string[], roe: string, userId: number): number {
  const db = getJobDb();
  const ex = db.prepare("SELECT EngagementID FROM XENGAGEMENT WHERE name=?").get(name) as { EngagementID: number } | undefined;
  if (ex) {
    db.prepare("UPDATE XENGAGEMENT SET scope=?, roe=?, active=1 WHERE EngagementID=?")
      .run(JSON.stringify(scope), roe || null, ex.EngagementID);
    return ex.EngagementID;
  }
  return createEngagement(name, scope, roe, userId);
}

export interface Job {
  JobID: number;
  connector: string;
  params: string | null;
  target: string | null;
  status: string;
  user_id: number | null;
  worker: string | null;
  result_json: string | null;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  log: string | null;
  result_summary: string | null;
  error: string | null;
}

function nowSql(): string {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

export function createJob(
  connector: string,
  params: unknown,
  target: string | null,
  userId: number,
  engagementId: number | null = null,
  worker: string | null = null
): number {
  const info = getJobDb()
    .prepare(
      `INSERT INTO XJOB (connector, params, target, engagement_id, worker, status, user_id, created_at)
       VALUES (?,?,?,?,?,'queued',?,?)`
    )
    .run(connector, JSON.stringify(params ?? {}), target, engagementId, worker, userId, nowSql());
  return Number(info.lastInsertRowid);
}

/**
 * Creates an already-"collected" job: a normalized result ready to be imported by the
 * local runner (import_findings → ASSET / CPE / CPEFORASSET / ASSETVULNERABILITY).
 * Used by the XOR agent (inventory, vulnerabilities) — no tool execution.
 */
export function createCollectedJob(connector: string, result: unknown, target: string | null): number {
  const info = getJobDb()
    .prepare(
      `INSERT INTO XJOB (connector, params, target, status, result_json, created_at, finished_at)
       VALUES (?, '{}', ?, 'collected', ?, ?, ?)`
    )
    .run(connector, target, JSON.stringify(result ?? {}), nowSql(), nowSql());
  return Number(info.lastInsertRowid);
}

// ── Workers (remote agents) ─────────────────────────────────────────────────────

export interface Worker {
  WorkerID: number;
  name: string;
  kind: string;
  capabilities: string | null;   // JSON array of connector ids ("" / null = all)
  status: string;
  last_seen: string | null;
  created_at: string | null;
}

export function listWorkers(): Worker[] {
  return getJobDb()
    .prepare("SELECT WorkerID, name, kind, capabilities, status, last_seen, created_at FROM XWORKER ORDER BY name")
    .all() as Worker[];
}

// Creates a worker and returns the token IN CLEAR (shown only once)
export function createWorker(name: string, capabilities: string[], userId: number): { id: number; token: string } {
  const token = crypto.randomBytes(24).toString("hex");
  const info = getJobDb()
    .prepare(
      `INSERT INTO XWORKER (name, token_hash, kind, capabilities, status, created_at, created_by)
       VALUES (?,?,'remote',?, 'idle', ?, ?)`
    )
    .run(name, sha256(token), capabilities.length ? JSON.stringify(capabilities) : null, nowSql(), userId);
  return { id: Number(info.lastInsertRowid), token };
}

export function deleteWorker(id: number): void {
  getJobDb().prepare("DELETE FROM XWORKER WHERE WorkerID=?").run(id);
}

export function getWorkerByToken(token: string): Worker | undefined {
  return getJobDb()
    .prepare("SELECT * FROM XWORKER WHERE token_hash=?")
    .get(sha256(token)) as Worker | undefined;
}

export function touchWorker(name: string, status = "idle"): void {
  getJobDb().prepare("UPDATE XWORKER SET last_seen=?, status=? WHERE name=?").run(nowSql(), status, name);
}

/**
 * Atomically claims a 'queued' job explicitly assigned to the remote worker `name`.
 * (Unassigned jobs stay with the local runner — deterministic separation.)
 * Respects the capabilities (supported connectors) when they are defined.
 */
export function claimRemoteJob(name: string, capabilities: string[]): Job | undefined {
  const d = getJobDb();
  const tx = d.transaction(() => {
    let sql = `SELECT * FROM XJOB WHERE status='queued' AND worker = ?`;
    const args: unknown[] = [name];
    if (capabilities.length) {
      sql += ` AND connector IN (${capabilities.map(() => "?").join(",")})`;
      args.push(...capabilities);
    }
    sql += " ORDER BY JobID ASC LIMIT 1";
    const job = d.prepare(sql).get(...args) as Job | undefined;
    if (!job) return undefined;
    d.prepare("UPDATE XJOB SET status='running', started_at=?, worker=? WHERE JobID=?")
      .run(nowSql(), name, job.JobID);
    return { ...job, status: "running", worker: name } as Job;
  });
  return tx();
}

export function appendJobLog(jobId: number, chunk: string): void {
  getJobDb().prepare("UPDATE XJOB SET log = COALESCE(log,'') || ? WHERE JobID=?").run(chunk, jobId);
}

/**
 * A remote worker has finished the run+parse: store the normalized result.
 * status 'collected' = awaiting import by the local runner (DB access);
 * status 'error' = failure on the worker side.
 */
export function attachRemoteResult(
  jobId: number,
  ok: boolean,
  resultJson: string | null,
  exitCode: number | null,
  error: string | null
): void {
  getJobDb()
    .prepare(
      `UPDATE XJOB SET status=?, result_json=?, exit_code=?, error=?, finished_at=? WHERE JobID=?`
    )
    .run(ok ? "collected" : "error", resultJson, exitCode, error, nowSql(), jobId);
}

export function getJob(id: number): Job | undefined {
  return getJobDb().prepare("SELECT * FROM XJOB WHERE JobID = ?").get(id) as Job | undefined;
}

export function listJobs(limit: number, userId?: number): Job[] {
  const cols =
    "JobID, connector, target, status, user_id, created_at, started_at, finished_at, exit_code, result_summary, error";
  if (userId != null) {
    return getJobDb()
      .prepare(`SELECT ${cols} FROM XJOB WHERE user_id = ? ORDER BY JobID DESC LIMIT ?`)
      .all(userId, limit) as Job[];
  }
  return getJobDb()
    .prepare(`SELECT ${cols} FROM XJOB ORDER BY JobID DESC LIMIT ?`)
    .all(limit) as Job[];
}

// ── Scheduled tasks (cron recurrence) ──────────────────────────────────────────

export interface Schedule {
  ScheduleID: number;
  connector: string;
  params: string | null;
  target: string | null;
  engagement_id: number | null;
  worker: string | null;
  cron: string;
  enabled: number;
  created_at: string | null;
  created_by: number | null;
  last_run_at: string | null;
  last_job_id: number | null;
  run_count: number;
}

export function createSchedule(opts: {
  connector: string;
  params: unknown;
  target: string | null;
  engagementId: number | null;
  worker: string | null;
  cron: string;
  userId: number;
}): number {
  const info = getJobDb()
    .prepare(
      `INSERT INTO XSCHEDULE (connector, params, target, engagement_id, worker, cron, enabled, created_at, created_by)
       VALUES (?,?,?,?,?,?,1,?,?)`
    )
    .run(opts.connector, JSON.stringify(opts.params ?? {}), opts.target, opts.engagementId,
      opts.worker, opts.cron, nowSql(), opts.userId);
  return Number(info.lastInsertRowid);
}

export function listSchedules(userId?: number): Schedule[] {
  if (userId != null) {
    return getJobDb()
      .prepare("SELECT * FROM XSCHEDULE WHERE created_by = ? ORDER BY ScheduleID DESC")
      .all(userId) as Schedule[];
  }
  return getJobDb().prepare("SELECT * FROM XSCHEDULE ORDER BY ScheduleID DESC").all() as Schedule[];
}

export function listEnabledSchedules(): Schedule[] {
  return getJobDb().prepare("SELECT * FROM XSCHEDULE WHERE enabled = 1").all() as Schedule[];
}

export function getSchedule(id: number): Schedule | undefined {
  return getJobDb().prepare("SELECT * FROM XSCHEDULE WHERE ScheduleID = ?").get(id) as Schedule | undefined;
}

export function setScheduleEnabled(id: number, enabled: boolean): void {
  getJobDb().prepare("UPDATE XSCHEDULE SET enabled = ? WHERE ScheduleID = ?").run(enabled ? 1 : 0, id);
}

export function deleteSchedule(id: number): void {
  getJobDb().prepare("DELETE FROM XSCHEDULE WHERE ScheduleID = ?").run(id);
}

export function markScheduleRun(id: number, jobId: number, at: string): void {
  getJobDb()
    .prepare("UPDATE XSCHEDULE SET last_run_at = ?, last_job_id = ?, run_count = run_count + 1 WHERE ScheduleID = ?")
    .run(at, jobId, id);
}

/** Minute "YYYY-MM-DD HH:MM" of a SQL timestamp (to avoid double firing). */
export function minuteOf(sql: string | null): string | null {
  return sql ? sql.slice(0, 16) : null;
}

export function sqlNow(): string {
  return nowSql();
}
