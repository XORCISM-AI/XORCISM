/**
 * xid.ts — XID database: users, roles, permissions (RBAC/CRUD),
 * sessions and audit log. Accessed via better-sqlite3 (synchronous).
 */

import Database from "better-sqlite3";
import path from "path";
import fs from "fs";

// Same location as db.ts: OUTSIDE OneDrive (cf. note in db.ts).
// Overridable via DB_DIR.
const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";
const XID_PATH = path.join(DB_DIR, "XID.db");

let _db: Database.Database | null = null;

export function getXidDb(): Database.Database {
  if (_db) return _db;
  const db = new Database(XID_PATH); // creates the file if missing
  // DELETE mode (no -wal file): writes are immediately durable in
  // the .db — avoids the regressions caused by OneDrive mis-syncing the WAL.
  db.pragma("journal_mode = DELETE");
  db.pragma("synchronous = FULL");
  db.pragma("foreign_keys = ON");
  _db = db;
  ensureSchema(db);
  return db;
}

function ensureSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS XUSER (
      UserID INTEGER PRIMARY KEY AUTOINCREMENT,
      Email TEXT NOT NULL,
      LoweredEmail TEXT NOT NULL UNIQUE,
      DisplayName TEXT,
      PasswordHash TEXT NOT NULL,
      IsApproved INTEGER NOT NULL DEFAULT 1,
      IsLockedOut INTEGER NOT NULL DEFAULT 0,
      MustChangePassword INTEGER NOT NULL DEFAULT 0,
      FailedPasswordAttemptCount INTEGER NOT NULL DEFAULT 0,
      FailedPasswordWindowStart TEXT,
      LastLoginDate TEXT,
      LastPasswordChangedDate TEXT,
      CreatedDate TEXT,
      CreatedByUserID INTEGER,
      Comment TEXT
    );

    CREATE TABLE IF NOT EXISTS XROLE (
      RoleID INTEGER PRIMARY KEY AUTOINCREMENT,
      RoleName TEXT NOT NULL UNIQUE,
      RoleDescription TEXT,
      CreatedDate TEXT
    );

    CREATE TABLE IF NOT EXISTS XUSERROLE (
      UserRoleID INTEGER PRIMARY KEY AUTOINCREMENT,
      UserID INTEGER NOT NULL,
      RoleID INTEGER NOT NULL,
      UNIQUE(UserID, RoleID)
    );

    CREATE TABLE IF NOT EXISTS XPERMISSION (
      PermissionID INTEGER PRIMARY KEY AUTOINCREMENT,
      RoleID INTEGER NOT NULL,
      ResourceType TEXT NOT NULL,   -- 'page' | 'database' | 'table' | 'field'
      ResourceKey TEXT NOT NULL,    -- '/', 'XORCISM', 'XORCISM.CWE', 'XORCISM.CWE.CWEName'
      CanCreate INTEGER NOT NULL DEFAULT 0,
      CanRead INTEGER NOT NULL DEFAULT 0,
      CanUpdate INTEGER NOT NULL DEFAULT 0,
      CanDelete INTEGER NOT NULL DEFAULT 0,
      CreatedDate TEXT,
      UNIQUE(RoleID, ResourceType, ResourceKey)
    );

    CREATE TABLE IF NOT EXISTS XSESSION (
      SessionID TEXT PRIMARY KEY,   -- SHA-256(token) ; the raw token stays in the cookie
      UserID INTEGER NOT NULL,
      CreatedDate TEXT NOT NULL,
      ExpiresDate TEXT NOT NULL,
      LastSeenDate TEXT,
      IP TEXT,
      UserAgent TEXT
    );

    CREATE TABLE IF NOT EXISTS XAUDITLOG (
      AuditID INTEGER PRIMARY KEY AUTOINCREMENT,
      UserID INTEGER,
      Action TEXT NOT NULL,
      ResourceType TEXT,
      ResourceKey TEXT,
      Detail TEXT,
      IP TEXT,
      Timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS XTENANT (
      TenantID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantName TEXT NOT NULL UNIQUE,
      IsSystem INTEGER NOT NULL DEFAULT 0,
      IsActive INTEGER NOT NULL DEFAULT 1,
      CreatedDate TEXT
    );

    CREATE TABLE IF NOT EXISTS XPASSWORDRESET (
      ResetID INTEGER PRIMARY KEY AUTOINCREMENT,
      UserID INTEGER NOT NULL, TokenHash TEXT NOT NULL UNIQUE,
      ExpiresDate TEXT NOT NULL, UsedDate TEXT, CreatedDate TEXT
    );

    CREATE TABLE IF NOT EXISTS XFEEDBACK (
      FeedbackID INTEGER PRIMARY KEY AUTOINCREMENT,
      UserID INTEGER, Email TEXT, Type TEXT NOT NULL DEFAULT 'rating',
      FeatureKey TEXT, Rating INTEGER, Title TEXT, Message TEXT,
      Status TEXT NOT NULL DEFAULT 'new', CreatedDate TEXT
    );

    CREATE TABLE IF NOT EXISTS XUSERPREF (
      UserID INTEGER NOT NULL,
      PrefKey TEXT NOT NULL,
      PrefValue TEXT,
      ModifiedDate TEXT,
      PRIMARY KEY (UserID, PrefKey)
    );

    -- Passkeys (WebAuthn / FIDO2): credentials registered per user
    CREATE TABLE IF NOT EXISTS XWEBAUTHN (
      CredentialID TEXT PRIMARY KEY,   -- credential identifier (base64url)
      UserID INTEGER NOT NULL,
      PublicKeyJwk TEXT NOT NULL,      -- public key in JWK format (JSON)
      Alg INTEGER NOT NULL,            -- COSE algorithm (-7 ES256 / -257 RS256)
      SignCount INTEGER NOT NULL DEFAULT 0,
      Transports TEXT,
      Aaguid TEXT,
      Name TEXT,
      CreatedDate TEXT,
      LastUsedDate TEXT
    );

    CREATE INDEX IF NOT EXISTS ix_userrole_user ON XUSERROLE(UserID);
    CREATE INDEX IF NOT EXISTS ix_perm_role ON XPERMISSION(RoleID);
    CREATE INDEX IF NOT EXISTS ix_session_user ON XSESSION(UserID);
    CREATE INDEX IF NOT EXISTS ix_audit_user ON XAUDITLOG(UserID);
    CREATE INDEX IF NOT EXISTS ix_reset_user ON XPASSWORDRESET(UserID);
    CREATE INDEX IF NOT EXISTS ix_webauthn_user ON XWEBAUTHN(UserID);
  `);

  // Column migrations (multi-tenant) — idempotent.
  // GLOBAL roles (Admin/User); isolation is done via the user → tenant
  // membership and filtering of operational data.
  addColumnIfMissing(db, "XUSER", "TenantID", "INTEGER");
  addColumnIfMissing(db, "XUSER", "PinHash", "TEXT"); // PIN (scrambled keypad)
  addColumnIfMissing(db, "XAUDITLOG", "TenantID", "INTEGER");
  db.exec("CREATE INDEX IF NOT EXISTS ix_user_tenant ON XUSER(TenantID);");
}

function addColumnIfMissing(
  db: Database.Database,
  table: string,
  column: string,
  ddlType: string
): void {
  const cols = db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[];
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE "${table}" ADD COLUMN "${column}" ${ddlType}`);
  }
}

// ── Types ───────────────────────────────────────────────────────────────────

export interface XUser {
  UserID: number;
  Email: string;
  LoweredEmail: string;
  DisplayName: string | null;
  PasswordHash: string;
  IsApproved: number;
  IsLockedOut: number;
  MustChangePassword: number;
  FailedPasswordAttemptCount: number;
  FailedPasswordWindowStart: string | null;
  LastLoginDate: string | null;
  TenantID: number | null;
  PinHash: string | null;
}

export interface Tenant {
  TenantID: number;
  TenantName: string;
  IsSystem: number;
  IsActive: number;
}

export interface Permission {
  ResourceType: string;
  ResourceKey: string;
  CanCreate: number;
  CanRead: number;
  CanUpdate: number;
  CanDelete: number;
}

function now(): string {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

// ── Users ────────────────────────────────────────────────────────────

export function findUserByEmail(email: string): XUser | undefined {
  return getXidDb()
    .prepare("SELECT * FROM XUSER WHERE LoweredEmail = ?")
    .get(email.trim().toLowerCase()) as XUser | undefined;
}

export function getUserById(id: number): XUser | undefined {
  return getXidDb().prepare("SELECT * FROM XUSER WHERE UserID = ?").get(id) as
    | XUser
    | undefined;
}

export function createUser(opts: {
  email: string;
  displayName?: string;
  passwordHash: string;
  mustChange?: boolean;
  createdBy?: number | null;
  tenantId?: number | null;
}): number {
  const db = getXidDb();
  const info = db
    .prepare(
      `INSERT INTO XUSER (Email, LoweredEmail, DisplayName, PasswordHash,
         MustChangePassword, CreatedDate, CreatedByUserID, LastPasswordChangedDate, TenantID)
       VALUES (?,?,?,?,?,?,?,?,?)`
    )
    .run(
      opts.email.trim(),
      opts.email.trim().toLowerCase(),
      opts.displayName ?? null,
      opts.passwordHash,
      opts.mustChange ? 1 : 0,
      now(),
      opts.createdBy ?? null,
      now(),
      opts.tenantId ?? null
    );
  createPersonForUser(opts.displayName ?? null, opts.email.trim(), opts.tenantId ?? null);
  return Number(info.lastInsertRowid);
}

/**
 * Creates the PERSON record (XORCISM database) associated with a new user:
 * display name → FirstName + FullName, e-mail → email. Then links that person to
 * the user's organisation (PERSONFORORGANISATION). Best-effort: must never make
 * account creation fail (database locked by an import…). Idempotent on both the
 * PERSON (by e-mail) and the PERSONFORORGANISATION link (by person+organisation).
 */
function createPersonForUser(displayName: string | null, email: string, tenantId: number | null): void {
  try {
    const xdb = new Database(path.join(DB_DIR, "XORCISM.db"));
    try {
      xdb.pragma("busy_timeout = 5000");
      // PERSON: idempotent by e-mail (re-seed, OIDC…). Resolve the id either way.
      let personId = (
        xdb.prepare(`SELECT PersonID FROM "PERSON" WHERE email = ? COLLATE NOCASE`).get(email) as
          { PersonID: number } | undefined
      )?.PersonID;
      if (!personId) {
        personId = (
          xdb.prepare(`SELECT COALESCE(MAX(PersonID),0)+1 AS n FROM "PERSON"`).get() as { n: number }
        ).n;
        xdb
          .prepare(
            `INSERT INTO "PERSON" (PersonID, FirstName, FullName, email, CreatedDate)
             VALUES (?,?,?,?,?)`
          )
          .run(personId, displayName, displayName, email, now());
      }
      linkPersonToOrganisation(xdb, personId, tenantId);
    } finally {
      xdb.close();
    }
  } catch (e) {
    console.warn("[xid] création PERSON/PERSONFORORGANISATION impossible :", (e as Error).message);
  }
}

/**
 * Links a PERSON to the user's organisation via PERSONFORORGANISATION. The XID
 * model has no direct organisation, so we resolve it from the user's tenant name
 * (matching ORGANISATION name / known-as), falling back to the lowest
 * OrganisationID. Idempotent: skips if the (person, organisation) link exists.
 * Fixed attributes per spec: relationshiptype="User", ConfidenceLevelID=3,
 * TrustLevelID=2, CreatedDate=now, ValidFromDate=today.
 */
function linkPersonToOrganisation(
  xdb: InstanceType<typeof Database>,
  personId: number,
  tenantId: number | null
): void {
  if (!xdb.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ORGANISATION'").get()) return;
  if (!xdb.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='PERSONFORORGANISATION'").get()) return;
  let orgId: number | null = null;
  // 1. tenant name ↔ organisation name / known-as
  if (tenantId) {
    const ten = getXidDb()
      .prepare("SELECT TenantName FROM XTENANT WHERE TenantID = ?")
      .get(tenantId) as { TenantName?: string } | undefined;
    const tn = (ten?.TenantName || "").trim().toLowerCase();
    if (tn) {
      const org = xdb
        .prepare("SELECT OrganisationID FROM ORGANISATION WHERE LOWER(OrganisationName)=? OR LOWER(OrganisationKnownAs)=?")
        .get(tn, tn) as { OrganisationID: number } | undefined;
      if (org) orgId = org.OrganisationID;
    }
  }
  // 2. fallback: lowest organisation id (never null when an organisation exists)
  if (orgId == null) {
    const first = xdb.prepare("SELECT MIN(OrganisationID) AS m FROM ORGANISATION").get() as { m: number | null };
    orgId = first && first.m != null ? first.m : null;
  }
  if (orgId == null) return;
  // idempotent: do not duplicate the (person, organisation) link
  if (xdb.prepare("SELECT 1 FROM PERSONFORORGANISATION WHERE PersonID=? AND OrganisationID=? LIMIT 1").get(personId, orgId))
    return;
  const nextId = (
    xdb.prepare("SELECT COALESCE(MAX(PersonOrganisationID),0)+1 AS n FROM PERSONFORORGANISATION").get() as { n: number }
  ).n;
  const today = new Date().toISOString().slice(0, 10);
  xdb
    .prepare(
      `INSERT INTO PERSONFORORGANISATION
         (PersonOrganisationID, PersonID, OrganisationID, relationshiptype,
          CreatedDate, ValidFromDate, ConfidenceLevelID, TrustLevelID)
       VALUES (?,?,?,?,?,?,?,?)`
    )
    .run(nextId, personId, orgId, "User", now(), today, 3, 2);
}

export function setPassword(userId: number, passwordHash: string, mustChange = 0): void {
  getXidDb()
    .prepare(
      `UPDATE XUSER SET PasswordHash=?, MustChangePassword=?,
         LastPasswordChangedDate=?, FailedPasswordAttemptCount=0, IsLockedOut=0
       WHERE UserID=?`
    )
    .run(passwordHash, mustChange, now(), userId);
}

/** Sets (or clears if null) a user's PIN hash. */
export function setUserPinHash(userId: number, pinHash: string | null): void {
  getXidDb().prepare("UPDATE XUSER SET PinHash=? WHERE UserID=?").run(pinHash, userId);
}

export function recordLoginSuccess(userId: number): void {
  getXidDb()
    .prepare(
      `UPDATE XUSER SET LastLoginDate=?, FailedPasswordAttemptCount=0,
         FailedPasswordWindowStart=NULL WHERE UserID=?`
    )
    .run(now(), userId);
}

/** Increments the failure counter; locks beyond the threshold. */
export function recordLoginFailure(userId: number, maxAttempts = 5): void {
  const db = getXidDb();
  const u = getUserById(userId);
  if (!u) return;
  const count = (u.FailedPasswordAttemptCount ?? 0) + 1;
  const locked = count >= maxAttempts ? 1 : u.IsLockedOut;
  db.prepare(
    `UPDATE XUSER SET FailedPasswordAttemptCount=?, IsLockedOut=?,
       FailedPasswordWindowStart=COALESCE(FailedPasswordWindowStart, ?) WHERE UserID=?`
  ).run(count, locked, now(), userId);
}

/** Lists users; if tenantId is provided, restricts to that tenant. */
export function listUsers(tenantId?: number | null): Record<string, unknown>[] {
  const db = getXidDb();
  if (tenantId != null) {
    return db
      .prepare(
        `SELECT UserID, Email, DisplayName, IsApproved, IsLockedOut,
                MustChangePassword, LastLoginDate, CreatedDate, TenantID
         FROM XUSER WHERE TenantID = ? ORDER BY LoweredEmail`
      )
      .all(tenantId) as Record<string, unknown>[];
  }
  return db
    .prepare(
      `SELECT u.UserID, u.Email, u.DisplayName, u.IsApproved, u.IsLockedOut,
              u.MustChangePassword, u.LastLoginDate, u.CreatedDate, u.TenantID,
              t.TenantName
       FROM XUSER u LEFT JOIN XTENANT t ON t.TenantID = u.TenantID
       ORDER BY u.LoweredEmail`
    )
    .all() as Record<string, unknown>[];
}

// ── Tenants ───────────────────────────────────────────────────────────────────

export function listTenants(): Tenant[] {
  return getXidDb().prepare("SELECT * FROM XTENANT ORDER BY IsSystem DESC, TenantName").all() as Tenant[];
}

export function getTenantById(id: number): Tenant | undefined {
  return getXidDb().prepare("SELECT * FROM XTENANT WHERE TenantID = ?").get(id) as
    | Tenant
    | undefined;
}

export function ensureTenant(name: string, isSystem = false): number {
  const db = getXidDb();
  const ex = db.prepare("SELECT TenantID FROM XTENANT WHERE TenantName = ?").get(name) as
    | { TenantID: number }
    | undefined;
  if (ex) return ex.TenantID;
  const info = db
    .prepare("INSERT INTO XTENANT (TenantName, IsSystem, IsActive, CreatedDate) VALUES (?,?,1,?)")
    .run(name, isSystem ? 1 : 0, now());
  return Number(info.lastInsertRowid);
}

export function setUserTenant(userId: number, tenantId: number): void {
  getXidDb().prepare("UPDATE XUSER SET TenantID = ? WHERE UserID = ?").run(tenantId, userId);
}

export function setTenantActive(tenantId: number, active: boolean): void {
  getXidDb().prepare("UPDATE XTENANT SET IsActive = ? WHERE TenantID = ?").run(active ? 1 : 0, tenantId);
}

export function setUserLock(userId: number, locked: boolean): void {
  getXidDb()
    .prepare("UPDATE XUSER SET IsLockedOut=?, FailedPasswordAttemptCount=0 WHERE UserID=?")
    .run(locked ? 1 : 0, userId);
}

// ── Roles ───────────────────────────────────────────────────────────────────

export function listRoles(): { RoleID: number; RoleName: string; RoleDescription: string | null }[] {
  return getXidDb().prepare("SELECT * FROM XROLE ORDER BY RoleName").all() as any;
}

export function ensureRole(name: string, description = ""): number {
  const db = getXidDb();
  const ex = db.prepare("SELECT RoleID FROM XROLE WHERE RoleName=?").get(name) as
    | { RoleID: number }
    | undefined;
  if (ex) return ex.RoleID;
  const info = db
    .prepare("INSERT INTO XROLE (RoleName, RoleDescription, CreatedDate) VALUES (?,?,?)")
    .run(name, description, now());
  return Number(info.lastInsertRowid);
}

export function getUserRoles(userId: number): { RoleID: number; RoleName: string }[] {
  return getXidDb()
    .prepare(
      `SELECT r.RoleID, r.RoleName FROM XROLE r
       JOIN XUSERROLE ur ON ur.RoleID = r.RoleID WHERE ur.UserID = ?`
    )
    .all(userId) as any;
}

export function assignRole(userId: number, roleId: number): void {
  getXidDb()
    .prepare("INSERT OR IGNORE INTO XUSERROLE (UserID, RoleID) VALUES (?,?)")
    .run(userId, roleId);
}

export function removeRole(userId: number, roleId: number): void {
  getXidDb().prepare("DELETE FROM XUSERROLE WHERE UserID=? AND RoleID=?").run(userId, roleId);
}

export function isAdmin(userId: number): boolean {
  return getUserRoles(userId).some((r) => r.RoleName === "Admin");
}

// ── Password reset (single-use token) ──────────────────────
import crypto from "crypto";
const sha256hex = (s: string) => crypto.createHash("sha256").update(s).digest("hex");

/** Creates a reset token (1 h) and returns the token IN CLEAR (to send by e-mail). */
export function createPasswordReset(userId: number): string {
  const token = crypto.randomBytes(32).toString("base64url");
  const exp = new Date(Date.now() + 3600 * 1000).toISOString().replace("T", " ").slice(0, 19);
  getXidDb()
    .prepare("INSERT INTO XPASSWORDRESET (UserID, TokenHash, ExpiresDate, CreatedDate) VALUES (?,?,?,?)")
    .run(userId, sha256hex(token), exp, now());
  return token;
}

/** Consumes a valid token; returns the UserID or null. */
export function consumePasswordReset(token: string): number | null {
  const db = getXidDb();
  const nowS = now();
  const row = db
    .prepare("SELECT ResetID, UserID FROM XPASSWORDRESET WHERE TokenHash=? AND UsedDate IS NULL AND ExpiresDate > ?")
    .get(sha256hex(token.trim()), nowS) as { ResetID: number; UserID: number } | undefined;
  if (!row) return null;
  db.prepare("UPDATE XPASSWORDRESET SET UsedDate=? WHERE ResetID=?").run(nowS, row.ResetID);
  return row.UserID;
}

// ── Feedback (feature ratings / improvement requests) ─────────────
export function addFeedback(f: {
  userId: number | null; email: string | null; type: string;
  featureKey?: string | null; rating?: number | null; title?: string | null; message?: string | null;
}): void {
  getXidDb()
    .prepare(`INSERT INTO XFEEDBACK (UserID,Email,Type,FeatureKey,Rating,Title,Message,Status,CreatedDate)
              VALUES (?,?,?,?,?,?,?, 'new', ?)`)
    .run(f.userId, f.email, f.type, f.featureKey ?? null, f.rating ?? null, f.title ?? null, f.message ?? null, now());
}
export function listFeedbackByUser(userId: number): unknown[] {
  return getXidDb().prepare("SELECT * FROM XFEEDBACK WHERE UserID=? ORDER BY FeedbackID DESC LIMIT 30").all(userId);
}
export function listAllFeedback(limit = 200): unknown[] {
  return getXidDb()
    .prepare(`SELECT f.*, u.DisplayName FROM XFEEDBACK f LEFT JOIN XUSER u ON u.UserID=f.UserID
              ORDER BY f.FeedbackID DESC LIMIT ?`).all(limit);
}
export function feedbackAverages(): { FeatureKey: string; avg: number; n: number }[] {
  return getXidDb()
    .prepare(`SELECT FeatureKey, ROUND(AVG(Rating),2) avg, COUNT(*) n FROM XFEEDBACK
              WHERE Type='rating' AND Rating IS NOT NULL GROUP BY FeatureKey`).all() as { FeatureKey: string; avg: number; n: number }[];
}
export function setFeedbackStatus(id: number, status: string): void {
  getXidDb().prepare("UPDATE XFEEDBACK SET Status=? WHERE FeedbackID=?").run(status, id);
}

// ── User preferences (key → JSON, e.g. CTI feeds of the Threat Feeds page) ───
export function getUserPref(userId: number, key: string): string | null {
  const r = getXidDb()
    .prepare("SELECT PrefValue FROM XUSERPREF WHERE UserID=? AND PrefKey=?")
    .get(userId, key) as { PrefValue: string | null } | undefined;
  return r?.PrefValue ?? null;
}
export function setUserPref(userId: number, key: string, value: string): void {
  getXidDb()
    .prepare(`INSERT INTO XUSERPREF (UserID,PrefKey,PrefValue,ModifiedDate) VALUES (?,?,?,?)
              ON CONFLICT(UserID,PrefKey) DO UPDATE SET PrefValue=excluded.PrefValue, ModifiedDate=excluded.ModifiedDate`)
    .run(userId, key, value, now());
}

/** Default tenant for a self-registered account: first active non-System tenant. */
export function firstNonSystemTenant(): number | null {
  const r = getXidDb()
    .prepare("SELECT TenantID FROM XTENANT WHERE IsSystem=0 AND IsActive=1 ORDER BY TenantID LIMIT 1")
    .get() as { TenantID: number } | undefined;
  return r?.TenantID ?? null;
}

// ── Permissions ─────────────────────────────────────────────────────────────

export function getRolePermissions(roleId: number): Permission[] {
  return getXidDb()
    .prepare("SELECT * FROM XPERMISSION WHERE RoleID=?")
    .all(roleId) as Permission[];
}

/** Aggregated permissions (logical OR over all the user's roles). */
export function getEffectivePermissions(userId: number): Map<string, Permission> {
  const db = getXidDb();
  const rows = db
    .prepare(
      `SELECT p.* FROM XPERMISSION p
       JOIN XUSERROLE ur ON ur.RoleID = p.RoleID WHERE ur.UserID = ?`
    )
    .all(userId) as Permission[];
  const map = new Map<string, Permission>();
  for (const p of rows) {
    const key = `${p.ResourceType}:${p.ResourceKey}`;
    const cur = map.get(key);
    if (!cur) {
      map.set(key, { ...p });
    } else {
      cur.CanCreate = cur.CanCreate || p.CanCreate;
      cur.CanRead = cur.CanRead || p.CanRead;
      cur.CanUpdate = cur.CanUpdate || p.CanUpdate;
      cur.CanDelete = cur.CanDelete || p.CanDelete;
    }
  }
  return map;
}

export function setPermission(
  roleId: number,
  resourceType: string,
  resourceKey: string,
  crud: { c: boolean; r: boolean; u: boolean; d: boolean }
): void {
  getXidDb()
    .prepare(
      `INSERT INTO XPERMISSION (RoleID, ResourceType, ResourceKey, CanCreate, CanRead, CanUpdate, CanDelete, CreatedDate)
       VALUES (?,?,?,?,?,?,?,?)
       ON CONFLICT(RoleID, ResourceType, ResourceKey) DO UPDATE SET
         CanCreate=excluded.CanCreate, CanRead=excluded.CanRead,
         CanUpdate=excluded.CanUpdate, CanDelete=excluded.CanDelete`
    )
    .run(
      roleId,
      resourceType,
      resourceKey,
      crud.c ? 1 : 0,
      crud.r ? 1 : 0,
      crud.u ? 1 : 0,
      crud.d ? 1 : 0,
      now()
    );
}

// ── Sessions ────────────────────────────────────────────────────────────────

export function createSession(opts: {
  sessionId: string;
  userId: number;
  expiresIso: string;
  ip?: string;
  ua?: string;
}): void {
  getXidDb()
    .prepare(
      `INSERT INTO XSESSION (SessionID, UserID, CreatedDate, ExpiresDate, LastSeenDate, IP, UserAgent)
       VALUES (?,?,?,?,?,?,?)`
    )
    .run(opts.sessionId, opts.userId, now(), opts.expiresIso, now(), opts.ip ?? null, opts.ua ?? null);
}

export function getSession(sessionId: string):
  | {
      SessionID: string;
      UserID: number;
      ExpiresDate: string;
      LastSeenDate: string | null;
      CreatedDate: string;
    }
  | undefined {
  return getXidDb()
    .prepare(
      "SELECT SessionID, UserID, ExpiresDate, LastSeenDate, CreatedDate FROM XSESSION WHERE SessionID=?"
    )
    .get(sessionId) as any;
}

export function touchSession(sessionId: string): void {
  getXidDb().prepare("UPDATE XSESSION SET LastSeenDate=? WHERE SessionID=?").run(now(), sessionId);
}

/** Rotation: re-assigns a new ID (token hash) to an existing session. */
export function rotateSession(oldId: string, newId: string): void {
  getXidDb()
    .prepare("UPDATE XSESSION SET SessionID=?, CreatedDate=?, LastSeenDate=? WHERE SessionID=?")
    .run(newId, now(), now(), oldId);
}

export function deleteSession(sessionId: string): void {
  getXidDb().prepare("DELETE FROM XSESSION WHERE SessionID=?").run(sessionId);
}

export function deleteUserSessions(userId: number): void {
  getXidDb().prepare("DELETE FROM XSESSION WHERE UserID=?").run(userId);
}

export function purgeExpiredSessions(): void {
  getXidDb()
    .prepare("DELETE FROM XSESSION WHERE ExpiresDate < ?")
    .run(new Date().toISOString().replace("T", " ").slice(0, 19));
}

// ── Passkeys (WebAuthn / FIDO2) ───────────────────────────────────────────

export interface WebauthnCredential {
  CredentialID: string;
  UserID: number;
  PublicKeyJwk: string;
  Alg: number;
  SignCount: number;
  Transports: string | null;
  Aaguid: string | null;
  Name: string | null;
  CreatedDate: string | null;
  LastUsedDate: string | null;
}

export function addWebauthnCredential(c: {
  credentialId: string; userId: number; publicKeyJwk: string; alg: number;
  signCount: number; transports?: string | null; aaguid?: string | null; name?: string | null;
}): void {
  getXidDb()
    .prepare(
      `INSERT INTO XWEBAUTHN (CredentialID, UserID, PublicKeyJwk, Alg, SignCount, Transports, Aaguid, Name, CreatedDate)
       VALUES (?,?,?,?,?,?,?,?,?)`
    )
    .run(c.credentialId, c.userId, c.publicKeyJwk, c.alg, c.signCount,
      c.transports ?? null, c.aaguid ?? null, c.name ?? null, now());
}

export function getWebauthnCredential(credentialId: string): WebauthnCredential | undefined {
  return getXidDb().prepare("SELECT * FROM XWEBAUTHN WHERE CredentialID=?").get(credentialId) as
    | WebauthnCredential | undefined;
}

export function listWebauthnCredentials(userId: number): Array<{
  CredentialID: string; Name: string | null; CreatedDate: string | null; LastUsedDate: string | null; Transports: string | null;
}> {
  return getXidDb()
    .prepare(
      "SELECT CredentialID, Name, CreatedDate, LastUsedDate, Transports FROM XWEBAUTHN WHERE UserID=? ORDER BY CreatedDate"
    )
    .all(userId) as Array<{ CredentialID: string; Name: string | null; CreatedDate: string | null; LastUsedDate: string | null; Transports: string | null }>;
}

export function credentialIdsForUser(userId: number): string[] {
  return (getXidDb().prepare("SELECT CredentialID FROM XWEBAUTHN WHERE UserID=?").all(userId) as { CredentialID: string }[])
    .map((r) => r.CredentialID);
}

export function updateWebauthnUsage(credentialId: string, signCount: number): void {
  getXidDb().prepare("UPDATE XWEBAUTHN SET SignCount=?, LastUsedDate=? WHERE CredentialID=?")
    .run(signCount, now(), credentialId);
}

/** Deletes one of the user's passkeys; returns true if a row was removed. */
export function deleteWebauthnCredential(userId: number, credentialId: string): boolean {
  const r = getXidDb().prepare("DELETE FROM XWEBAUTHN WHERE UserID=? AND CredentialID=?").run(userId, credentialId);
  return r.changes > 0;
}

// ── Audit ───────────────────────────────────────────────────────────────────
// Dual write: (1) XAUDITLOG table (queryable, exhaustive, not capped on
// storage) and (2) JSONL file rotated daily in DB_DIR/audit-logs/,
// meant to be collected by a SIEM (one event = one JSON line).
const AUDIT_DIR = path.join(DB_DIR, "audit-logs");

function appendAuditFile(rec: Record<string, unknown>): void {
  try {
    if (!fs.existsSync(AUDIT_DIR)) fs.mkdirSync(AUDIT_DIR, { recursive: true });
    const day = new Date().toISOString().slice(0, 10);
    fs.appendFileSync(path.join(AUDIT_DIR, `audit-${day}.jsonl`), JSON.stringify(rec) + "\n");
  } catch {
    /* the audit file must never block the business action */
  }
}

export function addAudit(opts: {
  userId: number | null;
  action: string;
  resourceType?: string;
  resourceKey?: string;
  detail?: string;
  ip?: string;
  tenantId?: number | null;
}): void {
  const ts = new Date().toISOString();
  getXidDb()
    .prepare(
      `INSERT INTO XAUDITLOG (UserID, Action, ResourceType, ResourceKey, Detail, IP, Timestamp, TenantID)
       VALUES (?,?,?,?,?,?,?,?)`
    )
    .run(
      opts.userId,
      opts.action,
      opts.resourceType ?? null,
      opts.resourceKey ?? null,
      opts.detail ?? null,
      opts.ip ?? null,
      now(),
      opts.tenantId ?? null
    );
  // SIEM sink (JSONL) — stable keys, ISO 8601 timestamp (UTC).
  appendAuditFile({
    ts,
    action: opts.action,
    userId: opts.userId,
    resourceType: opts.resourceType ?? null,
    resourceKey: opts.resourceKey ?? null,
    detail: opts.detail ?? null,
    ip: opts.ip ?? null,
    tenantId: opts.tenantId ?? null,
  });
}

/**
 * Paginated + filtered query of the audit log (for SIEM export; no
 * 200 cap). Optional filters: action (prefix), userId, since/until
 * (ISO or "YYYY-MM-DD HH:MM:SS"), tenantId.
 */
export function queryAudit(opts: {
  limit?: number; offset?: number; action?: string; userId?: number;
  since?: string; until?: string; tenantId?: number | null;
}): Record<string, unknown>[] {
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.action) { where.push("a.Action LIKE ?"); params.push(opts.action + "%"); }
  if (opts.userId != null) { where.push("a.UserID = ?"); params.push(opts.userId); }
  if (opts.since) { where.push("a.Timestamp >= ?"); params.push(opts.since); }
  if (opts.until) { where.push("a.Timestamp <= ?"); params.push(opts.until); }
  if (opts.tenantId != null) { where.push("a.TenantID = ?"); params.push(opts.tenantId); }
  const limit = Math.min(Math.max(Number(opts.limit) || 1000, 1), 100000);
  const offset = Math.max(Number(opts.offset) || 0, 0);
  const sql =
    `SELECT a.*, u.Email FROM XAUDITLOG a LEFT JOIN XUSER u ON u.UserID = a.UserID` +
    (where.length ? ` WHERE ${where.join(" AND ")}` : "") +
    ` ORDER BY a.AuditID DESC LIMIT ? OFFSET ?`;
  return getXidDb().prepare(sql).all(...params, limit, offset) as Record<string, unknown>[];
}

/** Audit log; if tenantId is provided, restricts to that tenant. */
export function listAudit(limit = 200, tenantId?: number | null): Record<string, unknown>[] {
  const db = getXidDb();
  if (tenantId != null) {
    return db
      .prepare(
        `SELECT a.*, u.Email FROM XAUDITLOG a
         LEFT JOIN XUSER u ON u.UserID = a.UserID
         WHERE a.TenantID = ? ORDER BY a.AuditID DESC LIMIT ?`
      )
      .all(tenantId, limit) as Record<string, unknown>[];
  }
  return db
    .prepare(
      `SELECT a.*, u.Email FROM XAUDITLOG a
       LEFT JOIN XUSER u ON u.UserID = a.UserID
       ORDER BY a.AuditID DESC LIMIT ?`
    )
    .all(limit) as Record<string, unknown>[];
}
