/**
 * auth.ts — Password hashing (scrypt, OWASP), cookie-based sessions,
 * authentication and authorization middlewares (RBAC/CRUD), admin seed.
 */

import crypto from "crypto";
import { Request, Response, NextFunction } from "express";
import * as xid from "./xid";
import { tr } from "./i18n";

// ── scrypt hashing ────────────────────────────────────────────────────────────
// Stored format: scrypt$N$r$p$<saltB64>$<hashB64>
const SCRYPT_N = 16384; // 2^14 — ~16 MB memory (128*N*r)
const SCRYPT_r = 8;
const SCRYPT_p = 1;
const KEYLEN = 64;

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_r,
    p: SCRYPT_p,
    maxmem: 64 * 1024 * 1024,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_r}$${SCRYPT_p}$${salt.toString("base64")}$${hash.toString("base64")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  try {
    const [scheme, N, r, p, saltB64, hashB64] = stored.split("$");
    if (scheme !== "scrypt") return false;
    const salt = Buffer.from(saltB64, "base64");
    const expected = Buffer.from(hashB64, "base64");
    const actual = crypto.scryptSync(password, salt, expected.length, {
      N: Number(N),
      r: Number(r),
      p: Number(p),
      maxmem: 64 * 1024 * 1024,
    });
    return (
      expected.length === actual.length && crypto.timingSafeEqual(expected, actual)
    );
  } catch {
    return false;
  }
}

// ── Password policy (OWASP) ─────────────────────────────────────────
// Returns an i18n KEY (to translate at the call site via tr(req, key)) or null.
export function passwordPolicyError(pw: string): string | null {
  if (typeof pw !== "string" || pw.length < 12) return "pw.tooShort";
  if (pw.length > 128) return "pw.tooLong";
  // At least 3 character classes among: lowercase, uppercase, digit, symbol
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  if (classes < 3) return "pw.classes";
  return null;
}

// ── Cookies / session token ────────────────────────────────────────────────
const COOKIE_NAME = "xid_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // absolute cap: 8 h
const IDLE_TIMEOUT_MS = 30 * 60 * 1000; // inactivity: 30 min
const ROTATE_MS = 60 * 60 * 1000; // token rotation every 1 h

function sha256(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

// Converts "YYYY-MM-DD HH:MM:SS" (UTC) to a ms timestamp
function dbTimeMs(s: string | null | undefined): number {
  if (!s) return 0;
  const t = Date.parse(s.replace(" ", "T") + "Z");
  return Number.isNaN(t) ? 0 : t;
}

function setSessionCookie(req: Request, res: Response, token: string, maxAgeMs: number): void {
  const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "strict",
    secure,
    maxAge: maxAgeMs,
    path: "/",
  });
}

export function parseCookies(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function startSession(req: Request, res: Response, userId: number): void {
  const token = crypto.randomBytes(32).toString("base64url");
  const sessionId = sha256(token); // we store the hash, not the raw token
  const expires = new Date(Date.now() + SESSION_TTL_MS);
  xid.createSession({
    sessionId,
    userId,
    expiresIso: expires.toISOString().replace("T", " ").slice(0, 19),
    ip: clientIp(req),
    ua: String(req.headers["user-agent"] ?? "").slice(0, 255),
  });
  setSessionCookie(req, res, token, SESSION_TTL_MS);
}

export function endSession(req: Request, res: Response): void {
  const token = parseCookies(req)[COOKIE_NAME];
  if (token) xid.deleteSession(sha256(token));
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

export function clientIp(req: Request): string {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd) return fwd.split(",")[0].trim();
  return req.socket.remoteAddress ?? "";
}

// ── req.user ──────────────────────────────────────────────────────────────────
export interface SessionUser {
  UserID: number;
  Email: string;
  DisplayName: string | null;
  isAdmin: boolean;
  roles: string[];
  mustChangePassword: boolean;
  tenantId: number | null;
  tenantName: string | null;
  isSuperAdmin: boolean; // member of the System tenant with the Admin role
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: SessionUser;
    }
  }
}

/** Loads req.user from the session cookie (absolute timeout + inactivity + rotation). */
export function loadUser(req: Request, res: Response, next: NextFunction): void {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token) return next();

  let sessionId = sha256(token);
  const sess = xid.getSession(sessionId);
  if (!sess) return next();

  const nowMs = Date.now();
  const absoluteExpired = dbTimeMs(sess.ExpiresDate) <= nowMs;
  const idleExpired =
    !!sess.LastSeenDate && nowMs - dbTimeMs(sess.LastSeenDate) > IDLE_TIMEOUT_MS;
  if (absoluteExpired || idleExpired) {
    xid.deleteSession(sessionId);
    return next();
  }

  const u = xid.getUserById(sess.UserID);
  if (!u || u.IsLockedOut) return next();

  // Periodic token rotation (limits the exploitation window of a theft)
  if (nowMs - dbTimeMs(sess.CreatedDate) > ROTATE_MS) {
    const newToken = crypto.randomBytes(32).toString("base64url");
    const newId = sha256(newToken);
    xid.rotateSession(sessionId, newId);
    sessionId = newId;
    const remaining = Math.max(60_000, dbTimeMs(sess.ExpiresDate) - nowMs);
    setSessionCookie(req, res, newToken, remaining); // emits the new cookie
  } else {
    xid.touchSession(sessionId); // sliding inactivity
  }

  req.user = buildUserContext(u);
  next();
}

/** Builds the req.user context (roles, tenant, super-admin) from a user row.
 *  Shared by the session loader (loadUser) and the API-key authenticator. */
export function buildUserContext(u: xid.XUser): SessionUser {
  const roles = xid.getUserRoles(u.UserID).map((r) => r.RoleName);
  const isAdmin = roles.includes("Admin");
  const tenant = u.TenantID != null ? xid.getTenantById(u.TenantID) : undefined;
  return {
    UserID: u.UserID,
    Email: u.Email,
    DisplayName: u.DisplayName,
    isAdmin,
    roles,
    mustChangePassword: !!u.MustChangePassword,
    tenantId: u.TenantID ?? null,
    tenantName: tenant?.TenantName ?? null,
    isSuperAdmin: isAdmin && !!tenant && tenant.IsSystem === 1,
  };
}

// ── Authentication gate (pages + API) ─────────────────────────────────────
const PUBLIC_PATHS = new Set<string>(["/login", "/register", "/forgot", "/reset"]);
const PUBLIC_API = new Set<string>([
  "/api/auth/login", "/api/auth/me",
  "/api/auth/register", "/api/auth/forgot", "/api/auth/reset",
  "/api/v1/health", // API liveness probe (no secrets)
]);

export function requireAuthGate(req: Request, res: Response, next: NextFunction): void {
  const p = req.path;
  // Public static resources (login needs the CSS/JS)
  if (
    p.startsWith("/css/") ||
    p.startsWith("/js/") ||
    p.startsWith("/vendor/") ||
    p.startsWith("/trust/") ||        // public Trust Center page (slug)
    p.startsWith("/api/public/") ||   // public Trust Center API (read-only posture)
    PUBLIC_PATHS.has(p) ||
    PUBLIC_API.has(p)
  ) {
    return next();
  }
  if (req.user) return next();

  if (p.startsWith("/api/")) {
    res.status(401).json({ error: tr(req, "err.authRequired") });
  } else {
    res.redirect("/login");
  }
}

// ── RBAC/CRUD authorization ──────────────────────────────────────────────────────
type CrudAction = "read" | "create" | "update" | "delete";

/**
 * Checks that a user has the `action` permission on a `db.table` table.
 * Admin has all rights. Otherwise we look at the table permission then the database one.
 */
// ── Tables hidden from NON-Admin users (per database) ─────────────────────
// Pattern: exact table name, or prefix ending with "*" (e.g. "ADDRESS*").
// Edit this list to hide/show tables. Admins see everything.
const HIDDEN_TABLES_NONADMIN: Record<string, string[]> = {
  XORCISM: [
    "ACCESSRECORD", "ACCOUNT", "ACCOUNTAUTHENTICATIONTYPE", "ACCOUNTCHANGERECORD",
    "ACCOUNTWHITELIST", "ACTIONTAKEN", "ACTIONTAKENFORINCIDENT", "ACTIONTAKENFORTHREATCAMPAIGN",
    "ACTIONTYPE", "ADDRESS", "ADDRESSBLACKLIST", "ADDRESSCATEGORY", "ADDRESSCOUNTRY",
    "ADDRESSREPUTATION", "ADDRESSWHITELIST", "ADVISORY", "ALGORITHM", "ALGORITHMREFERENCE",
    // Application whitelists/blacklists + file extensions: hidden from non-Admins
    "APPLICATIONBLACKLIST*", "APPLICATIONWHITELIST*", "APPLICATIONFILEEXTENSION*",
    "APPLICATIONAUTHENTICATIONTYPE", "APPLICATIONCATEGORY", "APPLICATIONDEPENDENCY",
    "APPLICATIONDOCUMENT", "APPLICATIONFILEEXTENSIONBLACKLIST", "APPLICATIONFILELIST",
    "APPLICATIONFORORGANISATION", "APPLICATIONFUNCTION", "APPLICATIONMIMEWHITELIST",
    "APPLICATIONPORTWHITELIST", "APPLICATIONSECURITYLABEL", "APPLICATIONURI",
    "APPLICATIONURIWHITELIST", "APPLICATIONVERSION", "ARCHIVEFILE", "ARF*",
    "ARITHMETICFUNCTION", "ARITHMETICOPERATION", "ARP*", "ARTIFACT*",
    "ASN", "ASOBJECT", "ASSETADDRESS", "ASSETARPCACHE", "ASSETCERTIFICATE",
    "ASSETCERTIFICATEORGANISATION", "ASSETCHANGERECORD", "ASSETCREDENTIAL",
    "ASSETCRITICALITYLEVEL", "ASSETCRITICALITYLEVELFORASSET", "ASSETDEVICE", "ASSETMEMORYDUMP", "ASPNET*",
    // Low-level CPE / object / credential tables hidden from non-Admins.
    "CPEBANNER", "CPELOGICALTEST", "CREATIONOBJECT", "CREATIONOBJECTHASH",
    "CREDENTIALREPOSITORY", "CUSTOMOBJECT",
    // Low-level CWE (weakness enumeration) detail tables hidden from non-Admins.
    "CWEAFFECTEDFUNCTION", "CWEAFFECTEDRESOURCE", "CWEALTERNATETERM", "CWEALTERNATETERMTAG",
    "CWEARCHITECTURALPARADIGM", "CWEDESCRIPTION", "CWEREPOSITORY",
    // Evidence / finding / indicator / licence / locale detail tables hidden from non-Admins.
    "EVIDENCE*", "EXPLOITACCESSRECORD", "FINDING*", "INDICATOR*",
    "LICENSEACCESSRECORD", "LOCALEDESCRIPTION",
  ],
  // Compliance EVIDENCE table hidden from non-Admins (same EVIDENCE* rule).
  XCOMPLIANCE: ["EVIDENCE*"],
  // Threat INDICATOR* + low-level THREAT description tables hidden from non-Admins.
  XTHREAT: ["INDICATOR*", "THREATMOTIVEDESCRIPTION", "THREATTYPEDESCRIPTION"],
  // Incident-to-incident link table hidden from non-Admins.
  XINCIDENT: ["INCIDENTFORINCIDENT"],
  // Low-level OVAL tables (XOVAL) hidden from non-Admins. NB: 7 of the 8 tables requested
  // "in XORCISM" actually live in XOVAL → hidden here to meet the objective.
  XOVAL: [
    "OVALBEHAVIOR", "OVALBEHAVIORFOROVALOBJECT",
    "OVALCLASSDIRECTIVES", "OVALCLASSDIRECTIVESFOROVALDIRECTIVES",
    "OVALCLASSDIRECTIVESFOROVALRESULTS", "OVALCLASSENUMERATION", "OVALCOMPONENTGROUP",
    // Low-level OVAL (variables / tests / states / objects / systems / results)
    "OVALVARIABLEVALUEFOROVALSYSTEMOBJECT", "OVALVARIABLEVALUE", "OVALVARIABLES",
    "OVALVARIABLEFOROVALVARIABLES", "OVALVARIABLEDATATYPE",
    "OVALVARIABLECOMPONENTFOROVALCOMPONENTGROUP", "OVALVARIABLECOMPONENT", "OVALVARIABLE",
    "OVALTESTTYPEFOROVALSYSTEMTYPE", "OVALTESTTYPE", "OVALTESTS", "OVALTESTFOROVALTESTS",
    "OVALTESTEDVARIABLEFOROVALTESTTYPE", "OVALTESTEDVARIABLE",
    "OVALTESTEDITEMFOROVALTESTTYPE", "OVALTESTEDITEM",
    "OVALSYSTEMTYPEFOROVALRESULTSTYPE", "OVALSYSTEMTYPE", "OVALSYSTEMOBJECT",
    "OVALSYSTEMCHARACTERISTICS", "OVALSTATETYPE", "OVALSTATESIMPLEBASE",
    "OVALSTATERECORDFOROVALSTATE", "OVALSTATERECORD", "OVALSTATEFOROVALTEST",
    "OVALSTATEFIELDFOROVALSTATERECORD", "OVALSTATEFIELD", "OVALSTATECOMPLEXBASE", "OVALSTATE",
    "OVALSETFOROVALSET", "OVALSET", "OVALRESULTSTYPE", "OVALRESULTS",
    "OVALOBJECTWINDOWSREGISTRYKEY", "OVALOBJECTRECORDFOROVALOBJECT", "OVALOBJECTRECORD",
    "OVALOBJECTFOROVALTEST", "OVALOBJECTFOROVALSET", "OVALOBJECTFILE",
    "OVALOBJECTFIELDFOROVALOBJECTRECORD", "OVALOBJECTFIELD",
    "OVALOBJECTCOMPONENTFOROVALCOMPONENTGROUP", "OVALOBJECTCOMPONENT", "OVALOBJECT",
    "OVALMESSAGETYPEFOROVALTESTTYPE", "OVALMESSAGETYPEFOROVALTESTEDITEM",
    "OVALMESSAGETYPEFOROVALSYSTEMOBJECT", "OVALMESSAGETYPEFOROVALITEM",
    "OVALMESSAGETYPEFOROVALDEFINITIONTYPE", "OVALMESSAGETYPE",
    "OVALCRITERIATYPE", "OVALCRITERIATYPEFOROVALDEFINITIONTYPE", "OVALCRITERION",
    "OVALCRITERIONTYPE", "OVALCRITERIONTYPEFOROVALCRITERIATYPE", "OVALDEFAULTDIRECTIVES",
    "OVALDEFINITIONCHANGE", "OVALDEFINITIONCHANGES", "OVALDEFINITIONORGANISATION",
    "OVALDEFINITIONS", "OVALDEFINITIONSTATUS", "OVALDEFINITIONTYPE",
    "OVALDEFINITIONTYPEFOROVALSYSTEMTYPE", "OVALDIRECTIVE", "OVALDIRECTIVES",
    "OVALDIRECTIVESTYPE", "OVALENTITYATTRIBUTEGROUP", "OVALENTITYCOMPLEXBASE",
    "OVALENTITYSIMPLEBASE", "OVALEXTENSIONPOINT", "OVALEXTENSIONPOINTFOROVALGENERATORTYPE",
    "OVALEXTENSIONPOINTFORSYSTEMINFO", "OVALFILTER", "OVALFILTERFOROVALSET",
    "OVALGENERATORTYPE", "OVALITEM", "OVALITEMATTRIBUTEGROUP", "OVALITEMCOMPLEXBASE",
    "OVALITEMFOROVALSYSTEMOBJECT", "OVALITEMSIMPLEBASE", "OVALLITERALCOMPONENT",
    "OVALLITERALCOMPONENTFOROVALCOMPONENTGROUP", "OVALVARIABLETAG",
  ],
  // Low-level vulnerability join/detail tables (XVULNERABILITY) hidden from non-Admins.
  XVULNERABILITY: [
    "VULNERABILITYDESCRIPTION", "VULNERABILITYFORATTACKEXAMPLE", "VULNERABILITYFORATTACKPATTERN",
    "VULNERABILITYGOOGLEDORK", "VULNERABILITYMAPPING", "VULNERABILITYSCORE",
    "VULNERABILITYSEVERITY", "VULNERABILITYWEAKNESS",
  ],
};
const _hiddenCache: Record<string, { exact: Set<string>; prefixes: string[] }> = {};
function hiddenSpec(db: string): { exact: Set<string>; prefixes: string[] } {
  if (_hiddenCache[db]) return _hiddenCache[db];
  const exact = new Set<string>();
  const prefixes: string[] = [];
  for (const p of HIDDEN_TABLES_NONADMIN[db] ?? []) {
    if (p.endsWith("*")) prefixes.push(p.slice(0, -1).toUpperCase());
    else exact.add(p.toUpperCase());
  }
  return (_hiddenCache[db] = { exact, prefixes });
}
/** true if the table is hidden from non-Admins in this database (denylist + patterns). */
export function isHiddenForNonAdmin(db: string, table: string): boolean {
  const spec = hiddenSpec(db);
  const t = table.toUpperCase();
  return spec.exact.has(t) || spec.prefixes.some((pre) => t.startsWith(pre));
}

export function userCan(
  user: SessionUser | undefined,
  action: CrudAction,
  db: string,
  table?: string
): boolean {
  if (!user) return false;
  if (user.isAdmin) return true;
  // Tables hidden from non-Admins: deny (list + direct access/deep-link).
  if (table && isHiddenForNonAdmin(db, table)) return false;
  const perms = xid.getEffectivePermissions(user.UserID);
  const check = (p?: xid.Permission): boolean => {
    if (!p) return false;
    switch (action) {
      case "read": return !!p.CanRead;
      case "create": return !!p.CanCreate;
      case "update": return !!p.CanUpdate;
      case "delete": return !!p.CanDelete;
    }
  };
  // An explicit TABLE rule takes precedence over the DATABASE right: it allows
  // granting a table in a non-granted database, or DENYING a specific
  // table (all rights at 0) in a granted database.
  if (table) {
    const tp = perms.get(`table:${db}.${table}`);
    if (tp) return check(tp);
  }
  if (check(perms.get(`database:${db}`))) return true;
  return false;
}

export function userCanPage(user: SessionUser | undefined, pagePath: string): boolean {
  if (!user) return false;
  if (user.isAdmin) return true;
  const perms = xid.getEffectivePermissions(user.UserID);
  return !!perms.get(`page:${pagePath}`)?.CanRead;
}

/** Middleware requiring (read) access to a page for a sub-API. */
export function requirePageApi(pagePath: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (userCanPage(req.user, pagePath)) return next();
    res.status(403).json({ error: tr(req, "err.sectionDenied") });
  };
}

/**
 * Fields explicitly FORBIDDEN for an action (deny-list, field level).
 * A `field:DB.TABLE.COL` permission whose action right is 0 hides
 * the column; absent a rule, the field inherits the table's right.
 * Admin has no forbidden field.
 */
export function deniedFields(
  user: SessionUser | undefined,
  db: string,
  table: string,
  action: "read" | "create" | "update"
): Set<string> {
  const set = new Set<string>();
  if (!user || user.isAdmin) return set;
  const perms = xid.getEffectivePermissions(user.UserID);
  const prefix = `field:${db}.${table}.`;
  for (const [k, p] of perms) {
    if (!k.startsWith(prefix)) continue;
    const col = k.slice(prefix.length);
    const allowed =
      action === "read" ? p.CanRead : action === "create" ? p.CanCreate : p.CanUpdate;
    if (!allowed) set.add(col);
  }
  return set;
}

/** Middleware requiring the Admin role (super-admin OR tenant admin). */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (req.user?.isAdmin) return next();
  if (req.path.startsWith("/api/")) {
    res.status(403).json({ error: tr(req, "err.adminOnly") });
  } else {
    res.status(403).send(tr(req, "page.adminOnly"));
  }
}

/** Middleware requiring the super-admin (System tenant). */
export function requireSuperAdmin(req: Request, res: Response, next: NextFunction): void {
  if (req.user?.isSuperAdmin) return next();
  if (req.path.startsWith("/api/")) {
    res.status(403).json({ error: tr(req, "err.adminOnly") });
  } else {
    res.status(403).send(tr(req, "page.adminOnly"));
  }
}

// ── Admin seed + System tenant ───────────────────────────────────────────────
export function seedAdmin(): void {
  const db = xid.getXidDb();
  const systemTenant = xid.ensureTenant("System", true);
  const adminRoleId = xid.ensureRole("Admin", "Accès total");
  xid.ensureRole("User", "Utilisateur standard");

  // Multi-tenant migration: attach users without a tenant to the System tenant
  db.prepare("UPDATE XUSER SET TenantID = ? WHERE TenantID IS NULL").run(systemTenant);

  const count = (db.prepare("SELECT COUNT(*) AS n FROM XUSER").get() as { n: number }).n;
  if (count > 0) return;

  // Strong temporary password, shown ONCE
  const tempPw = crypto.randomBytes(12).toString("base64url"); // ~16 chars
  const uid = xid.createUser({
    email: "admin@xorcism.local",
    displayName: "Super administrateur",
    passwordHash: hashPassword(tempPw),
    mustChange: true,
    createdBy: null,
    tenantId: systemTenant,
  });
  xid.assignRole(uid, adminRoleId);
  xid.addAudit({ userId: uid, action: "seed_admin", detail: "Super-admin initial créé", tenantId: systemTenant });

  console.log("\n  ============================================================");
  console.log("  COMPTE ADMIN INITIAL CRÉÉ");
  console.log("    Email        : admin@xorcism.local");
  console.log(`    Mot de passe : ${tempPw}`);
  console.log("    (À CHANGER à la première connexion — affiché une seule fois)");
  console.log("  ============================================================\n");
}
