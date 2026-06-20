/**
 * apikey.ts — Programmatic API-key authentication for the XORCISM REST API.
 *
 * A key is `xor_<random>`; only its SHA-256 is stored (XID.XAPIKEY). A request may
 * present it as `Authorization: Bearer xor_…` or `X-API-Key: xor_…`. When valid, the
 * request is authenticated as the key's owning user — same RBAC + tenant scope as a
 * session. Read-only by design (no write scopes yet).
 */
import crypto from "crypto";
import { Request, Response, NextFunction } from "express";
import * as xid from "./xid";
import { buildUserContext } from "./auth";

const KEY_PREFIX = "xor_";
const sha256 = (s: string): string => crypto.createHash("sha256").update(s).digest("hex");

/** Per-resource scopes a key can hold. `read`/`write` are broad aliases. */
export const API_SCOPES = ["assets:read", "assets:write", "incidents:read", "incidents:write", "exposure:read", "risk:read", "identities:read", "compliance:read", "policies:read", "configuration:read", "crisis:read", "tid:read"] as const;

/** Does a key's scope list grant `required`? read = all *:read; write = all *:read+*:write; resource:write implies resource:read. */
export function scopeGrants(scopesCsv: string | null | undefined, required: string): boolean {
  const set = new Set((scopesCsv || "read").split(/[,\s]+/).map((s) => s.trim()).filter(Boolean));
  if (set.has(required) || set.has("write")) return true;
  if (required.endsWith(":read")) {
    if (set.has("read")) return true;
    const res = required.split(":")[0];
    if (set.has(`${res}:write`)) return true;
  }
  return false;
}

/** True if the request may use an endpoint requiring `scope`: sessions always pass
 *  (RBAC governs); API keys must hold the scope. */
export function scopeOrSession(req: Request, scope: string): boolean {
  const r = req as Request & { apiKeyId?: number; apiKeyScopes?: string };
  if (r.apiKeyId == null) return true;          // session-authenticated
  return scopeGrants(r.apiKeyScopes, scope);
}

/** Validates/normalizes a requested scope string to a clean CSV of allowed tokens. */
export function normalizeScopes(raw: unknown): string {
  const allowed = new Set<string>(["read", "write", ...API_SCOPES]);
  const toks = String(raw ?? "read").split(/[,\s]+/).map((s) => s.trim()).filter((s) => allowed.has(s));
  return toks.length ? Array.from(new Set(toks)).join(",") : "read";
}

/** Generates a fresh API key. The raw value is returned ONCE (never stored). */
export function generateApiKey(): { raw: string; hash: string; prefix: string } {
  const raw = KEY_PREFIX + crypto.randomBytes(24).toString("base64url"); // ~32 url-safe chars
  return { raw, hash: sha256(raw), prefix: raw.slice(0, 12) + "…" };       // e.g. "xor_3f9aK2p…"
}

function readKey(req: Request): string | null {
  const auth = req.headers["authorization"];
  if (typeof auth === "string" && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, "").trim();
  const x = req.headers["x-api-key"];
  if (typeof x === "string" && x.trim()) return x.trim();
  return null;
}

/**
 * Express middleware: if the request isn't already session-authenticated and carries
 * an API key, authenticate it as the key's owner. No-op otherwise (the normal auth
 * gate then decides). Mount AFTER loadUser and BEFORE requireAuthGate.
 */
export function apiKeyAuth(req: Request, _res: Response, next: NextFunction): void {
  if (req.user) return next();                 // session already won
  const key = readKey(req);
  if (!key || !key.startsWith(KEY_PREFIX)) return next();
  const row = xid.getApiKeyByHash(sha256(key));
  if (!row) return next();                      // unknown / revoked
  if (row.ExpiresDate && Date.parse(row.ExpiresDate) <= Date.now()) return next(); // expired
  const u = xid.getUserById(row.UserID);
  if (!u || u.IsLockedOut) return next();
  req.user = buildUserContext(u);
  const r = req as Request & { apiKeyId?: number; apiKeyScopes?: string };
  r.apiKeyId = row.KeyID;
  r.apiKeyScopes = row.Scopes || "read"; // CSV of scopes (legacy null = read)
  try { xid.touchApiKey(row.KeyID); } catch { /* best-effort */ }
  next();
}
