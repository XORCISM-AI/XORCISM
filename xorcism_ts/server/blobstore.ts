/**
 * blobstore.ts — content-addressed object storage for large files (STIX bundles, PCAPs, malware
 * samples, …). Files are written OUTSIDE OneDrive under DB_DIR/blobstore, sharded by SHA-256
 * (`ab/cd/<sha256>`), and **deduplicated** — identical bytes are stored once. A registry row
 * (XORCISM.FILEBLOB) holds the metadata + a refcount; a DB row references a blob by its sha256
 * "hash pointer" instead of carrying a multi-MB BLOB in row storage (which bloats the DB and slows
 * every query that doesn't need the bytes). Engine-independent: the same pattern maps to S3/MinIO later.
 */
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execFileSync } from "child_process";
import { allocId, getDb } from "./db";

const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";
const BLOB_DIR = process.env.XORCISM_BLOB_DIR ?? path.join(DB_DIR, "blobstore");

const isSha256 = (s: string): boolean => /^[a-f0-9]{64}$/i.test(s);
function shardPath(sha: string): string { return path.join(BLOB_DIR, sha.slice(0, 2), sha.slice(2, 4), sha); }

// ── storage backend ────────────────────────────────────────────────────────────────
// Bytes live on the local filesystem (default) or in S3/MinIO (XORCISM_BLOB_BACKEND=s3). The hash-
// pointer interface (FILEBLOB registry + putBlob/readBlob) is identical either way — only the byte
// storage swaps. S3 uses curl's built-in SigV4 signer (no aws-sdk dependency) and stays synchronous.
const BACKEND: "fs" | "s3" = process.env.XORCISM_BLOB_BACKEND === "s3" ? "s3" : "fs";
const S3 = {
  endpoint: (process.env.XORCISM_S3_ENDPOINT || "").replace(/\/+$/, ""), bucket: process.env.XORCISM_S3_BUCKET || "",
  region: process.env.XORCISM_S3_REGION || "us-east-1", ak: process.env.XORCISM_S3_ACCESS_KEY || "", sk: process.env.XORCISM_S3_SECRET_KEY || "",
};
const s3Url = (sha: string): string => `${S3.endpoint}/${S3.bucket}/${sha.slice(0, 2)}/${sha.slice(2, 4)}/${sha}`;
function s3Curl(args: string[], input?: Buffer): Buffer {
  return execFileSync("curl", ["-sS", "--fail", "--aws-sigv4", `aws:amz:${S3.region}:s3`, "--user", `${S3.ak}:${S3.sk}`, ...args], { input, maxBuffer: 256 * 1024 * 1024 });
}
function storageLoc(sha: string): string { return BACKEND === "s3" ? s3Url(sha) : shardPath(sha); }
function storageExists(sha: string): boolean {
  if (BACKEND === "s3") { try { s3Curl(["-I", s3Url(sha)]); return true; } catch { return false; } }
  return fs.existsSync(shardPath(sha));
}
function storagePut(sha: string, buf: Buffer): void {
  if (BACKEND === "s3") { s3Curl(["-X", "PUT", "-H", "Content-Type: application/octet-stream", "--data-binary", "@-", s3Url(sha)], buf); return; }
  const p = shardPath(sha); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, buf);
}
function storageGet(sha: string, storedPath?: string): Buffer | null {
  if (BACKEND === "s3") { try { return s3Curl([s3Url(sha)]); } catch { return null; } }
  const p = storedPath && fs.existsSync(storedPath) ? storedPath : shardPath(sha);
  try { return fs.existsSync(p) ? fs.readFileSync(p) : null; } catch { return null; }
}
function storageDelete(sha: string, storedPath?: string): void {
  if (BACKEND === "s3") { try { s3Curl(["-X", "DELETE", s3Url(sha)]); } catch { /* */ } return; }
  const p = storedPath || shardPath(sha);
  try { if (fs.existsSync(p)) fs.unlinkSync(p); } catch { /* */ }
}

// Tables whose in-row BLOB can be offloaded to the content-addressed store (DB, table, PK, name col).
const BLOB_TARGETS: { db: string; table: string; pk: string; nameCol?: string; contentType?: string }[] = [
  { db: "XOVAL", table: "OVALDEFINITION", pk: "OVALDefinitionID", nameCol: "OVALDefinitionIDPattern", contentType: "application/xml" },
  { db: "XORCISM", table: "DOCUMENT", pk: "DocumentID", nameCol: "DocumentName" },
  { db: "XCOMPLIANCE", table: "DOCUMENT", pk: "DocumentID", nameCol: "DocumentName" },
];

/** Add the BlobSha256 "hash pointer" column to a table (column-aware, best-effort). */
function addShaColumn(dbName: string, table: string): void {
  try {
    const db = getDb(dbName);
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) return;
    const have = new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
    if (!have.has("BlobSha256")) db.exec(`ALTER TABLE "${table}" ADD COLUMN "BlobSha256" TEXT`);
  } catch { /* table absent on this deployment */ }
}

/** Create the FILEBLOB registry + the on-disk store directory, and the BlobSha256 pointer columns. */
export function ensureBlobStore(): void {
  try {
    fs.mkdirSync(BLOB_DIR, { recursive: true });
    const xo = getDb("XORCISM");
    xo.exec(`
      CREATE TABLE IF NOT EXISTS FILEBLOB (
        BlobID INTEGER PRIMARY KEY, Sha256 TEXT, Size INTEGER, ContentType TEXT, OriginalName TEXT,
        RefCount INTEGER DEFAULT 1, Pinned INTEGER DEFAULT 0, StoragePath TEXT, FirstSeen TEXT, LastSeen TEXT, CreatedDate TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_fileblob_sha ON FILEBLOB(Sha256);`);
    try { const have = new Set((xo.prepare(`PRAGMA table_info("FILEBLOB")`).all() as { name: string }[]).map((c) => c.name)); if (!have.has("Pinned")) xo.exec(`ALTER TABLE FILEBLOB ADD COLUMN Pinned INTEGER DEFAULT 0`); } catch { /* */ }
    for (const t of BLOB_TARGETS) addShaColumn(t.db, t.table);
  } catch (e) { console.warn(`[blob] ensure: ${(e as Error).message}`); }
}

export interface PutResult { sha256: string; size: number; dedup: boolean; path: string }

/** Store bytes content-addressed (dedup by sha256). `pin` marks the blob as retained regardless of
 *  references (uploads / ingested bundles) so GC won't reclaim it. Returns the hash pointer. */
export function putBlob(buf: Buffer, opts: { name?: string; contentType?: string; pin?: boolean } = {}): PutResult {
  const sha = crypto.createHash("sha256").update(buf).digest("hex");
  const loc = storageLoc(sha); const now = new Date().toISOString();
  const db = getDb("XORCISM");
  const ex = db.prepare("SELECT BlobID FROM FILEBLOB WHERE Sha256 = ?").get(sha) as { BlobID: number } | undefined;
  if (!storageExists(sha)) storagePut(sha, buf);
  if (ex) {
    db.prepare("UPDATE FILEBLOB SET RefCount = RefCount + 1, LastSeen = ?, Size = ?, ContentType = COALESCE(ContentType, ?), OriginalName = COALESCE(OriginalName, ?), StoragePath = COALESCE(StoragePath, ?), Pinned = MAX(Pinned, ?) WHERE BlobID = ?")
      .run(now, buf.length, opts.contentType ?? null, opts.name ?? null, loc, opts.pin ? 1 : 0, ex.BlobID);
  } else {
    const id = allocId(db, "FILEBLOB", "BlobID");
    db.prepare("INSERT INTO FILEBLOB (BlobID, Sha256, Size, ContentType, OriginalName, RefCount, Pinned, StoragePath, FirstSeen, LastSeen, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
      .run(id, sha, buf.length, opts.contentType ?? null, opts.name ?? null, 1, opts.pin ? 1 : 0, loc, now, now, now);
  }
  return { sha256: sha, size: buf.length, dedup: !!ex, path: loc };
}

export interface BlobMeta { sha256: string; size: number; contentType: string | null; name: string | null; refCount: number; path: string }
export function getBlobMeta(sha: string): BlobMeta | null {
  if (!isSha256(sha)) return null;
  const r = getDb("XORCISM").prepare("SELECT * FROM FILEBLOB WHERE Sha256 = ?").get(sha.toLowerCase()) as any;
  if (!r) return null;
  return { sha256: String(r.Sha256), size: Number(r.Size || 0), contentType: r.ContentType ?? null, name: r.OriginalName ?? null, refCount: Number(r.RefCount || 1), path: String(r.StoragePath || shardPath(sha)) };
}

/** Read a blob's bytes by hash (returns null if the registry row or the stored object is missing). */
export function readBlob(sha: string): Buffer | null {
  const m = getBlobMeta(sha); if (!m) return null;
  return storageGet(m.sha256, m.path);
}

export function blobStoreStats(): { blobs: number; totalBytes: number; pinned: number; backend: string; dir: string } {
  try {
    const r = getDb("XORCISM").prepare("SELECT COUNT(*) n, COALESCE(SUM(Size),0) b, COALESCE(SUM(Pinned),0) p FROM FILEBLOB").get() as { n: number; b: number; p: number };
    return { blobs: Number(r.n), totalBytes: Number(r.b), pinned: Number(r.p), backend: BACKEND, dir: BACKEND === "s3" ? `${S3.endpoint}/${S3.bucket}` : BLOB_DIR };
  } catch { return { blobs: 0, totalBytes: 0, pinned: 0, backend: BACKEND, dir: BLOB_DIR }; }
}

// ── garbage collection (mark-and-sweep) ──────────────────────────────────────────────
/** Reclaim blobs that nothing references. Referenced = a BlobSha256 pointer column still names it.
 *  Pinned blobs (uploads / ingested bundles) are always kept. A grace window protects freshly created
 *  blobs (just uploaded, not yet wired into a row). `dryRun` (default) reports without deleting. */
export function gcBlobs(opts: { dryRun?: boolean; graceHours?: number } = {}): { scanned: number; referenced: number; pinned: number; orphan: number; deleted: number; bytesFreed: number; dryRun: boolean } {
  const db = getDb("XORCISM");
  const dryRun = opts.dryRun !== false; const grace = Math.max(0, opts.graceHours ?? 24) * 3600 * 1000; const now = Date.now();
  const referenced = new Set<string>();
  for (const t of BLOB_TARGETS) {
    try {
      const d = getDb(t.db);
      if (!d.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t.table)) continue;
      const have = new Set((d.prepare(`PRAGMA table_info("${t.table}")`).all() as { name: string }[]).map((c) => c.name));
      if (!have.has("BlobSha256")) continue;
      for (const r of d.prepare(`SELECT DISTINCT BlobSha256 s FROM "${t.table}" WHERE BlobSha256 IS NOT NULL AND BlobSha256 <> ''`).all() as { s: string }[]) referenced.add(String(r.s).toLowerCase());
    } catch { /* */ }
  }
  let pinned = 0, orphan = 0, deleted = 0, bytesFreed = 0; let scanned = 0;
  const blobs = db.prepare("SELECT BlobID, Sha256, Size, Pinned, StoragePath, CreatedDate FROM FILEBLOB").all() as any[];
  for (const b of blobs) {
    scanned++;
    const sha = String(b.Sha256).toLowerCase();
    if (Number(b.Pinned) === 1) { pinned++; continue; }
    if (referenced.has(sha)) continue;
    orphan++;
    const age = now - (Date.parse(String(b.CreatedDate || "")) || now);
    if (age < grace) continue; // protect freshly created, not-yet-wired blobs
    bytesFreed += Number(b.Size || 0);
    if (!dryRun) { storageDelete(sha, b.StoragePath); db.prepare("DELETE FROM FILEBLOB WHERE BlobID = ?").run(b.BlobID); deleted++; }
  }
  return { scanned, referenced: referenced.size, pinned, orphan, deleted, bytesFreed, dryRun };
}

// ── migrate existing in-row BLOBs → CAS ─────────────────────────────────────────────
export interface OffloadResult { migrated: number; reclaimed: number; bytes: number; skipped: number }

/** Move a table's in-row BLOB column into the content-addressed store, recording the sha256 pointer in
 *  BlobSha256. Non-destructive by default; `reclaim` nulls the BLOB **only after** the CAS copy reads
 *  back byte-identical (so the row keeps only the pointer and the DB reclaims the space). Idempotent:
 *  only rows with a BLOB and no pointer yet are processed. */
export function offloadBlobColumn(dbName: string, table: string, pk: string, opts: { blobCol?: string; nameCol?: string; contentType?: string; reclaim?: boolean; cap?: number } = {}): OffloadResult {
  const blobCol = opts.blobCol ?? "BLOB"; const cap = Math.max(1, opts.cap ?? 100000);
  const out: OffloadResult = { migrated: 0, reclaimed: 0, bytes: 0, skipped: 0 };
  try {
    const db = getDb(dbName);
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) return out;
    const have = new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
    if (!have.has(blobCol)) return out;
    if (!have.has("BlobSha256")) db.exec(`ALTER TABLE "${table}" ADD COLUMN "BlobSha256" TEXT`);
    const nameSel = opts.nameCol && have.has(opts.nameCol) ? `, "${opts.nameCol}" AS nm` : "";
    const rows = db.prepare(`SELECT "${pk}" AS pk, "${blobCol}" AS b${nameSel} FROM "${table}" WHERE "${blobCol}" IS NOT NULL AND "${blobCol}" <> '' AND (BlobSha256 IS NULL OR BlobSha256 = '') LIMIT ?`).all(cap) as any[];
    for (const r of rows) {
      const b = r.b; if (b == null || b === "") { out.skipped++; continue; }
      const buf = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
      if (!buf.length) { out.skipped++; continue; }
      const put = putBlob(buf, { name: r.nm ? String(r.nm) : undefined, contentType: opts.contentType });
      db.prepare(`UPDATE "${table}" SET BlobSha256 = ? WHERE "${pk}" = ?`).run(put.sha256, r.pk);
      out.migrated++; out.bytes += buf.length;
      if (opts.reclaim) { const back = readBlob(put.sha256); if (back && back.equals(buf)) { db.prepare(`UPDATE "${table}" SET "${blobCol}" = NULL WHERE "${pk}" = ?`).run(r.pk); out.reclaimed++; } }
    }
  } catch (e) { console.warn(`[blob] offload ${dbName}.${table}: ${(e as Error).message}`); }
  return out;
}

/** Offload every known in-row BLOB column (OVAL definitions + DOCUMENT files) to the CAS. */
export function migrateInRowBlobs(opts: { reclaim?: boolean; cap?: number } = {}): Record<string, OffloadResult> {
  const results: Record<string, OffloadResult> = {};
  for (const t of BLOB_TARGETS) results[`${t.db}.${t.table}`] = offloadBlobColumn(t.db, t.table, t.pk, { nameCol: t.nameCol, contentType: t.contentType, reclaim: opts.reclaim, cap: opts.cap });
  return results;
}
