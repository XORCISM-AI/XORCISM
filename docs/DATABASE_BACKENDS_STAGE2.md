# Database backends — Stage 2 (Node/TS data layer) migration plan

> Status: **Route A (libSQL) implemented.** `db.ts` is now a pluggable synchronous driver:
> `better-sqlite3` remains the zero-config default; `libsql`/Turso is opt-in for HA / replication /
> embedded replicas — with **zero changes to the ~1,964 call sites**. Routes B/C below remain
> documented options if a true async client-server Postgres is ever required.
>
> **Enable libSQL:** `npm i libsql`, then `XORCISM_DB_DRIVER=libsql`. To make a logical DB an embedded
> replica of a remote libSQL/Turso server, set `LIBSQL_SYNC_URL` (+ `LIBSQL_AUTH_TOKEN`) globally or
> per DB (`LIBSQL_<NAME>_SYNC_URL`); replicas refresh every `LIBSQL_SYNC_SECONDS` (default 30). If the
> `libsql` package isn't installed, the app logs a warning and falls back to better-sqlite3.

## 1. Where we are

- **Stage 1 (done).** The **Python** side is already engine-agnostic: `xorcism_python/config.py`
  (`XORCISM_DB_ENGINE` + `database_url`) on SQLAlchemy, plus `tools/migrate_db.py` (a SQLite →
  server copier) and `docs/DATABASE_BACKENDS.md`. The importers can already target Postgres/MySQL.
- **Stage 2 (this doc).** The **Node/TypeScript** app server (`xorcism_ts/server`) is **not**
  engine-agnostic. It uses `better-sqlite3` through one accessor:

  ```ts
  // db.ts
  const connections = new Map<string, Database.Database>();
  export function getDb(name: string): Database.Database {
    const db = new Database(dbPath, { readonly: false, fileMustExist: true });
    db.pragma("journal_mode = WAL"); db.pragma("foreign_keys = ON"); db.pragma("busy_timeout = 5000");
    // …cached per logical DB…
  }
  ```

  Every module then calls `getDb("X").prepare(sql).get()/.all()/.run()` **synchronously**.

## 2. Why this is a dedicated effort, quantified

A survey of `xorcism_ts/server` (105 files):

| Surface | Count | Why it matters |
|---|---:|---|
| `getDb()` call sites | ~860 | 9 logical DBs (XORCISM 371, XCOMPLIANCE 153, XTHREAT 88, XINCIDENT 68, XVULNERABILITY 61, XOVAL 11, XMALWARE/XID 4, XTICKET 3) |
| `.prepare(...).get/all/run` | **1,964** | the entire data layer is **synchronous** |
| `.transaction(...)` | 73 | better-sqlite3 sync transactions |
| `COALESCE(MAX(id),0)+1` id allocation | **97** | **race under any concurrent writer** — fine-ish on single-writer SQLite, a correctness bug on multi-writer Postgres |
| `PRAGMA table_info(...)` | 159 | runtime schema introspection (the "column-aware INSERT" + `ensure*` ALTER pattern) |
| `ALTER TABLE … ADD COLUMN` (runtime) | 51 | app-managed migrations at boot |
| `rowid` references | 57 | SQLite implicit rowid |
| `INSERT OR IGNORE/REPLACE` / `ON CONFLICT` / `GLOB` / `datetime('now')` | 8 / 5 / 3 / 1 | dialect-specific SQL |

The hard wall: **`pg` (the Node Postgres driver) is async; better-sqlite3 is sync.** Going to a real
client-server Postgres means either (a) threading `await` through ~2,000 call sites *and every
function/route above them*, or (b) blocking the event loop with a sync-over-async shim (which throws
away the concurrency that is the whole reason to adopt Postgres). Neither is a "wave".

## 3. First: what is the *actual* goal?

"Stage 2" was shorthand. The right route depends entirely on the driver:

| Goal | Best route |
|---|---|
| **HA / replication / managed backups / read replicas**, keep single logical writer | **Route A — libSQL/Turso** (keep the sync API) |
| **Multi-writer concurrency, shared managed RDBMS, heavy SQL/analytics, org policy mandates Postgres** | **Route C — async Postgres port** |
| Just "more robust than a file on disk" | Route A, or even Litestream/LiteFS (no code change) |

## 4. Options

### Route A — libSQL / Turso (recommended default)
libSQL is a fork of SQLite with a **better-sqlite3-compatible client** (`@libsql/client`, and
`libsql` exposes a near drop-in sync `Database`). It adds **embedded replicas**, server mode,
replication and managed durability — while keeping the **synchronous API**.
- **Change surface:** swap the `new Database(...)` construction in **`db.ts` only**; the 1,964 call
  sites stay as-is. Add a `sync()` step for embedded replicas.
- **Effort:** ~0.5–1 day + testing. **Risk: low.** Delivers HA/replication/backups, not multi-writer
  Postgres semantics.
- **Caveat:** still SQLite SQL dialect (so the 97 `MAX()+1` races remain — see §6, worth fixing
  regardless).

### Route B — rqlite / dqlite (distributed SQLite)
Raft-replicated SQLite. rqlite is HTTP-only → forces a query-layer rewrite (loses the sync API);
dqlite has limited Node bindings. **Not recommended** for this codebase.

### Route C — Async Postgres port (the literal "Stage 2")
A real client-server engine behind `XORCISM_DB_ENGINE=postgres`, selectable per deployment, with
SQLite kept as the zero-config default. This is the multi-week, flagged, codemod-driven effort below.

## 5. Route C — phased plan (only if true Postgres is required)

**Milestone 0 — non-breaking facade (1 PR, ~1 day).** Introduce an async data interface and back it
with the *current* sync SQLite calls (so behaviour is identical), then convert **one** pilot module
(e.g. `pqcmm.ts` — small, self-contained) end-to-end to prove the shape:
```ts
export interface Db {
  query<T=any>(sql: string, params?: unknown[]): Promise<T[]>;     // .all
  one<T=any>(sql: string, params?: unknown[]): Promise<T|undefined>;// .get
  exec(sql: string, params?: unknown[]): Promise<{ changes: number; lastId?: number }>; // .run
  tx<T>(fn: (t: Db) => Promise<T>): Promise<T>;                    // transaction
}
export function db(name: string): Db;       // async accessor, replaces getDb()
```
No engine added yet, no behaviour change — pure refactor + pilot. Ship and verify.

**Milestone 1 — mechanical async migration (codemod, reviewed in batches).**
`getDb("X").prepare(s).all(a) → await db("X").query(s,[a])` (and `.get`→`one`, `.run`→`exec`,
`.transaction`→`tx`). An AST codemod (ts-morph/jscodeshift) does the bulk; then make the enclosing
functions `async` and propagate `await` up to the route handlers (Express handlers are already
async-capable). Reviewed **one logical DB at a time** (XOVAL/XID/XTICKET/XMALWARE first — only ~22
call sites — then XINCIDENT, XVULNERABILITY, XTHREAT, XCOMPLIANCE, XORCISM).

**Milestone 2 — the Postgres impl + dialect layer (see §6).** Add a `pg`-backed `Db`. A thin SQL
dialect adapter rewrites the handful of SQLite-isms; ids move to sequences.

**Milestone 3 — schema + data migration.** Generate Postgres DDL from `databases/*_sqlite.sql`
(reuse the Stage-1 `tools/migrate_db.py` data copier). Replace the 159 `PRAGMA table_info` +51
runtime `ALTER` with an introspection adapter (`information_schema.columns`) behind the same
`ensure*` helpers.

**Milestone 4 — test gate.** Run the existing offline module verifications (the `DB_DIR`-copy
harnesses used throughout this codebase) against **both** engines in CI; add a docker-compose
Postgres service. Cut over per deployment via `XORCISM_DB_ENGINE`.

## 6. Dialect + correctness adapter (the real work in Route C)

| SQLite pattern | Count | Postgres translation |
|---|---:|---|
| `COALESCE(MAX(Id),0)+1` for new ids | 97 | **`SERIAL`/`IDENTITY` + `INSERT … RETURNING id`** — also removes a latent race that exists today under concurrent writers |
| `PRAGMA table_info(t)` | 159 | `information_schema.columns` adapter (cached) |
| runtime `ALTER TABLE ADD COLUMN` | 51 | same SQL works; gate on the introspection adapter |
| `INSERT OR IGNORE` / `OR REPLACE` | 8 | `INSERT … ON CONFLICT DO NOTHING / DO UPDATE` |
| `datetime('now')`, `strftime` | 1 | `now()` / `to_char` |
| `LIKE` (case-insensitive by default in SQLite) | many | `ILIKE` |
| `rowid` | 57 | explicit PK (most are already `INTEGER PRIMARY KEY`; audit the rest) |
| `GLOB` | 3 | `~` / `SIMILAR TO` |
| WAL / `busy_timeout` pragmas | — | drop (pool + transactions handle it) |
| booleans stored as 0/1 | many | keep `smallint`/`int` to avoid churn, or `boolean` with a cast adapter |

The **97 `MAX()+1`** sites are the single most important finding: they are a pre-existing
concurrency hazard (two simultaneous inserts can collide) that SQLite's single-writer WAL hides.
Fixing them (sequences/RETURNING) is worthwhile **even if you stay on SQLite/libSQL**.

## 7. Recommendation

1. **Decide the goal (§3).** If it's HA/replication/backups → **Route A (libSQL)**: ~1 day, low risk,
   keeps the sync API. This is very likely the right answer and I can do it in a single focused PR.
2. **Independently, fix the 97 `MAX()+1` id allocations** → sequence/RETURNING helper. Correctness
   win on any backend; a good first concrete step.
3. **Only pursue Route C (Postgres)** if multi-writer/managed-RDBMS is a hard requirement. If so,
   start with **Milestone 0** (non-breaking facade + one pilot module) — small, reversible, and it
   de-risks the codemod before committing to the multi-week migration.

Do **not** attempt Route C as a single big-bang change: 1,964 sync call sites + 73 transactions
across 105 files is exactly the kind of refactor that must be flagged, codemodded, and migrated one
DB at a time behind `XORCISM_DB_ENGINE`, with the test gate green on both engines at every step.
