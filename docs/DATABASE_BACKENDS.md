# Database backends (SQLite / PostgreSQL / MySQL / MariaDB)

XORCISM ships on **SQLite** (one file per logical database, 11 in total) and is being made
portable to server databases (**PostgreSQL / MySQL / MariaDB**). This is a staged migration —
the table below is the honest current state.

| Layer | Tech | Multi-engine status |
|-------|------|---------------------|
| **Python** (importers, connectors `runner.py`, SQLAlchemy models) | SQLAlchemy | ✅ **Engine-agnostic now** — set `XORCISM_DB_ENGINE`. |
| **Data migration** (`tools/migrate_db.py`) | SQLAlchemy reflect+copy | ✅ **Works now** — SQLite → PostgreSQL / MySQL / MariaDB. |
| **Node server** (`xorcism_ts`) | `better-sqlite3` (synchronous) | ⏳ **SQLite only** — see *Stage 2* below. |

The 11 logical databases map to **one server database per logical name, lowercased**
(`XORCISM` → `xorcism`, `XVULNERABILITY` → `xvulnerability`, …), mirroring the per-file SQLite
layout (the Python code already opens one connection per logical DB; there are no cross-database
SQL joins to rewrite).

## 1. Point the Python side at PostgreSQL / MySQL

```bash
# choose the engine + connection (driver installed once):
pip install psycopg2-binary        # PostgreSQL     (or:  pip install pymysql   for MySQL/MariaDB)

export XORCISM_DB_ENGINE=postgresql        # postgresql | mysql | mariadb  (default: sqlite)
export XORCISM_DB_HOST=db.internal
export XORCISM_DB_PORT=5432                 # default 5432 (pg) / 3306 (mysql)
export XORCISM_DB_USER=xorcism
export XORCISM_DB_PASSWORD=•••
# optional: export XORCISM_DB_PREFIX=xorcism_     # → xorcism_xorcism, xorcism_xvulnerability, …
```

`config.py` then builds, per logical DB, e.g.
`postgresql+psycopg2://xorcism:•••@db.internal:5432/xvulnerability`. Importers/connectors
honour it automatically (they use `xorcism_python.models.base.session_scope`).

## 2. Migrate the data (SQLite → server)

```bash
# create the empty target databases on the server first:
#   PostgreSQL:  for d in xorcism xvulnerability xattack xmalware xincident xthreat \
#                          xoval xwindows xcompliance xticket xid; do createdb $d; done
#   MySQL/MariaDB: CREATE DATABASE xorcism; …  (one per logical name)

python tools/migrate_db.py --engine postgresql            # copies all 11 SQLite DBs
python tools/migrate_db.py --engine mysql --only XORCISM,XVULNERABILITY   # subset
python tools/migrate_db.py --target-dir /tmp/copy --only XOVAL            # SQLite→SQLite self-test
```

The tool **reflects** each SQLite schema, recreates it on the target (coercing SQLite's untyped
columns to `TEXT` so server engines accept them), and **bulk-copies** the rows
(`--batch`, default 1000). `--drop` recreates target tables; `--dry-run` reflects only.
Verified SQLite→SQLite on XOVAL: 111 tables / 2.2M rows, per-table counts identical.

> Note: SQLite is forgiving about types; on a strict engine, hand-review a few legacy columns
> (e.g. boolean-ish `INTEGER`/`REAL` flags, the `BLOB`-named text column) after the first copy.
> Re-running is safe with `--drop`.

## 3. Stage 2 — the Node server (remaining work)

The `xorcism_ts` server uses **synchronous `better-sqlite3`** (`getDb(name).prepare(sql).get()/
.all()/.run()`) in essentially every module. PostgreSQL/MySQL drivers (`pg`, `mysql2`) are
**asynchronous**, so porting the Node backend is not a config flip — it requires:

1. A thin DB adapter interface behind `getDb()` (a `query/get/all/run` seam).
2. Replacing synchronous call sites with the adapter (and making the call chain `async` where the
   driver is async), or adopting a synchronous Postgres shim where viable.
3. SQL-dialect handling: `INSERT OR IGNORE`/`INSERT OR REPLACE`, `lastInsertRowid`,
   `PRAGMA`, `datetime('now')`/`date('now', …)`, `||` concatenation, `AUTOINCREMENT` vs
   `SERIAL`/`IDENTITY`, and the `CREATE TABLE IF NOT EXISTS … ALTER` idempotent-schema helpers.
4. Connection pooling + transaction semantics (`db.transaction(...)` → pooled async tx).

This is a multi-PR effort and is intentionally **not** attempted in one big-bang change (it would
destabilise the working SQLite app). Stage 1 (this change) makes the Python side and data fully
portable so a server database can be stood up and loaded today; Stage 2 ports the Node read/write
layer behind the adapter seam.
