"""
XORCISM Configuration
Converted from App.config / ConfigurationManager
"""
import os
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Bases SQLite HORS de OneDrive (OneDrive corrompt les WAL / fige les lectures
# sous les handles ouverts). Surchargeable via la variable XORCISM_DB_DIR.
DB_DIR   = os.getenv("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")

# The 11 logical databases of XORCISM (one SQLite file each by default).
LOGICAL_DBS = [
    "XORCISM", "XVULNERABILITY", "XATTACK", "XMALWARE", "XINCIDENT", "XTHREAT",
    "XOVAL", "XWINDOWS", "XCOMPLIANCE", "XTICKET", "XID",
]

# ── Multi-engine backend (SQLite default; PostgreSQL / MySQL / MariaDB supported) ──
# XORCISM's Python data layer is SQLAlchemy, so it is engine-agnostic: set
# XORCISM_DB_ENGINE=postgresql|mysql to point the importers/connectors/models at a server
# database instead of the SQLite files. Each logical DB maps to its own database on the server
# (name lowercased, e.g. "xorcism", "xvulnerability"…), mirroring the per-file SQLite layout.
# Provision + load a target with tools/migrate_db.py; see docs/DATABASE_BACKENDS.md.
#   XORCISM_DB_ENGINE   sqlite (default) | postgresql | mysql | mariadb
#   XORCISM_DB_HOST/PORT/USER/PASSWORD   server connection (non-sqlite)
#   XORCISM_DB_PREFIX   optional prefix on the per-logical database name (default "")
DB_ENGINE = os.getenv("XORCISM_DB_ENGINE", "sqlite").strip().lower()
_DRIVERS = {
    "postgresql": "postgresql+psycopg2", "postgres": "postgresql+psycopg2",
    "mysql": "mysql+pymysql", "mariadb": "mysql+pymysql",
}


def database_url(name: str) -> str:
    """SQLAlchemy URL for a logical database under the configured engine."""
    if DB_ENGINE in _DRIVERS:
        driver = _DRIVERS[DB_ENGINE]
        host = os.getenv("XORCISM_DB_HOST", "localhost")
        port = os.getenv("XORCISM_DB_PORT", "5432" if "postgresql" in driver else "3306")
        user = urllib.parse.quote_plus(os.getenv("XORCISM_DB_USER", "xorcism"))
        pw = urllib.parse.quote_plus(os.getenv("XORCISM_DB_PASSWORD", ""))
        dbname = (os.getenv("XORCISM_DB_PREFIX", "") + name).lower()
        return f"{driver}://{user}:{pw}@{host}:{port}/{dbname}"
    # default: one SQLite file per logical DB
    return f"sqlite:///{os.path.join(DB_DIR, name + '.db')}"


# SQLAlchemy database URLs (per logical DB), built for the configured engine.
DATABASES = {name: database_url(name) for name in LOGICAL_DBS}

# Email (was in App.config)
SMTP_SERVER   = os.getenv("SMTP_SERVER",   "smtp.example.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = "contact@hackenaton.org"

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
