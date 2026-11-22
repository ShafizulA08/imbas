"""SQLite persistence layer for the recon app."""
import json
import sqlite3
import threading
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "imbas.db"

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    in_scope TEXT DEFAULT 'confirmed',
    notes TEXT DEFAULT '',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued',        -- queued|running|done|error|cancelled
    modules TEXT NOT NULL DEFAULT '[]',           -- JSON list of module names
    options TEXT NOT NULL DEFAULT '{}',           -- JSON scan options
    progress REAL NOT NULL DEFAULT 0,
    current_task TEXT DEFAULT '',
    stats TEXT NOT NULL DEFAULT '{}',
    log TEXT NOT NULL DEFAULT '',
    started_at REAL,
    finished_at REAL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    ip TEXT,
    source TEXT DEFAULT '',
    records TEXT DEFAULT '{}',                    -- JSON: dns records
    UNIQUE(scan_id, hostname)
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    hostname TEXT,
    port INTEGER NOT NULL,
    proto TEXT DEFAULT 'tcp',
    state TEXT DEFAULT 'open',
    service TEXT DEFAULT '',
    banner TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS http_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    url TEXT NOT NULL,
    status INTEGER,
    title TEXT,
    server TEXT,
    tech TEXT DEFAULT '[]',                       -- JSON list
    redirect_to TEXT,
    tls_issuer TEXT,
    tls_expires TEXT,
    headers TEXT DEFAULT '{}',                    -- JSON dict
    header_score REAL,
    UNIQUE(scan_id, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id INTEGER NOT NULL,
    severity TEXT NOT NULL,                       -- critical|high|medium|low|info
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    host TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    recommendation TEXT DEFAULT '',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source TEXT DEFAULT '',
    status INTEGER DEFAULT 0,
    content_type TEXT DEFAULT '',
    interesting INTEGER DEFAULT 0,
    note TEXT DEFAULT '',
    UNIQUE(scan_id, url)
);

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    kind TEXT NOT NULL,
    value_masked TEXT NOT NULL,
    context TEXT DEFAULT '',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    source TEXT DEFAULT '',
    UNIQUE(scan_id, email, source)
);

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    interval_hours REAL NOT NULL DEFAULT 24,
    modules TEXT NOT NULL DEFAULT '[]',          -- JSON list
    options TEXT NOT NULL DEFAULT '{}',          -- JSON scan options
    webhook_url TEXT DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run REAL,
    next_run REAL NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_http_scan ON http_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_urls_scan ON urls(scan_id);
CREATE INDEX IF NOT EXISTS idx_secrets_scan ON secrets(scan_id);
CREATE INDEX IF NOT EXISTS idx_emails_scan ON emails(scan_id);
CREATE INDEX IF NOT EXISTS idx_schedules_target ON schedules(target_id);
"""


def get_db() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()


def query(sql: str, params=()) -> list[dict]:
    cur = get_db().execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def query_one(sql: str, params=()) -> dict | None:
    row = get_db().execute(sql, params).fetchone()
    return dict(row) if row else None


def execute(sql: str, params=()) -> int:
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    return cur.lastrowid


def j(value) -> str:
    return json.dumps(value, default=str)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
