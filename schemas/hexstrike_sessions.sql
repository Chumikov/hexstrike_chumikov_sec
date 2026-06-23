-- HexStrike Guardrails + Pentest Session schema (v6.4.0+)
--
-- Single SQLite database shared by:
--   * hexstrike_guardrails/audit.py      -> audit_log, kill_switch_events
--   * hexstrike_guardrails/scope.py      -> metadata (default_scope_rules)
--   * pentest_session.py                 -> sessions, findings, recon_data
--
-- All IDs are uuid4().hex (32 chars) or short prefixes (12-16 chars).
-- Timestamps are RFC3339 UTC strings produced by datetime.now(timezone.utc).isoformat().
--
-- Future (v6.5.0 P2): checkpoints table will be added on top of this schema.

-- ============================================================================
-- Sessions (pentest_session.py)
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,                          -- uuid4().hex[:16]
    target        TEXT NOT NULL,
    name          TEXT,
    scope         TEXT,                                      -- human-readable scope description
    scope_rules   TEXT NOT NULL DEFAULT '[]',                -- JSON array of scope rules
    tester        TEXT,
    status        TEXT NOT NULL DEFAULT 'active',            -- active | closed | killed
    metadata      TEXT NOT NULL DEFAULT '{}',                -- JSON object
    created_at    TEXT NOT NULL,                             -- RFC3339 UTC
    updated_at    TEXT NOT NULL,                             -- RFC3339 UTC
    closed_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);

-- ============================================================================
-- Findings (pentest_session.py)
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,                        -- uuid4().hex[:16]
    session_id      TEXT NOT NULL
                    REFERENCES sessions(id) ON DELETE CASCADE,
    tool            TEXT,
    target          TEXT,
    vuln_type       TEXT,
    severity        TEXT NOT NULL,                           -- critical|high|medium|low|info
    cvss_score      REAL NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    evidence        TEXT,
    endpoint        TEXT,
    recommendation  TEXT,
    is_confirmed    INTEGER NOT NULL DEFAULT 0,              -- bool 0/1
    is_fp           INTEGER NOT NULL DEFAULT 0,              -- bool 0/1 (false positive)
    raw_output      TEXT,
    created_at      TEXT NOT NULL,                           -- RFC3339 UTC
    -- Deduplication guard (P10 from audit): same tool+title+endpoint within a session
    -- is allowed (re-scan) but consumers may collapse by this key.
    UNIQUE (session_id, tool, title, endpoint)
);
CREATE INDEX IF NOT EXISTS idx_findings_session   ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_confirmed ON findings(is_confirmed);
CREATE INDEX IF NOT EXISTS idx_findings_fp        ON findings(is_fp);

-- ============================================================================
-- Recon data (pentest_session.py) — separate append-only log per session
-- ============================================================================
CREATE TABLE IF NOT EXISTS recon_data (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL
                  REFERENCES sessions(id) ON DELETE CASCADE,
    data_type     TEXT NOT NULL,                             -- ports | dns | headers | endpoints | technologies | misc
    data          TEXT NOT NULL,                             -- JSON-encoded value
    source_tool   TEXT,
    created_at    TEXT NOT NULL                              -- RFC3339 UTC
);
CREATE INDEX IF NOT EXISTS idx_recon_session ON recon_data(session_id);
CREATE INDEX IF NOT EXISTS idx_recon_type    ON recon_data(data_type);

-- ============================================================================
-- Audit log (hexstrike_guardrails/audit.py)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT,                                      -- nullable for system-wide events
    tool          TEXT NOT NULL,
    target        TEXT,
    tier          TEXT NOT NULL,                             -- SAFE | INTRUSIVE | DESTRUCTIVE
    status        TEXT NOT NULL,                             -- allowed|blocked_scope|blocked_tier|blocked_rate|killed|error
    duration_ms   INTEGER,
    error         TEXT,
    created_at    TEXT NOT NULL                              -- RFC3339 UTC
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_status  ON audit_log(status);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

-- ============================================================================
-- Kill switch events (hexstrike_guardrails/killswitch.py)
-- ============================================================================
CREATE TABLE IF NOT EXISTS kill_switch_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT,                                      -- nullable = kill-all
    reason        TEXT,
    killed_count  INTEGER NOT NULL DEFAULT 0,
    failed_count  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL                              -- RFC3339 UTC
);
CREATE INDEX IF NOT EXISTS idx_kills_session ON kill_switch_events(session_id);
CREATE INDEX IF NOT EXISTS idx_kills_created ON kill_switch_events(created_at);

-- ============================================================================
-- Metadata (key/value store for guardrails configuration)
-- ============================================================================
CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Seed: empty default scope (allow-all). Updated via PUT /api/guardrails/scope.
INSERT OR IGNORE INTO metadata(key, value) VALUES ('default_scope_rules', '[]');
INSERT OR IGNORE INTO metadata(key, value) VALUES ('schema_version', 'v6.4.0');
