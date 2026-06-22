"""Thread-safe SQLite connection layer for guardrails and pentest_session.

Design notes
------------
* Each call to :func:`get_connection` opens a short-lived, thread-local
  ``sqlite3.Connection`` and yields it. The caller never closes the connection
  explicitly; the context manager handles commit/rollback/close.
* ``check_same_thread=False`` is acceptable because every public function in
  this package uses :func:`get_connection` inside a ``with`` block (one
  connection per logical operation, never shared across threads).
* WAL journal mode (``PRAGMA journal_mode=WAL``) allows concurrent readers
  while a single writer holds the database; this matches the load profile
  of HexStrike (many tool calls producing audit_log rows in parallel).
* ``init_db`` is idempotent and cheap (``CREATE TABLE IF NOT EXISTS``),
  but we still wrap it in a module-level ``_INITIALISED`` flag to avoid the
  extra round-trip on every request that netcuter's reference code paid.

The :func:`set_db_path` hook exists for tests (``tmp_path`` fixture) and
for the ``GUARDRAILS_DB`` environment variable at import time.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

__all__ = ["get_connection", "init_db", "set_db_path", "get_db_path"]

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DB_PATH = _REPO_ROOT / "data" / "hexstrike_sessions.db"
_SCHEMA_FILE = _REPO_ROOT / "schemas" / "hexstrike_sessions.sql"

_DB_PATH: Path = Path(
    os.environ.get("GUARDRAILS_DB", str(_DEFAULT_DB_PATH))
)
_INITIALISED: bool = False
_INIT_LOCK = threading.Lock()


def set_db_path(path: Path | str) -> None:
    """Override the database path (mainly for tests).

    Resets the ``_INITIALISED`` flag so the next :func:`get_connection` call
    re-runs the schema bootstrap against the new file.
    """
    global _DB_PATH, _INITIALISED
    with _INIT_LOCK:
        _DB_PATH = Path(path)
        _INITIALISED = False


def get_db_path() -> Path:
    return _DB_PATH


def init_db() -> None:
    """Create the database file and all tables/indexes if they don't exist.

    Safe to call repeatedly; runs the schema SQL inside a single transaction.
    Acquires ``_INIT_LOCK`` to guarantee that two concurrent first-callers
    (e.g. two Gunicorn workers booting at once) do not race.
    """
    global _INITIALISED
    with _INIT_LOCK:
        if _INITIALISED:
            return
        db_path = _DB_PATH
        db_path.parent.mkdir(parents=True, exist_ok=True)
        if not _SCHEMA_FILE.is_file():
            # Schemas directory missing (e.g. source-only install) - defer.
            logger.warning(
                "Schema file not found at %s; skipping init_db", _SCHEMA_FILE
            )
            return
        schema_sql = _SCHEMA_FILE.read_text(encoding="utf-8")
        # connect once just to apply schema + WAL pragma.
        conn = sqlite3.connect(str(db_path))
        try:
            # https://www.sqlite.org/wal.html
            conn.execute("PRAGMA journal_mode=WAL")
            # Foreign keys are off by default in SQLite; turn them on so
            # ON DELETE CASCADE on findings/recon_data/audit_log works.
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript(schema_sql)
            conn.commit()
        finally:
            conn.close()
        _INITIALISED = True
        logger.debug("guardrails DB initialised at %s", db_path)


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Yield a short-lived SQLite connection configured for guardrails use.

    * Enables WAL and ``foreign_keys=ON`` on every connection (cheap).
    * Commits on clean exit, rolls back on exception, always closes.
    """
    if not _INITIALISED:
        init_db()
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        # WAL is a persistent DB property but the pragma is cheap; keep it
        # explicit so tests that override the path also get WAL.
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
