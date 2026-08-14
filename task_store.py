"""Persistent async-task store for HexStrike (v6.4.7).

Problem
-------
``ProcessPool`` in ``hexstrike_server.py`` kept task state in plain in-process
dicts (``self.results``, ``self.active_tasks``). Under gunicorn
``--max-requests 1000`` every worker is killed and respawned every 1000
requests, silently destroying every in-flight and completed-but-unpolled task.
A long nmap/sqlmap submitted via ``execute_command_async`` would vanish
without a trace; the operator's poll would return ``not_found``.

Solution
-------
Mirror task lifecycle into the shared SQLite database
(``data/hexstrike_sessions.db``) so that state survives worker recycles. The
pool continues to *execute* in-process (we cannot resume a subprocess that was
SIGKILLed), but the **status** is now durable:

* ``submit`` inserts a row with ``status='queued'``.
* ``mark_running`` flips it to ``'running'`` when a worker picks it up.
* ``mark_completed`` / ``mark_failed`` write the result/error.
* On boot, ``recover`` reclassifies any lingering ``'running'`` rows from a
  previous (dead) worker as ``'lost'`` — so a poll after a recycle returns an
  honest ``lost`` instead of a misleading ``not_found``.

The store is best-effort: if SQLite is unavailable, every method degrades to a
no-op and the pool falls back to in-process behaviour. This keeps the server
functional even with a broken/missing DB (defensive design, same principle as
the guardrails wrapper).
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn():
    """Return a live sqlite connection from the shared guardrails DB.

    Imported lazily so that importing this module is cheap and never crashes
    the server on environments where the DB cannot be opened yet.
    """
    from hexstrike_guardrails._db import get_connection
    return get_connection()


def new_task_id() -> str:
    return uuid.uuid4().hex[:16]


def submit(task_id: str, command: Optional[str] = None,
           tool: Optional[str] = None, target: Optional[str] = None) -> bool:
    """Insert a new task row. Returns False (and logs) on DB failure."""
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO async_tasks(id, status, command, tool, target, "
                "submitted_at) VALUES (?,?,?,?,?,?)",
                (task_id, "queued", command, tool, target, _now()),
            )
        return True
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("task_store.submit failed: %s", exc)
        return False


def mark_running(task_id: str, worker_id: Optional[int] = None) -> bool:
    try:
        with _conn() as c:
            c.execute(
                "UPDATE async_tasks SET status='running', started_at=?, "
                "worker_id=? WHERE id=?",
                (_now(), worker_id, task_id),
            )
        return True
    except Exception as exc:  # pragma: no cover
        logger.warning("task_store.mark_running failed: %s", exc)
        return False


def mark_completed(task_id: str, result: Any,
                   execution_time_ms: Optional[int] = None) -> bool:
    try:
        payload = json.dumps(result, default=str)
        with _conn() as c:
            c.execute(
                "UPDATE async_tasks SET status='completed', result=?, "
                "completed_at=?, execution_time_ms=? WHERE id=?",
                (payload, _now(), execution_time_ms, task_id),
            )
        return True
    except Exception as exc:  # pragma: no cover
        logger.warning("task_store.mark_completed failed: %s", exc)
        return False


def mark_failed(task_id: str, error: str,
                execution_time_ms: Optional[int] = None) -> bool:
    try:
        with _conn() as c:
            c.execute(
                "UPDATE async_tasks SET status='failed', error=?, "
                "completed_at=?, execution_time_ms=? WHERE id=?",
                (error, _now(), execution_time_ms, task_id),
            )
        return True
    except Exception as exc:  # pragma: no cover
        logger.warning("task_store.mark_failed failed: %s", exc)
        return False


def get(task_id: str) -> Optional[Dict[str, Any]]:
    """Return a task row as a dict, or None if absent / DB unavailable."""
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT id, status, command, tool, target, result, error, "
                "worker_id, submitted_at, started_at, completed_at, "
                "execution_time_ms FROM async_tasks WHERE id=?",
                (task_id,),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        # Decode the JSON result column for the caller's convenience.
        if d.get("result"):
            try:
                d["result"] = json.loads(d["result"])
            except Exception:
                pass
        return d
    except Exception as exc:  # pragma: no cover
        logger.warning("task_store.get failed: %s", exc)
        return None


def recover() -> int:
    """On boot, mark any leftover 'running'/'queued' rows from a previous
    (dead) worker as 'lost'. Returns the number of rows reclassified.

    Safe to call on every worker start. Idempotent within a boot because the
    UPDATE only touches rows still in a transient state.
    """
    try:
        with _conn() as c:
            cur = c.execute(
                "UPDATE async_tasks SET status='lost', "
                "error=COALESCE(error, 'worker recycled before completion'), "
                "completed_at=COALESCE(completed_at, ?) "
                "WHERE status IN ('running','queued')",
                (_now(),),
            )
            n = cur.rowcount or 0
        if n:
            logger.info("task_store.recover: %d task(s) marked lost", n)
        return n
    except Exception as exc:  # pragma: no cover
        logger.warning("task_store.recover failed: %s", exc)
        return 0


def cleanup_old(days: int = 7) -> int:
    """Delete completed/failed/lost rows older than ``days``. Returns count.

    Keeps the table from growing unbounded across a long engagement.
    """
    try:
        cutoff = (datetime.now(timezone.utc).timestamp()) - days * 86400
        # submitted_at is RFC3339; compare lexicographically against an
        # RFC3339 cutoff to avoid per-row parsing.
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
        with _conn() as c:
            cur = c.execute(
                "DELETE FROM async_tasks WHERE status IN "
                "('completed','failed','lost') AND submitted_at < ?",
                (cutoff_iso,),
            )
            return cur.rowcount or 0
    except Exception as exc:  # pragma: no cover
        logger.warning("task_store.cleanup_old failed: %s", exc)
        return 0
