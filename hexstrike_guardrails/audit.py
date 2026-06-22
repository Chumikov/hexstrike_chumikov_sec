"""Audit logger (G5).

Append-only journal of every guardrails decision (allowed / blocked) and
tool dispatch, written to the shared SQLite database (table ``audit_log``).

Each row records:

    * ``session_id`` — optional; ``None`` for system-wide events
    * ``tool``       — the tool name the caller tried to invoke
    * ``target``     — the normalised hostname/IP of the dispatch
    * ``tier``       — ``SAFE`` / ``INTRUSIVE`` / ``DESTRUCTIVE`` (see tiers.py)
    * ``status``     — one of :class:`AuditStatus` (allow / blocked reason)
    * ``duration_ms``— wall-clock duration of the dispatch (when applicable)
    * ``error``      — short error description (when applicable)

Design choices vs. netcuter reference (AUDIT.md §G6-G9):
    * Every SQL statement is parameterised (``?`` placeholders).
    * All DB I/O happens inside the ``with get_connection()`` context manager
      from :mod:`hexstrike_guardrails._db`, which guarantees commit/rollback
      and closes the connection in ``finally``.
    * The :class:`AuditLogger` itself is stateless (no per-instance caches)
      and therefore trivially thread-safe; concurrent calls open their own
      short-lived connections.

Public API:
    * :class:`AuditStatus` — enum of allowed status values
    * :class:`AuditEvent`  — convenience dataclass for batched inserts
    * :class:`AuditLogger` — main class, used by ``GuardrailsState``
"""

from __future__ import annotations

import enum
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from ._db import get_connection

logger = logging.getLogger(__name__)


class AuditStatus(str, enum.Enum):
    ALLOWED = "allowed"
    BLOCKED_SCOPE = "blocked_scope"
    BLOCKED_TIER = "blocked_tier"
    BLOCKED_RATE = "blocked_rate"
    KILLED = "killed"
    ERROR = "error"


@dataclass
class AuditEvent:
    session_id: Optional[str]
    tool: str
    target: Optional[str]
    tier: str
    status: AuditStatus
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _utc_now_iso()
        if isinstance(self.status, AuditStatus):
            self.status = self.status  # keep enum for to_dict
        # Normalise: status stored as enum, serialised via .value on write.

    def to_row(self) -> tuple:
        return (
            self.session_id,
            self.tool,
            self.target,
            self.tier if isinstance(self.tier, str) else str(self.tier),
            self.status.value if isinstance(self.status, AuditStatus) else str(self.status),
            self.duration_ms,
            self.error,
            self.created_at,
        )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogger:
    """SQLite-backed audit log for guardrails decisions."""

    table = "audit_log"

    # ------------------------------------------------------------------
    def log(
        self,
        session_id: Optional[str],
        tool: str,
        target: Optional[str],
        tier: str,
        status: AuditStatus | str,
        duration_ms: Optional[int] = None,
        error: Optional[str] = None,
    ) -> None:
        """Insert one audit row. Best-effort: errors are logged, not raised."""
        if isinstance(status, AuditStatus):
            status_value = status.value
        else:
            status_value = str(status)
        tier_value = tier if isinstance(tier, str) else str(tier)
        try:
            with get_connection() as conn:
                conn.execute(
                    f"""INSERT INTO {self.table}
                        (session_id, tool, target, tier, status,
                         duration_ms, error, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (session_id, tool, target, tier_value, status_value,
                     duration_ms, error, _utc_now_iso()),
                )
        except Exception:
            logger.exception(
                "audit.log failed (tool=%s target=%s status=%s)",
                tool, target, status_value,
            )

    def log_event(self, event: AuditEvent) -> None:
        """Convenience wrapper taking an :class:`AuditEvent`."""
        try:
            with get_connection() as conn:
                conn.execute(
                    f"""INSERT INTO {self.table}
                        (session_id, tool, target, tier, status,
                         duration_ms, error, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    event.to_row(),
                )
        except Exception:
            logger.exception("audit.log_event failed: %r", asdict(event))

    def log_many(self, events: Iterable[AuditEvent]) -> int:
        """Batched insert. Returns the number of rows actually written."""
        rows = [e.to_row() for e in events]
        if not rows:
            return 0
        try:
            with get_connection() as conn:
                conn.executemany(
                    f"""INSERT INTO {self.table}
                        (session_id, tool, target, tier, status,
                         duration_ms, error, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    rows,
                )
            return len(rows)
        except Exception:
            logger.exception("audit.log_many failed (%d rows)", len(rows))
            return 0

    # ------------------------------------------------------------------
    def get_events(
        self,
        session_id: Optional[str] = None,
        status: Optional[AuditStatus | str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Read events newest-first. ``session_id=None`` returns system-wide."""
        if limit < 0:
            limit = 0
        if offset < 0:
            offset = 0
        clauses: List[str] = []
        params: List[Any] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(
                status.value if isinstance(status, AuditStatus) else str(status)
            )
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT * FROM {self.table}{where} "
            "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        try:
            with get_connection() as conn:
                rows = conn.execute(sql, params).fetchall()
        except Exception:
            logger.exception("audit.get_events failed")
            return []
        return [dict(r) for r in rows]

    def count_by_status(self, session_id: Optional[str] = None) -> Dict[str, int]:
        """Aggregate counts grouped by ``status`` (for the health panel)."""
        where = "WHERE session_id = ?" if session_id is not None else ""
        params: List[Any] = [session_id] if session_id is not None else []
        sql = (
            f"SELECT status, COUNT(*) AS cnt FROM {self.table} {where} "
            "GROUP BY status"
        )
        out: Dict[str, int] = {s.value: 0 for s in AuditStatus}
        try:
            with get_connection() as conn:
                for row in conn.execute(sql, params).fetchall():
                    out[row["status"]] = int(row["cnt"])
        except Exception:
            logger.exception("audit.count_by_status failed")
        return out

    def count_total(self, session_id: Optional[str] = None) -> int:
        where = "WHERE session_id = ?" if session_id is not None else ""
        params: List[Any] = [session_id] if session_id is not None else []
        try:
            with get_connection() as conn:
                row = conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM {self.table} {where}", params
                ).fetchone()
            return int(row["cnt"]) if row else 0
        except Exception:
            logger.exception("audit.count_total failed")
            return 0

    # ------------------------------------------------------------------
    def snapshot(self, recent_limit: int = 15) -> Dict[str, Any]:
        """Compact summary for the health panel (counts + recent rows)."""
        return {
            "counts": self.count_by_status(),
            "total": self.count_total(),
            "recent": self.get_events(limit=recent_limit),
        }
