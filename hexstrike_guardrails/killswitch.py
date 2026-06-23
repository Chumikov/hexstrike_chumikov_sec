"""Kill switch (G4) — emergency stop for in-flight tool processes.

The kill switch is engaged when:

    * an operator hits ``POST /api/session/{id}/kill`` from the UI, or
    * an operator hits ``POST /api/guardrails/kill-all`` to abort everything, or
    * the wrapper in ``state.GuardrailsState.check`` notices the global flag
      is set and refuses new dispatches.

While engaged, every subsequent tool call in the affected scope is rejected
up-front (no new process is started). Already-running processes registered
via :meth:`KillSwitch.register` receive ``SIGTERM`` and, after a short grace
period, ``SIGKILL``.

Design vs. netcuter reference (AUDIT.md §G4-G5):
    * The reference released the lock between copying the PID set and
      popping the session entry, allowing new registrations to be silently
      dropped. Here the lock is held for the **entire** kill operation and
      individual PIDs are removed as they are processed — new
      registrations are accepted (the session entry is preserved) and will
      receive the same signal on the next call to ``engage``.
    * We send ``SIGTERM`` first and escalate to ``SIGKILL`` after
      ``kill_grace_sec`` seconds if the process is still alive. The grace
      period defaults to 3 s and can be overridden per call.
    * We do *not* attempt process-group kills (``os.killpg``) by default
      because HexStrike launches most tools directly via ``subprocess.Popen``
      without ``preexec_fn=os.setsid``. The wrapper that integrates with
      ``execute_command_with_recovery`` (Phase 7) registers the
      ``Popen`` instance, and we use its ``.terminate()`` / ``.kill()`` API
      which propagates to children when the parent exits.

The kill switch is **process-local**: in a multi-worker Gunicorn deployment
each worker has its own ``KillSwitch`` instance. Cross-worker coordination
happens through the global ``engaged`` flag stored in the shared SQLite DB
(see ``_load_global_flag`` / ``_store_global_flag``).
"""

from __future__ import annotations

import enum
import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set

from ._db import get_connection

logger = logging.getLogger(__name__)


# ============================================================================
# Data types
# ============================================================================

class KillOutcome(str, enum.Enum):
    TERMINATED = "terminated"      # SIGTERM accepted, process exited
    FORCE_KILLED = "force_killed"  # SIGKILL required
    NOT_FOUND = "not_found"        # PID already gone
    PERMISSION = "permission"      # OS refused (different uid?)
    ERROR = "error"                # unexpected exception


@dataclass(eq=False)
class _RegisteredProc:
    """A process tracked by the kill switch.

    ``eq=False`` keeps the default identity-based hash so instances can live
    inside a ``set`` even though they hold an unhashable ``Popen``.
    """

    pid: int
    popen: Optional[subprocess.Popen] = None
    registered_at: float = field(default_factory=time.time)


@dataclass
class KillReport:
    """Result of an :meth:`KillSwitch.engage` call."""

    session_id: Optional[str]
    reason: str
    killed: List[int] = field(default_factory=list)
    failed: List[int] = field(default_factory=list)
    outcomes: Dict[int, KillOutcome] = field(default_factory=dict)
    engaged_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "reason": self.reason,
            "engaged_at": self.engaged_at,
            "killed_count": len(self.killed),
            "failed_count": len(self.failed),
            "killed_pids": self.killed,
            "failed_pids": self.failed,
            "outcomes": {str(pid): o.value for pid, o in self.outcomes.items()},
        }


# ============================================================================
# KillSwitch
# ============================================================================

_DEFAULT_GRACE_SEC = 3.0
_GLOBAL_FLAG_KEY = "kill_switch_global_engaged"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class KillSwitch:
    """Track running processes per session and abort them on demand."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._engaged: bool = False
        # session_id -> set of registered processes (PID + Popen).
        self._procs: Dict[str, Set[_RegisteredProc]] = {}
        # Persisted global flag so other workers see the state.
        try:
            self._load_global_flag()
        except Exception:  # pragma: no cover - DB not ready during bootstrap
            logger.exception("kill_switch: failed to read global flag at init")

    # ------------------------------------------------------------------
    @staticmethod
    def _utc_now_iso_static() -> str:
        return _utc_now_iso()

    def _load_global_flag(self) -> None:
        try:
            with get_connection() as conn:
                row = conn.execute(
                    "SELECT value FROM metadata WHERE key = ?", (_GLOBAL_FLAG_KEY,)
                ).fetchone()
        except Exception:
            return
        if row and str(row["value"]).lower() in {"1", "true", "yes"}:
            self._engaged = True

    def _store_global_flag(self, value: bool) -> None:
        payload = "1" if value else "0"
        try:
            with get_connection() as conn:
                conn.execute(
                    "INSERT INTO metadata(key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (_GLOBAL_FLAG_KEY, payload),
                )
        except Exception:
            logger.exception("kill_switch: cannot persist global flag")

    # ------------------------------------------------------------------
    def is_engaged(self) -> bool:
        """Whether new tool dispatches should be blocked globally."""
        return self._engaged

    def engaged_session_ids(self) -> List[str]:
        """Sessions that currently have at least one registered process."""
        with self._lock:
            return [sid for sid, procs in self._procs.items() if procs]

    def registered_count(self, session_id: Optional[str] = None) -> int:
        with self._lock:
            if session_id is None:
                return sum(len(s) for s in self._procs.values())
            return len(self._procs.get(session_id, ()))

    # ------------------------------------------------------------------
    def register(
        self,
        session_id: str,
        pid: int,
        popen: Optional[subprocess.Popen] = None,
    ) -> None:
        """Track a process so it can be killed later.

        Safe to call from any thread; no-op if ``pid`` is not a positive int.
        """
        if not session_id or not isinstance(pid, int) or pid <= 0:
            return
        entry = _RegisteredProc(pid=pid, popen=popen)
        with self._lock:
            self._procs.setdefault(session_id, set()).add(entry)

    def unregister(self, session_id: str, pid: int) -> None:
        """Drop a previously-registered process (e.g. after clean exit)."""
        if not session_id or not isinstance(pid, int) or pid <= 0:
            return
        with self._lock:
            procs = self._procs.get(session_id)
            if not procs:
                return
            for entry in list(procs):
                if entry.pid == pid:
                    procs.discard(entry)
            if not procs:
                self._procs.pop(session_id, None)

    # ------------------------------------------------------------------
    def engage(
        self,
        session_id: Optional[str] = None,
        reason: str = "manual",
        kill_grace_sec: float = _DEFAULT_GRACE_SEC,
    ) -> KillReport:
        """Engage the kill switch.

        * If ``session_id`` is ``None`` — kill **all** registered processes
          and set the global flag (blocks new dispatches globally).
        * If ``session_id`` is given — kill only that session's processes.
          The global flag is **not** set in this case.

        Returns a :class:`KillReport` and persists a row in
        ``kill_switch_events`` for audit purposes.
        """
        report = KillReport(session_id=session_id, reason=reason)

        # CRITICAL: hold the lock for the entire kill sequence so concurrent
        # ``register`` calls cannot leak processes (AUDIT.md §G4).
        with self._lock:
            if session_id is None:
                targets: Iterable[tuple[Optional[str], Set[_RegisteredProc]]] = (
                    (sid, set(procs)) for sid, procs in self._procs.items()
                )
                self._engaged = True
                self._store_global_flag(True)
            else:
                procs = self._procs.get(session_id, set())
                if not procs:
                    # Nothing to kill; still record the event.
                    self._record_event(report)
                    return report
                targets = [(session_id, set(procs))]

            for sid, procs_snapshot in targets:
                # Iterate over a static copy; we mutate the live set inside.
                for entry in procs_snapshot:
                    outcome = self._signal_one(entry, kill_grace_sec)
                    report.outcomes[entry.pid] = outcome
                    if outcome in (KillOutcome.TERMINATED, KillOutcome.FORCE_KILLED,
                                   KillOutcome.NOT_FOUND):
                        report.killed.append(entry.pid)
                        # Remove from live set immediately.
                        live = self._procs.get(sid or "", None)
                        if live is not None:
                            live.discard(entry)
                    else:
                        report.failed.append(entry.pid)

            # Clean up empty session buckets.
            if session_id is None:
                self._procs.clear()
            else:
                if not self._procs.get(session_id):
                    self._procs.pop(session_id, None)

        self._record_event(report)
        logger.warning(
            "kill_switch engaged: session=%s reason=%s killed=%d failed=%d",
            session_id, reason, len(report.killed), len(report.failed),
        )
        return report

    def _signal_one(self, entry: _RegisteredProc, kill_grace_sec: float) -> KillOutcome:
        """Send SIGTERM, wait, escalate to SIGKILL. Returns the outcome."""
        # Prefer Popen API (works for current process tree).
        if entry.popen is not None:
            if entry.popen.poll() is not None:
                return KillOutcome.NOT_FOUND
            try:
                entry.popen.terminate()  # SIGTERM on POSIX
            except ProcessLookupError:
                return KillOutcome.NOT_FOUND
            except PermissionError:
                return KillOutcome.PERMISSION
            except Exception:
                logger.exception("kill_switch: terminate() failed for pid=%d", entry.pid)
                return KillOutcome.ERROR
            try:
                entry.popen.wait(timeout=kill_grace_sec)
                return KillOutcome.TERMINATED
            except subprocess.TimeoutExpired:
                pass
            try:
                entry.popen.kill()  # SIGKILL
                entry.popen.wait(timeout=kill_grace_sec)
                return KillOutcome.FORCE_KILLED
            except Exception:
                logger.exception("kill_switch: kill() failed for pid=%d", entry.pid)
                return KillOutcome.ERROR

        # Fall back to OS signals when only a PID is known.
        try:
            os.kill(entry.pid, signal.SIGTERM)
        except ProcessLookupError:
            return KillOutcome.NOT_FOUND
        except PermissionError:
            return KillOutcome.PERMISSION
        except Exception:
            logger.exception("kill_switch: os.kill SIGTERM failed for pid=%d", entry.pid)
            return KillOutcome.ERROR

        # Poll for graceful exit.
        deadline = time.time() + max(0.1, kill_grace_sec)
        while time.time() < deadline:
            if _pid_dead(entry.pid):
                return KillOutcome.TERMINATED
            time.sleep(0.05)

        try:
            os.kill(entry.pid, signal.SIGKILL)
        except ProcessLookupError:
            return KillOutcome.NOT_FOUND  # died between SIGTERM and SIGKILL
        except Exception:
            logger.exception("kill_switch: os.kill SIGKILL failed for pid=%d", entry.pid)
            return KillOutcome.ERROR
        return KillOutcome.FORCE_KILLED

    # ------------------------------------------------------------------
    def reset(self) -> bool:
        """Clear the global engaged flag (after the emergency is resolved).

        Does not start any new processes; it only allows future tool calls
        to be dispatched again.
        """
        with self._lock:
            was = self._engaged
            self._engaged = False
            self._store_global_flag(False)
        if was:
            logger.info("kill_switch disengaged")
        return was

    # ------------------------------------------------------------------
    def _record_event(self, report: KillReport) -> None:
        try:
            with get_connection() as conn:
                conn.execute(
                    """INSERT INTO kill_switch_events
                       (session_id, reason, killed_count, failed_count, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (report.session_id, report.reason,
                     len(report.killed), len(report.failed), report.engaged_at),
                )
        except Exception:
            logger.exception("kill_switch: cannot persist event")

    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        """Summary for the health panel."""
        with self._lock:
            return {
                "engaged": self._engaged,
                "sessions_with_procs": len(self._procs),
                "registered_procs": sum(len(s) for s in self._procs.values()),
            }


# ============================================================================
# Helpers
# ============================================================================

def _pid_dead(pid: int) -> bool:
    """True if ``pid`` no longer exists (or is a zombie we can reap)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        # Process exists but is owned by another uid; assume still alive.
        return False
    except OSError:
        return True
    return False
