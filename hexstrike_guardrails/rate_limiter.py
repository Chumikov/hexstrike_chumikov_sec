"""Target rate limiter (G3).

Two independent gates per target:

    1. **Concurrency cap** — at most ``max_concurrent`` in-flight tool calls
       per (normalised) target, enforced via a ``threading.Semaphore`` per
       target.
    2. **Request-rate cap** — at most ``max_rps`` tool *starts* per second
       per target, enforced via a sliding-window counter (1-second deque of
       start timestamps).

Both gates are coordinated by :meth:`TargetRateLimiter.acquire` /
:meth:`TargetRateLimiter.release`. The intended call site is the guardrails
wrapper (Phase 7): ``acquire`` before dispatching a tool call, ``release``
inside a ``finally`` once it has finished.

Design choices vs. netcuter reference (see AUDIT.md §G12):
    * ``_semaphores`` / ``_windows`` grow lazily with distinct targets and
      are pruned by :meth:`cleanup_stale` after ``stale_ttl`` seconds of
      inactivity — prevents unbounded memory growth on long-running servers.
    * ``acquire`` returns a boolean rather than blocking forever: the caller
      decides whether to retry, queue, or surface a 429 to the agent.
    * ``release`` is idempotent — calling it twice for the same target is
      safe (matches the behaviour of ``threading.Semaphore.release``).

The class is thread-safe; one shared instance lives in
``GuardrailsState`` (Phase 7).
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

# Sensible defaults; overridable via constructor or env in state.py.
DEFAULT_MAX_CONCURRENT = 5
DEFAULT_MAX_RPS = 10
DEFAULT_STALE_TTL_SEC = 600  # 10 min


@dataclass
class _TargetState:
    """Per-target bookkeeping (guarded by the parent's lock)."""

    semaphore: threading.Semaphore
    last_seen: float = field(default_factory=time.time)
    # Sliding window of call-start timestamps within the last 1s.
    starts: deque = field(default_factory=deque)


class TargetRateLimiter:
    """Per-target concurrency + request-rate limiter."""

    def __init__(
        self,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        max_rps: int = DEFAULT_MAX_RPS,
        stale_ttl_sec: float = DEFAULT_STALE_TTL_SEC,
    ) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        if max_rps < 1:
            raise ValueError("max_rps must be >= 1")
        if stale_ttl_sec < 1:
            raise ValueError("stale_ttl_sec must be >= 1")
        self._max_concurrent = int(max_concurrent)
        self._max_rps = int(max_rps)
        self._stale_ttl = float(stale_ttl_sec)
        self._lock = threading.Lock()
        self._targets: Dict[str, _TargetState] = {}

    # ------------------------------------------------------------------
    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    @property
    def max_rps(self) -> int:
        return self._max_rps

    def tracked_targets(self) -> int:
        """Number of distinct targets currently tracked (for the UI)."""
        with self._lock:
            return len(self._targets)

    # ------------------------------------------------------------------
    def _get_state(self, target: str) -> _TargetState:
        """Must be called under ``self._lock``."""
        st = self._targets.get(target)
        if st is None:
            st = _TargetState(semaphore=threading.Semaphore(self._max_concurrent))
            self._targets[target] = st
        st.last_seen = time.time()
        return st

    def _purge_window(self, st: _TargetState, now: float) -> None:
        """Drop timestamps older than 1s from the sliding window."""
        cutoff = now - 1.0
        while st.starts and st.starts[0] < cutoff:
            st.starts.popleft()

    # ------------------------------------------------------------------
    def check_rate(self, target: str) -> bool:
        """Non-blocking rate check. ``True`` if a call could start *now*.

        Does *not* consume a slot — use :meth:`acquire` for that. Useful for
        pre-flight checks in the UI or audit log.
        """
        with self._lock:
            st = self._targets.get(target)
            if st is None:
                return True
            now = time.time()
            self._purge_window(st, now)
            return len(st.starts) < self._max_rps

    def try_acquire(self, target: str) -> bool:
        """Non-blocking acquire: concurrency + rate. ``True`` on success.

        On success the caller **must** call :meth:`release` when done.
        """
        if not target:
            return False
        with self._lock:
            st = self._get_state(target)
            now = time.time()
            self._purge_window(st, now)
            if len(st.starts) >= self._max_rps:
                return False
            # Semaphore.acquire(blocking=False) — non-blocking.
            if not st.semaphore.acquire(blocking=False):
                return False
            st.starts.append(now)
            return True

    def acquire(self, target: str, timeout: float = 0.0) -> bool:
        """Blocking acquire with up to ``timeout`` seconds wait.

        ``timeout=0`` is equivalent to :meth:`try_acquire`. On success the
        caller **must** call :meth:`release` when done.
        """
        if timeout <= 0:
            return self.try_acquire(target)
        if not target:
            return False
        deadline = time.time() + timeout
        # Spin briefly until both gates open or the deadline expires.
        # We keep the loop cheap (10 ms) so the GIL is not hogged.
        while True:
            if self.try_acquire(target):
                return True
            if time.time() >= deadline:
                return False
            time.sleep(0.01)

    def release(self, target: str) -> None:
        """Release one concurrency slot for ``target``. Idempotent."""
        if not target:
            return
        with self._lock:
            st = self._targets.get(target)
            if st is None:
                # Defensive: release without acquire is a no-op.
                return
            try:
                st.semaphore.release()
            except ValueError:
                # Semaphore already at its initial value — ignore.
                logger.debug("release on idle semaphore for %r", target)

    # ------------------------------------------------------------------
    def cleanup_stale(self, now: float | None = None) -> int:
        """Drop per-target state idle for longer than ``stale_ttl``.

        Returns the number of pruned targets. Intended to be invoked by a
        background timer in :class:`GuardrailsState`; safe to call from any
        thread. Stale targets whose semaphore still has slots borrowed are
        kept to avoid leaking the cap.
        """
        if now is None:
            now = time.time()
        cutoff = now - self._stale_ttl
        pruned = 0
        with self._lock:
            for target in list(self._targets):
                st = self._targets[target]
                if st.last_seen < cutoff:
                    # Only evict when no in-flight call is using the slot.
                    if st.semaphore._value >= self._max_concurrent:  # type: ignore[attr-defined]
                        del self._targets[target]
                        pruned += 1
        if pruned:
            logger.debug("rate limiter pruned %d stale target(s)", pruned)
        return pruned

    # ------------------------------------------------------------------
    def snapshot(self) -> Dict[str, int]:
        """Return summary stats for the health panel."""
        with self._lock:
            in_flight = sum(
                self._max_concurrent - st.semaphore._value  # type: ignore[attr-defined]
                for st in self._targets.values()
            )
            return {
                "tracked_targets": len(self._targets),
                "in_flight_slots": in_flight,
                "max_concurrent": self._max_concurrent,
                "max_rps": self._max_rps,
            }
