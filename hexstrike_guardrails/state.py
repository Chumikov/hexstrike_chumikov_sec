"""GuardrailsState — orchestrates the five guardrail components.

Single per-process singleton (created by :func:`get_state` and reset by
:func:`reset_state` in tests) that exposes:

    * :class:`ScopeValidator`
    * :class:`TargetRateLimiter`
    * :class:`KillSwitch`
    * :class:`AuditLogger`
    * the scope rules loaded from the ``metadata`` table

The :meth:`check` method is the integration point used by the Flask wrapper
in :mod:`hexstrike_guardrails.blueprint` (Phase 7) and by the decorator on
``execute_command_with_recovery`` in ``hexstrike_server.py``. It returns a
:class:`Decision` describing whether to allow or block the call, and writes
an audit row for either outcome.

Configuration is read from environment variables once at construction:

    ============================ =========================================
    Env var                      Meaning
    ============================ =========================================
    ``GUARDRAILS_MAX_CONCURRENT`` Per-target concurrency (default 5)
    ``GUARDRAILS_MAX_RPS``        Per-target requests/sec (default 10)
    ``GUARDRAILS_RATE_TIMEOUT``   Blocking acquire timeout sec (default 0.0)
    ``GUARDRAILS_AUTOCONFIRM``    If ``1``, destructive tools skip the
                                  confirmation requirement (default ``0``)
    ============================ =========================================
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .audit import AuditLogger, AuditStatus
from .killswitch import KillSwitch
from .rate_limiter import TargetRateLimiter
from .scope import ScopeValidator
from .tiers import Tier, classify_tool

logger = logging.getLogger(__name__)


class GuardrailsBlocked(Exception):
    """Raised by :meth:`GuardrailsState.enforce` when a call is blocked.

    Attributes:
        reason:    one of ``scope`` / ``tier`` / ``rate`` / ``kill`` / ``error``
        tier:      Tier of the tool that was blocked
        target:    target that was being tested
        tool:      tool name that was being dispatched
        detail:    optional human-readable extra info (e.g. matched rule)
    """

    def __init__(
        self,
        reason: str,
        *,
        tier: Optional[Tier] = None,
        target: Optional[str] = None,
        tool: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        super().__init__(f"guardrails blocked: {reason} (tool={tool}, target={target})")
        self.reason = reason
        self.tier = tier
        self.target = target
        self.tool = tool
        self.detail = detail

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": "guardrails_blocked",
            "reason": self.reason,
            "tier": self.tier.value if isinstance(self.tier, Tier) else self.tier,
            "target": self.target,
            "tool": self.tool,
            "detail": self.detail,
        }


@dataclass
class Decision:
    """Outcome of :meth:`GuardrailsState.check`."""

    allowed: bool
    tier: Tier
    reason: Optional[str] = None      # set when ``allowed is False``
    detail: Optional[str] = None      # extra context (e.g. matched rule)
    duration_ms: Optional[int] = None


# ---------------------------------------------------------------------------
# Scope persistence helpers
# ---------------------------------------------------------------------------

_SCOPE_KEY = "default_scope_rules"


def _load_scope_rules() -> List[str]:
    """Read the persisted default scope from the ``metadata`` table."""
    from ._db import get_connection
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = ?", (_SCOPE_KEY,)
            ).fetchone()
    except Exception:
        logger.exception("scope rules load failed; defaulting to empty")
        return []
    if not row:
        return []
    import json
    try:
        raw = json.loads(row["value"] or "[]")
        return [str(r) for r in raw if isinstance(r, str) and r.strip()]
    except (ValueError, TypeError):
        logger.warning("scope rules stored value is not JSON: %r", row["value"])
        return []


def _store_scope_rules(rules: List[str]) -> None:
    import json
    payload = json.dumps([str(r) for r in rules if str(r).strip()])
    from ._db import get_connection
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (_SCOPE_KEY, payload),
        )


# ---------------------------------------------------------------------------
# GuardrailsState
# ---------------------------------------------------------------------------


class GuardrailsState:
    """Top-level orchestrator. One instance per process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.rate_limiter = TargetRateLimiter(
            max_concurrent=_env_int("GUARDRAILS_MAX_CONCURRENT", 5),
            max_rps=_env_int("GUARDRAILS_MAX_RPS", 10),
        )
        self.kill_switch = KillSwitch()
        self.audit = AuditLogger()
        self._rate_timeout = _env_float("GUARDRAILS_RATE_TIMEOUT", 0.0)
        self._autoconfirm = _env_int("GUARDRAILS_AUTOCONFIRM", 0) == 1
        rules = _load_scope_rules()
        self.scope_validator = ScopeValidator(rules)

    # ------------------------------------------------------------------
    @property
    def autoconfirm_destructive(self) -> bool:
        return self._autoconfirm

    def set_autoconfirm(self, value: bool) -> None:
        self._autoconfirm = bool(value)

    # ------------------------------------------------------------------
    def update_scope(self, rules: List[str]) -> None:
        """Replace the active scope (validates each rule, persists to DB)."""
        # Will raise ScopeParseError on bad input.
        new_validator = ScopeValidator(rules)
        with self._lock:
            self.scope_validator = new_validator
        _store_scope_rules(rules)

    def get_scope(self) -> List[str]:
        with self._lock:
            return self.scope_validator.to_raw_list()

    # ------------------------------------------------------------------
    def check(
        self,
        tool: str,
        target: Optional[str],
        params: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        confirmed: bool = False,
    ) -> Decision:
        """Run all guardrail gates and audit the outcome.

        Returns a :class:`Decision` (``allowed=True`` means proceed). The
        caller is responsible for calling :meth:`release_target` when done
        with the dispatch.
        """
        start = time.time()
        tier = classify_tool(tool, params)

        # 1) Global kill switch.
        if self.kill_switch.is_engaged():
            self.audit.log(session_id, tool, target, tier,
                           AuditStatus.KILLED, error="kill switch engaged")
            return Decision(False, tier, reason="kill",
                            detail="kill_switch_engaged",
                            duration_ms=_elapsed_ms(start))

        # 2) Scope (only when at least one rule is configured).
        if self.scope_validator.has_rules() and target:
            in_scope, matched = self.scope_validator.validate(target)
            if not in_scope:
                self.audit.log(session_id, tool, target, tier,
                               AuditStatus.BLOCKED_SCOPE,
                               error=f"target {target!r} not in scope")
                return Decision(False, tier, reason="scope",
                                detail=f"target out of scope",
                                duration_ms=_elapsed_ms(start))

        # 3) Tier confirmation for destructive tools.
        if tier is Tier.DESTRUCTIVE and not self._autoconfirm and not confirmed:
            self.audit.log(session_id, tool, target, tier,
                           AuditStatus.BLOCKED_TIER,
                           error="destructive requires confirmation")
            return Decision(False, tier, reason="tier",
                            detail="destructive requires confirmation",
                            duration_ms=_elapsed_ms(start))

        # 4) Rate limit (concurrency + rps).
        if target:
            acquired = self.rate_limiter.acquire(target, timeout=self._rate_timeout)
            if not acquired:
                self.audit.log(session_id, tool, target, tier,
                               AuditStatus.BLOCKED_RATE,
                               error="rate limit exceeded")
                return Decision(False, tier, reason="rate",
                                detail="rate limit exceeded",
                                duration_ms=_elapsed_ms(start))

        # All gates passed.
        self.audit.log(session_id, tool, target, tier, AuditStatus.ALLOWED)
        return Decision(True, tier, duration_ms=_elapsed_ms(start))

    def release_target(self, target: Optional[str]) -> None:
        """Release the rate-limit slot acquired by :meth:`check`.

        Must be called once for every successful ``check`` (i.e. one whose
        Decision was ``allowed=True`` and that had a non-empty target).
        """
        if target:
            self.rate_limiter.release(target)

    # ------------------------------------------------------------------
    def enforce(
        self,
        tool: str,
        target: Optional[str],
        fn: Callable[[], Any],
        *,
        params: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        confirmed: bool = False,
    ) -> Any:
        """Run :meth:`check`, then ``fn``, then release — or raise.

        Suitable for wrapping the inner callable of a tool dispatch site:

            result = state.enforce("nmap", target, lambda: do_nmap(...),
                                   params=params, session_id=sid)
        """
        decision = self.check(tool, target, params=params,
                              session_id=session_id, confirmed=confirmed)
        if not decision.allowed:
            raise GuardrailsBlocked(
                decision.reason or "unknown",
                tier=decision.tier, target=target, tool=tool,
                detail=decision.detail,
            )
        try:
            return fn()
        finally:
            self.release_target(target)

    # ------------------------------------------------------------------
    def snapshot(self) -> Dict[str, Any]:
        """Return a serialisable view of the whole guardrails state."""
        return {
            "scope_rules": self.get_scope(),
            "rate_limiter": self.rate_limiter.snapshot(),
            "kill_switch": self.kill_switch.snapshot(),
            "audit": self.audit.snapshot(),
            "autoconfirm_destructive": self._autoconfirm,
            "tier_counts": {
                t.value: sum(1 for v in __import__(
                    "hexstrike_guardrails.tiers", fromlist=["TOOL_TIERS"]
                ).TOOL_TIERS.values() if v is t)
                for t in Tier
            },
        }


# ---------------------------------------------------------------------------
# Helpers + singleton
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("env %s=%r is not int, using default %d", name, raw, default)
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("env %s=%r is not float, using default %f", name, raw, default)
        return default


def _elapsed_ms(start: float) -> int:
    return int((time.time() - start) * 1000)


# Module-level singleton. Tests reset it via ``reset_state``.
_STATE: Optional[GuardrailsState] = None
_STATE_LOCK = threading.Lock()


def get_state() -> GuardrailsState:
    """Return the module-wide singleton, creating it on first access."""
    global _STATE
    if _STATE is None:
        with _STATE_LOCK:
            if _STATE is None:
                _STATE = GuardrailsState()
    return _STATE


def reset_state() -> None:
    """Discard the singleton (tests use this to isolate state)."""
    global _STATE
    with _STATE_LOCK:
        _STATE = None
