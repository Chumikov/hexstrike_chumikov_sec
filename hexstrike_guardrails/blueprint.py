"""Flask blueprint registering all guardrails HTTP endpoints.

Used by ``hexstrike_server.py``::

    from hexstrike_guardrails import register_guardrails
    register_guardrails(app)         # before app.run()

This mounts two blueprints:

    * ``guardrails_bp``  at ``/api/guardrails/*``  — scope, tiers, kill switch
    * ``session_audit_bp`` at ``/api/session/<id>/audit``
      and ``/api/session/<id>/kill``

The session-management CRUD endpoints (create / list / finding / report) are
**not** registered here — they live in :mod:`pentest_session` (Phase 8).

Endpoints
---------
    GET    /api/guardrails/state           — snapshot of all guardrails
    GET    /api/guardrails/scope           — current default scope rules
    PUT    /api/guardrails/scope           — replace default scope rules
    POST   /api/guardrails/validate        — {target, session_id?} -> {in_scope, matched}
    GET    /api/guardrails/tiers           — {tool: tier} mapping
    GET    /api/guardrails/tier-summary    — counts per tier
    POST   /api/guardrails/kill-all        — engage global kill switch
    POST   /api/guardrails/reset           — disengage global kill switch
    GET    /api/guardrails/audit           — recent audit events (optional filters)
    POST   /api/session/<id>/kill          — engage session-scoped kill switch
    GET    /api/session/<id>/audit         — per-session audit trail

The wrapper that enforces scope/tier/rate on tool dispatch is exposed via
:meth:`wrap_executor` and is invoked from ``hexstrike_server.py`` to decorate
``execute_command_with_recovery`` (see Phase 7 integration commit).
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Dict, Optional

from flask import Blueprint, Flask, jsonify, request

from .audit import AuditLogger, AuditStatus
from .killswitch import KillSwitch
from .scope import ScopeParseError, ScopeValidator
from .state import GuardrailsBlocked, GuardrailsState, get_state
from .tiers import TOOL_TIERS, Tier, classify_tool, tiers_summary

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Blueprint factories
# ---------------------------------------------------------------------------


def _get_state_or_500():
    """Helper for endpoints: return (state, None) or (None, error_response)."""
    try:
        return get_state(), None
    except Exception as exc:
        logger.exception("guardrails state unavailable")
        return None, (jsonify({"error": "guardrails_unavailable",
                                "detail": str(exc)}), 503)


def _json_body() -> Dict[str, Any]:
    """Best-effort JSON body extraction (force=False so 400 is raised by Flask)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return {}
    return data


def build_guardrails_bp() -> Blueprint:
    """Endpoints under ``/api/guardrails/*``."""
    bp = Blueprint("guardrails", __name__, url_prefix="/api/guardrails")

    @bp.get("/state")
    def get_state_endpoint():
        state, err = _get_state_or_500()
        if err:
            return err
        return jsonify(state.snapshot())

    @bp.get("/scope")
    def get_scope():
        state, err = _get_state_or_500()
        if err:
            return err
        return jsonify({"rules": state.get_scope()})

    @bp.put("/scope")
    def put_scope():
        state, err = _get_state_or_500()
        if err:
            return err
        data = _json_body()
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list):
            return jsonify({"error": "rules must be a list of strings"}), 400
        try:
            rules = [str(r) for r in raw_rules]
            state.update_scope(rules)
        except ScopeParseError as exc:
            return jsonify({"error": "invalid_scope_rule", "detail": str(exc)}), 400
        return jsonify({"rules": state.get_scope()})

    @bp.post("/validate")
    def validate_target():
        state, err = _get_state_or_500()
        if err:
            return err
        data = _json_body()
        target = data.get("target")
        if not isinstance(target, str) or not target.strip():
            return jsonify({"error": "target must be a non-empty string"}), 400
        in_scope, matched = state.scope_validator.validate(target)
        return jsonify({
            "target": target,
            "in_scope": in_scope,
            "matched_rule": matched,
            "scope_size": len(state.get_scope()),
        })

    @bp.get("/tiers")
    def get_tiers():
        # Returns the canonical mapping tool -> tier value.
        return jsonify({name: t.value for name, t in TOOL_TIERS.items()})

    @bp.get("/tier-summary")
    def get_tier_summary():
        return jsonify(tiers_summary())

    @bp.post("/kill-all")
    def kill_all():
        state, err = _get_state_or_500()
        if err:
            return err
        reason = (_json_body().get("reason") or "manual") if request.data else "manual"
        report = state.kill_switch.engage(session_id=None, reason=str(reason))
        return jsonify(report.to_dict())

    @bp.post("/reset")
    def reset_kill_switch():
        state, err = _get_state_or_500()
        if err:
            return err
        was = state.kill_switch.reset()
        return jsonify({"was_engaged": was, "engaged": False})

    @bp.get("/audit")
    def get_audit():
        state, err = _get_state_or_500()
        if err:
            return err
        session_id = request.args.get("session_id")
        status = request.args.get("status")
        try:
            limit = max(0, min(500, int(request.args.get("limit", 100))))
        except ValueError:
            limit = 100
        try:
            offset = max(0, int(request.args.get("offset", 0)))
        except ValueError:
            offset = 0
        events = state.audit.get_events(
            session_id=session_id, status=status,
            limit=limit, offset=offset,
        )
        return jsonify({
            "events": events,
            "counts": state.audit.count_by_status(),
            "total": state.audit.count_total(),
            "limit": limit,
            "offset": offset,
        })

    return bp


def build_session_audit_bp() -> Blueprint:
    """Endpoints under ``/api/session/<id>/...`` that depend on guardrails."""
    bp = Blueprint("session_guardrails", __name__, url_prefix="/api/session")

    @bp.post("/<session_id>/kill")
    def kill_session(session_id: str):
        state, err = _get_state_or_500()
        if err:
            return err
        reason = (_json_body().get("reason") or "session_terminate") if request.data else "session_terminate"
        report = state.kill_switch.engage(
            session_id=session_id, reason=str(reason),
        )
        return jsonify(report.to_dict())

    @bp.get("/<session_id>/audit")
    def session_audit(session_id: str):
        state, err = _get_state_or_500()
        if err:
            return err
        try:
            limit = max(0, min(500, int(request.args.get("limit", 100))))
        except ValueError:
            limit = 100
        try:
            offset = max(0, int(request.args.get("offset", 0)))
        except ValueError:
            offset = 0
        events = state.audit.get_events(
            session_id=session_id, limit=limit, offset=offset,
        )
        counts = state.audit.count_by_status(session_id=session_id)
        return jsonify({
            "session_id": session_id,
            "events": events,
            "counts": counts,
            "total": state.audit.count_total(session_id),
            "limit": limit,
            "offset": offset,
        })

    return bp


# ---------------------------------------------------------------------------
# Wrapper decorator for execute_command_with_recovery integration
# ---------------------------------------------------------------------------


def wrap_executor(
    fn: Callable[..., Any],
    *,
    tool_arg: str = "tool_name",
    target_arg: str = "target",
    params_arg: Optional[str] = "parameters",
    session_id_arg: Optional[str] = "session_id",
) -> Callable[..., Any]:
    """Wrap an executor so each call passes through guardrails.

    The wrapper inspects the call's keyword args for ``tool_arg``,
    ``target_arg``, ``params_arg`` and ``session_id_arg`` and feeds them to
    :meth:`GuardrailsState.enforce`. If the call is blocked the resulting
    :class:`GuardrailsBlocked` propagates to the caller (the Flask error
    handler in :mod:`hexstrike_server.py` converts it into a JSON 403).

    Designed to decorate ``execute_command_with_recovery(tool_name, command,
    parameters, session_id=None)`` in ``hexstrike_server.py``::

        from hexstrike_guardrails import wrap_executor
        execute_command_with_recovery = wrap_executor(
            execute_command_with_recovery,
        )

    The wrapper falls through to ``fn`` if the guardrails state cannot be
    initialised (defensive: the server still works without guardrails DB).
    """
    @functools.wraps(fn)
    def decorated(*args, **kwargs):
        try:
            state = get_state()
        except Exception:  # pragma: no cover - defensive
            logger.exception("guardrails unavailable; calling executor bare")
            return fn(*args, **kwargs)

        tool = kwargs.get(tool_arg)
        target = kwargs.get(target_arg)
        params = kwargs.get(params_arg) if params_arg else None
        session_id = kwargs.get(session_id_arg) if session_id_arg else None

        # If the caller passed positional args, try to pull them by signature
        # best-effort. Most call sites use kwargs (see hexstrike_server.py).
        if not tool and args:
            tool = str(args[0])
        if target is None and isinstance(params, dict):
            target = params.get("target") or params.get("host")

        if not tool:
            # No tool context — bypass guardrails but audit the bare call.
            return fn(*args, **kwargs)

        tier = classify_tool(tool, params)
        # Destructive tools without confirmation: block (unless autoconfirm).
        confirmed = bool(kwargs.get("confirmed") or
                         (isinstance(params, dict) and params.get("confirmed")))

        try:
            decision = state.check(tool, target, params=params,
                                   session_id=session_id, confirmed=confirmed)
            if not decision.allowed:
                raise GuardrailsBlocked(
                    decision.reason or "unknown",
                    tier=decision.tier, target=target, tool=tool,
                    detail=decision.detail,
                )
        except GuardrailsBlocked:
            raise
        except Exception:  # pragma: no cover - defensive
            logger.exception("guardrails check crashed; allowing call")
            return fn(*args, **kwargs)

        try:
            return fn(*args, **kwargs)
        finally:
            state.release_target(target)

    return decorated


# ---------------------------------------------------------------------------
# register_guardrails — top-level entry point
# ---------------------------------------------------------------------------


def register_guardrails(app: Flask) -> GuardrailsState:
    """Initialise guardrails on ``app`` and register all blueprints.

    Returns the :class:`GuardrailsState` singleton so the caller can poke at
    it (e.g. for tests or for the /health endpoint's template context).
    """
    state = get_state()
    if "guardrails" not in app.blueprints:
        app.register_blueprint(build_guardrails_bp())
    if "session_guardrails" not in app.blueprints:
        app.register_blueprint(build_session_audit_bp())

    @app.errorhandler(GuardrailsBlocked)
    def _handle_blocked(exc: GuardrailsBlocked):
        resp = exc.to_dict()
        status = 403
        if exc.reason in {"rate"}:
            status = 429
        elif exc.reason in {"kill"}:
            status = 503
        return jsonify(resp), status

    logger.info(
        "guardrails registered: scope_size=%d autoconfirm=%s",
        len(state.get_scope()), state.autoconfirm_destructive,
    )
    return state
