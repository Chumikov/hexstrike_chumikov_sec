"""HexStrike Guardrails package (v6.4.0+).

Public API — re-exported from submodules::

    from hexstrike_guardrails import (
        Tier, classify_tool, TOOL_TIERS,
        ScopeValidator, ScopeRule,
        TargetRateLimiter,
        KillSwitch,
        AuditLogger, AuditStatus,
        GuardrailsState, GuardrailsBlocked, get_state,
        register_guardrails,
    )

Components are imported lazily through ``__getattr__`` so that importing this
package (e.g. for ``hexstrike_guardrails.__version__``) is cheap and does not
require Flask or SQLite to be initialised.
"""

from __future__ import annotations

__version__ = "6.4.0"

# Database helpers are tiny and side-effect free at import time — safe to
# expose eagerly for tests and for pentest_session.py.
from ._db import get_connection, init_db, set_db_path, get_db_path

_PUBLIC_NAMES = {
    # tiers
    "Tier", "classify_tool", "TOOL_TIERS", "ALL_KNOWN_TOOLS",
    # scope
    "ScopeValidator", "ScopeRule", "ScopeParseError",
    # rate limiter
    "TargetRateLimiter",
    # kill switch
    "KillSwitch",
    # audit
    "AuditLogger", "AuditEvent", "AuditStatus",
    # state + blueprint
    "GuardrailsState", "GuardrailsBlocked", "get_state", "register_guardrails",
}

_SUBMODULE_OF = {
    "Tier": "tiers", "classify_tool": "tiers", "TOOL_TIERS": "tiers",
    "ALL_KNOWN_TOOLS": "tiers",
    "ScopeValidator": "scope", "ScopeRule": "scope", "ScopeParseError": "scope",
    "TargetRateLimiter": "rate_limiter",
    "KillSwitch": "killswitch",
    "AuditLogger": "audit", "AuditEvent": "audit", "AuditStatus": "audit",
    "GuardrailsState": "state", "GuardrailsBlocked": "state", "get_state": "state",
    "register_guardrails": "blueprint",
}

__all__ = sorted(_PUBLIC_NAMES | {
    "get_connection", "init_db", "set_db_path", "get_db_path", "__version__",
})


def __getattr__(name: str):
    if name in _SUBMODULE_OF:
        from importlib import import_module

        mod = import_module(f".{_SUBMODULE_OF[name]}", __package__)
        try:
            return getattr(mod, name)
        except AttributeError as exc:  # pragma: no cover - defensive
            raise ImportError(
                f"cannot import {name!r} from hexstrike_guardrails."
                f"_{_SUBMODULE_OF[name]}"
            ) from exc
    raise AttributeError(f"module 'hexstrike_guardrails' has no attribute {name!r}")


def __dir__() -> list[str]:
    return list(__all__)
