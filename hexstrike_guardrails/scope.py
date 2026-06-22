r"""Scope validation (G1).

A *scope* is a list of rules that define which targets (hosts, IPs, networks)
a HexStrike session is allowed to test. An empty scope means "allow all"
(used during the initial bootstrap or for unrestricted engagements).

Rule syntax (auto-detected):

    * ``192.168.0.0/24``              — CIDR (IPv4 or IPv6)
    * ``10.0.0.5``                    — bare IP address (treated as ``/32``)
    * ``example.com``                 — exact hostname match
    * ``*.example.com``               — wildcard: any subdomain, one or more
                                        levels deep (``a.example.com`` and
                                        ``a.b.example.com`` both match)
    * ``r:^internal\.corp\.example$`` — regex (prefix ``r:``), anchored
                                        explicitly by the caller

The validator returns ``(in_scope, matched_rule)`` so the caller can surface
which rule authorized (or would have authorized) the request.

Design decisions vs. netcuter reference (see AUDIT.md §G1-G3):
    * Normalisation uses :func:`urllib.parse.urlsplit` so scheme, userinfo,
      port, path, query and fragment are stripped consistently — including
      bracketed IPv6 literals (``[::1]:8080``) which netcuter's ``split(':')``
      mangled.
    * Regex rules are compiled once and re-used. Patterns longer than 256
      characters are rejected up front to limit catastrophic backtracking
      risk; callers wanting ReDoS hardening should pass simple patterns.
    * ``fnmatch.translate`` is used for wildcards, with the resulting regex
      cached per rule.

Public API:
    * :class:`ScopeRule` — single parsed rule
    * :class:`ScopeValidator` — list of rules, ``validate(target)`` method
    * :exc:`ScopeParseError` — raised when a rule cannot be parsed
"""

from __future__ import annotations

import enum
import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Cap regex pattern size to mitigate ReDoS (AUDIT.md §G2).
_MAX_REGEX_LEN = 256


class ScopeParseError(ValueError):
    """Raised when a scope rule cannot be parsed."""


class RuleType(str, enum.Enum):
    CIDR = "cidr"
    HOSTNAME = "hostname"
    WILDCARD = "wildcard"
    REGEX = "regex"


@dataclass(frozen=True)
class ScopeRule:
    """A single parsed scope rule.

    Attributes:
        raw:      original text the rule was parsed from
        kind:     :class:`RuleType`
        network:  ``ipaddress.ip_network`` when ``kind == CIDR`` else ``None``
        pattern:  lowercase pattern (hostname or wildcard) for non-CIDR rules
        regex:    compiled regex when ``kind in {WILDCARD, REGEX}`` else ``None``
    """

    raw: str
    kind: RuleType
    network: Optional[ipaddress._BaseNetwork] = None
    pattern: Optional[str] = None
    regex: Optional[re.Pattern[str]] = None

    @classmethod
    def parse(cls, raw: str) -> "ScopeRule":
        raw = (raw or "").strip()
        if not raw:
            raise ScopeParseError("empty scope rule")

        # Regex rule: explicit ``r:`` prefix.
        if raw.startswith("r:"):
            pattern = raw[2:]
            if len(pattern) > _MAX_REGEX_LEN:
                raise ScopeParseError(
                    f"regex rule exceeds {_MAX_REGEX_LEN} chars (ReDoS guard)"
                )
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ScopeParseError(f"invalid regex {pattern!r}: {exc}") from exc
            return cls(raw=raw, kind=RuleType.REGEX, regex=compiled, pattern=pattern)

        # Bare IP or CIDR — ipaddress strict=False accepts both
        # ``192.168.0.0/24`` and ``192.168.0.5`` (the latter becomes /32 or /128).
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return cls(raw=raw, kind=RuleType.CIDR, network=net)
        except ValueError:
            pass

        # Wildcard: contains ``*`` or ``?``.
        if "*" in raw or "?" in raw:
            lowered = raw.lower()
            try:
                # fnmatch.translate produces a regex that matches the entire
                # string; cache compiled form for repeat validate() calls.
                compiled = re.compile(fnmatch.translate(lowered), re.IGNORECASE)
            except re.error as exc:  # pragma: no cover - fnmatch never fails
                raise ScopeParseError(f"invalid wildcard {raw!r}: {exc}") from exc
            return cls(raw=raw, kind=RuleType.WILDCARD,
                       pattern=lowered, regex=compiled)

        # Hostname: any non-empty string that didn't match the above.
        # Reject whitespace and obvious garbage early.
        if re.search(r"\s", raw):
            raise ScopeParseError(f"hostname rule {raw!r} contains whitespace")
        lowered = raw.lower().rstrip(".")
        if not lowered:
            raise ScopeParseError("hostname rule reduces to empty after dot strip")
        return cls(raw=raw, kind=RuleType.HOSTNAME, pattern=lowered)

    # ------------------------------------------------------------------
    def matches(self, target: str) -> bool:
        """Return True iff this rule authorises ``target`` (already normalised)."""
        if not target:
            return False

        if self.kind is RuleType.CIDR:
            assert self.network is not None
            try:
                addr = ipaddress.ip_address(target)
            except ValueError:
                # Non-IP target cannot match an IP rule.
                return False
            # ipaddress refuses cross-family comparisons; check version first.
            if addr.version != self.network.version:
                return False
            return addr in self.network

        if self.kind is RuleType.HOSTNAME:
            assert self.pattern is not None
            return target == self.pattern

        # WILDCARD and REGEX both have a compiled regex.
        assert self.regex is not None
        return self.regex.match(target) is not None


# ---------------------------------------------------------------------------
# Hostname / IP normalisation
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def normalize_target(raw: str) -> str:
    """Strip scheme, userinfo, port, path, query, fragment from ``raw``.

    Returns a lowercase hostname or bracket-stripped IP literal. Examples::

        >>> normalize_target("https://example.com:8443/path?q=1")
        'example.com'
        >>> normalize_target("http://[::1]:8080/")
        '::1'
        >>> normalize_target("192.168.0.5:22")
        '192.168.0.5'
        >>> normalize_target("USER:PASS@host.internal")
        'host.internal'
        >>> normalize_target("host.internal.")
        'host.internal'

    Returns an empty string if no usable host could be extracted.
    """
    if raw is None:
        return ""
    text = str(raw).strip()
    if not text:
        return ""

    # If the caller passed a bare "host:port" without scheme, urlsplit treats
    # ``host`` as the path. Inject ``//`` when we detect that case so the
    # netloc parser picks it up.
    if "://" not in text and not text.startswith("//"):
        # heuristic: looks like host:port or just host
        text = "//" + text

    parts = urlsplit(text)
    host = parts.hostname or ""  # urlsplit lowercases hostnames already
    if not host:
        return ""
    return host.rstrip(".")


# ---------------------------------------------------------------------------
# ScopeValidator
# ---------------------------------------------------------------------------


class ScopeValidator:
    """Validate a target against an allowlist of :class:`ScopeRule` instances.

    An empty rule list means "allow all" (``validate()`` returns ``(True, None)``).
    """

    def __init__(self, rules: Sequence[str | ScopeRule] = ()) -> None:
        self._rules: List[ScopeRule] = []
        for entry in rules:
            if isinstance(entry, ScopeRule):
                self._rules.append(entry)
            else:
                self._rules.append(ScopeRule.parse(str(entry)))

    # ------------------------------------------------------------------
    @property
    def rules(self) -> List[ScopeRule]:
        return list(self._rules)

    def has_rules(self) -> bool:
        """``True`` when at least one rule is configured (deny-by-default)."""
        return bool(self._rules)

    def to_raw_list(self) -> List[str]:
        return [r.raw for r in self._rules]

    # ------------------------------------------------------------------
    def validate(self, target: str) -> Tuple[bool, Optional[str]]:
        """Return ``(in_scope, matched_rule_raw)``.

        When no rules are configured, the target is allowed (``matched_rule=None``).
        When at least one rule matches, ``matched_rule`` is the original raw
        text of the matching rule (useful for audit logging).
        """
        if not self._rules:
            return True, None
        host = normalize_target(target)
        if not host:
            # Could not extract a hostname — refuse to fail open.
            logger.warning("scope.validate: target %r reduced to empty", target)
            return False, None
        for rule in self._rules:
            try:
                if rule.matches(host):
                    return True, rule.raw
            except Exception:  # pragma: no cover - defensive
                logger.exception("scope rule %r crashed on %r", rule.raw, host)
                continue
        return False, None

    # ------------------------------------------------------------------
    def add_rule(self, raw: str) -> None:
        """Parse and append ``raw``. Raises :class:`ScopeParseError` on bad input."""
        self._rules.append(ScopeRule.parse(raw))

    def clear(self) -> None:
        self._rules.clear()
