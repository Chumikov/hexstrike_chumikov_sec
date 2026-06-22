"""Tool classification: SAFE / INTRUSIVE / DESTRUCTIVE.

Public API:
    * ``Tier`` — enum with three levels + ``requires_confirmation`` property
    * ``TOOL_TIERS`` — canonical mapping ``{tool_name: Tier}`` for the ~150
      tools known to HexStrike (union of ``/health`` categories in
      ``hexstrike_server.py`` and the 25 MCP tools in ``hexstrike_mcp.py``).
    * ``classify_tool(name, params=None) -> Tier`` — lookup with token-based
      fallback for unknown tools.
    * ``ALL_KNOWN_TOOLS`` — frozenset of every name in ``TOOL_TIERS``.

Design rules (see AUDIT.md §G13):
    * Mapping is code-defined (not external JSON) to avoid an extra runtime
      dependency and to keep the canonical list under version control with
      tests.
    * Unknown tools fall back to ``INTRUSIVE`` (fail-safe: better to gate an
      unknown tool than to allow it silently).
    * Special parameter-aware rules (e.g. ``nmap-advanced`` with
      ``aggressive=True``) live in ``classify_tool``, not in the mapping.

The mapping is consumed by:
    * ``hexstrike_guardrails/state.GuardrailsState.check`` — the per-call
      wrapper that decides allow/block.
    * ``hexstrike_guardrails/blueprint.py`` ``GET /api/guardrails/tiers`` —
      introspection endpoint for the UI / agent.
"""

from __future__ import annotations

import enum
import logging
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)


class Tier(enum.Enum):
    """Three-level blast-radius classification."""

    SAFE = "SAFE"
    INTRUSIVE = "INTRUSIVE"
    DESTRUCTIVE = "DESTRUCTIVE"

    @property
    def requires_confirmation(self) -> bool:
        """Only destructive tools require explicit user/agent confirmation."""
        return self is Tier.DESTRUCTIVE

    @property
    def rank(self) -> int:
        """Numeric severity for sorting (SAFE < INTRUSIVE < DESTRUCTIVE)."""
        return {Tier.SAFE: 0, Tier.INTRUSIVE: 1, Tier.DESTRUCTIVE: 2}[self]

    @classmethod
    def parse(cls, value: str | "Tier") -> "Tier":
        """Best-effort parse from string; unknown values → INTRUSIVE."""
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).upper())
        except ValueError:
            logger.warning("unknown tier %r, defaulting to INTRUSIVE", value)
            return Tier.INTRUSIVE


# ============================================================================
# Canonical mapping — covers all 150+ tools from /health + 25 MCP tools.
# Maintainers: keep categories in alphabetical order within each tier for the
# benefit of diff reviews; do not invent tiers other than the three above.
# ============================================================================

_SAFE_TOOLS: frozenset[str] = frozenset({
    # --- MCP meta / agent utilities (never touch a target) -------------------
    "batch_execute", "get_mcp_stats", "clear_mcp_cache", "server_health",
    "list_files",
    # --- Passive recon (DNS / certificate transparency / APIs) ---------------
    "subfinder", "amass_passive", "httpx_probe", "analyze_target_intelligence",
    "gau", "waybackurls", "theharvester", "sherlock", "social-analyzer",
    "maltego", "shodan", "censys", "have-i-been-pwned", "crtsh",
    # --- Local binary analysis (no network) ----------------------------------
    "gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump", "ghidra",
    "pwntools", "one-gadget", "ropper", "angr", "libc-database", "pwninit",
    "hash-identifier", "ophcrack", "searchsploit", "strings", "xxd", "file",
    "foremost", "exiftool", "photorec", "testdisk", "scalpel", "bulk_extractor",
    "stegsolve", "zsteg", "outguess", "steghide", "hashpump", "volatility",
    "volatility3", "sleuthkit", "autopsy", "katana", "hakrawler", "arjun",
    "paramspider", "wafw00f", "anew", "qsreplace", "uro", "postman",
    "api-schema-analyzer", "jwt-analyzer",
})

_INTRUSIVE_TOOLS: frozenset[str] = frozenset({
    # --- MCP active scanners -------------------------------------------------
    "nmap_scan", "gobuster_scan", "nuclei_scan", "prowler_scan", "trivy_scan",
    "nikto_scan", "ffuf_scan", "amass_scan", "dirsearch_scan",
    "rustscan_fast_scan", "intelligent_smart_scan",
    # --- Essential network/web scanners --------------------------------------
    "nmap", "gobuster", "dirb", "nikto", "masscan", "rustscan", "autorecon",
    "nbtscan", "arp-scan", "nxc", "netexec", "enum4linux", "enum4linux-ng",
    "rpcclient", "smbmap", "feroxbuster", "wfuzz", "xsser", "dotdotpwn",
    "x8", "jaeles", "dalfox", "burpsuite", "zaproxy", "wpscan",
    "nuclei", "fierce", "dnsenum", "recon-ng", "spiderfoot",
    "prowler", "scout-suite", "trivy", "kube-hunter", "kube-bench",
    "docker-bench-security", "checkov", "terrascan", "falco", "clair",
    "curl", "httpie", "wireshark", "tshark", "tcpdump", "kismet",
    "airmon-ng", "airodump-ng",
})

_DESTRUCTIVE_TOOLS: frozenset[str] = frozenset({
    # --- MCP destructive -----------------------------------------------------
    "sqlmap_scan", "hydra_attack", "execute_command", "create_file",
    "nmap_advanced_scan",  # default; see classify_tool for aggressive override
    # --- Exploit / cred harvesting -------------------------------------------
    "sqlmap", "hydra", "medusa", "patator", "john", "hashcat", "hashcat-utils",
    "metasploit", "msfvenom", "msfconsole", "responder", "evil-winrm",
    "aircrack-ng", "aireplay-ng", "setoolkit", "beef",
})


def _build_mapping() -> Dict[str, Tier]:
    out: Dict[str, Tier] = {}
    for name in _SAFE_TOOLS:
        out[name] = Tier.SAFE
    for name in _INTRUSIVE_TOOLS:
        out[name] = Tier.INTRUSIVE
    for name in _DESTRUCTIVE_TOOLS:
        out[name] = Tier.DESTRUCTIVE
    return out


TOOL_TIERS: Dict[str, Tier] = _build_mapping()
ALL_KNOWN_TOOLS: frozenset[str] = frozenset(TOOL_TIERS)


# ============================================================================
# Token-based fallback for tools not in TOOL_TIERS.
# Order matters: DESTRUCTIVE checked first (most specific), then INTRUSIVE,
# then SAFE. If nothing matches, the default Tier.INTRUSIVE is returned.
# ============================================================================

_DESTRUCTIVE_TOKENS: tuple[str, ...] = (
    "exploit", "payload", "metasploit", "msfvenom", "msfconsole",
    "sqlmap", "hydra", "medusa", "patator", "john", "hashcat",
    "brute", "crack", "decrypt", "reverse_shell", "shell",
    "responder", "ntlmrelayx", "evil-winrm", "aircrack", "aireplay",
    "setoolkit", "beef", "destructive", "execute_command", "create_file",
)
_INTRUSIVE_TOKENS: tuple[str, ...] = (
    "scan", "nmap", "masscan", "rustscan", "gobuster", "ffuf", "feroxbuster",
    "dirb", "dirsearch", "nikto", "nuclei", "wpscan", "zaproxy", "burp",
    "enum", "brute_force_dir", "fuzz", "wfuzz", "crawl", "spider",
    "probe", "recon-ng", "fierce", "dnsenum", "wireless", "sniff", "capture",
)
_SAFE_TOKENS: tuple[str, ...] = (
    "whois", "dig", "dns", "lookup", "passive", "osint", "shodan", "censys",
    "search", "list", "info", "health", "stats", "cache", "view", "read",
    "show", "get", "describe", "explain",
)


def _token_match(name: str, tokens: Iterable[str]) -> bool:
    name_lower = name.lower()
    return any(tok in name_lower for tok in tokens)


def _tier_from_tokens(name: str) -> Optional[Tier]:
    """Apply token heuristics; return ``None`` if no token matches."""
    if _token_match(name, _DESTRUCTIVE_TOKENS):
        return Tier.DESTRUCTIVE
    if _token_match(name, _INTRUSIVE_TOKENS):
        return Tier.INTRUSIVE
    if _token_match(name, _SAFE_TOKENS):
        return Tier.SAFE
    return None


def classify_tool(name: str, params: Optional[Dict[str, Any]] = None) -> Tier:
    """Return the ``Tier`` for ``name``; consider ``params`` for special cases.

    Resolution order:
        1. Exact match in ``TOOL_TIERS`` (case-insensitive on lowercase name).
        2. Parameter-aware overrides (e.g. ``nmap_advanced_scan`` with
           ``aggressive=True`` is always DESTRUCTIVE regardless of mapping).
        3. Token-based fallback for unknown tool names.
        4. Default ``Tier.INTRUSIVE`` (fail-safe).

    ``params`` is an optional dict of tool parameters (the same dict that the
    caller would send to ``/api/tools/<name>``). It is consulted only for
    well-known overrides; unknown keys are ignored.
    """
    if not isinstance(name, str) or not name:
        # No usable name -> be conservative.
        return Tier.INTRUSIVE

    key = name.lower().strip()
    if not key:
        return Tier.INTRUSIVE

    # Parameter-aware overrides take precedence over the static mapping.
    if params and isinstance(params, dict):
        if key == "nmap_advanced_scan":
            # Already DESTRUCTIVE in mapping, but document the rule for clarity.
            if params.get("aggressive") in (True, "true", "True", 1, "1"):
                return Tier.DESTRUCTIVE
        if key == "execute_command":
            # Arbitrary command execution — always destructive, no exceptions.
            return Tier.DESTRUCTIVE
        if key == "create_file":
            # Writes arbitrary content to the server filesystem.
            return Tier.DESTRUCTIVE

    tier = TOOL_TIERS.get(key)
    if tier is not None:
        # Allow params to *promote* a known tool to a higher tier.
        if tier is Tier.INTRUSIVE and params and isinstance(params, dict):
            if key in {"nmap", "rustscan", "masscan", "nmap_scan",
                       "rustscan_fast_scan"} and params.get("aggressive") in (
                       True, "true", "True", 1, "1"):
                return Tier.DESTRUCTIVE
        return tier

    fallback = _tier_from_tokens(key)
    if fallback is not None:
        return fallback

    logger.debug("tool %r not in TOOL_TIERS; defaulting to INTRUSIVE", name)
    return Tier.INTRUSIVE


def tiers_summary() -> Dict[str, Dict[str, int]]:
    """Return counts per tier — used by ``GET /api/guardrails/tiers`` and
    the health-panel UI to render category badges.
    """
    counts = {t.value: 0 for t in Tier}
    for tier in TOOL_TIERS.values():
        counts[tier.value] += 1
    return {"by_tier": counts, "total": len(TOOL_TIERS)}
