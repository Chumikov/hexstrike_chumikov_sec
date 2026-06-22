"""Unit tests for hexstrike_guardrails.tiers (G2).

Covers:
  * Tier enum (value, requires_confirmation, rank, parse)
  * TOOL_TIERS mapping covers the 150+ canonical tools
  * classify_tool() resolution order: exact match -> parameter overrides ->
    token fallback -> default INTRUSIVE
"""
import pytest

from hexstrike_guardrails import Tier
from hexstrike_guardrails.tiers import (
    ALL_KNOWN_TOOLS,
    TOOL_TIERS,
    classify_tool,
    tiers_summary,
)


pytestmark = pytest.mark.guardrails


# ---------------------------------------------------------------------------
# Tier enum
# ---------------------------------------------------------------------------


class TestTierEnum:
    def test_values(self):
        assert Tier.SAFE.value == "SAFE"
        assert Tier.INTRUSIVE.value == "INTRUSIVE"
        assert Tier.DESTRUCTIVE.value == "DESTRUCTIVE"

    @pytest.mark.parametrize("tier, expected", [
        (Tier.SAFE, False),
        (Tier.INTRUSIVE, False),
        (Tier.DESTRUCTIVE, True),
    ])
    def test_requires_confirmation(self, tier, expected):
        assert tier.requires_confirmation is expected

    @pytest.mark.parametrize("a, b", [
        (Tier.SAFE, Tier.INTRUSIVE),
        (Tier.INTRUSIVE, Tier.DESTRUCTIVE),
        (Tier.SAFE, Tier.DESTRUCTIVE),
    ])
    def test_rank_ordering(self, a, b):
        assert a.rank < b.rank

    def test_parse_lowercase(self):
        assert Tier.parse("safe") is Tier.SAFE
        assert Tier.parse("Intrusive") is Tier.INTRUSIVE
        assert Tier.parse("DESTRUCTIVE") is Tier.DESTRUCTIVE

    def test_parse_unknown_defaults_to_intrusive(self):
        assert Tier.parse("nonsense") is Tier.INTRUSIVE
        assert Tier.parse("") is Tier.INTRUSIVE

    def test_parse_passes_through_tier(self):
        assert Tier.parse(Tier.SAFE) is Tier.SAFE


# ---------------------------------------------------------------------------
# TOOL_TIERS mapping
# ---------------------------------------------------------------------------


class TestToolTiersMapping:
    def test_covers_at_least_100_tools(self):
        assert len(TOOL_TIERS) >= 100, "TOOL_TIERS should cover the canonical /health list"

    def test_all_known_tools_matches_mapping_keys(self):
        assert set(TOOL_TIERS.keys()) == set(ALL_KNOWN_TOOLS)

    @pytest.mark.parametrize("tool", [
        # MCP tools
        "nmap_scan", "nuclei_scan", "subfinder_scan", "httpx_probe",
        "sqlmap_scan", "hydra_attack", "execute_command", "create_file",
        "nmap_advanced_scan", "katana_crawl",
        # /health canonical
        "nmap", "gobuster", "nuclei", "sqlmap", "hydra", "john", "hashcat",
        "metasploit", "msfvenom", "msfconsole", "responder", "evil-winrm",
        "subfinder", "amass", "theharvester", "shodan", "censys",
        "httpx", "wafw00f", "nikto", "gobuster", "ffuf", "feroxbuster",
    ])
    def test_known_tool_present(self, tool):
        assert tool in TOOL_TIERS, f"{tool!r} missing from TOOL_TIERS"

    def test_tier_distribution_reasonable(self):
        """Each tier has a non-trivial share; no tier is empty."""
        summary = tiers_summary()
        assert summary["total"] == len(TOOL_TIERS)
        by_tier = summary["by_tier"]
        assert by_tier["SAFE"] > 10
        assert by_tier["INTRUSIVE"] > 10
        assert by_tier["DESTRUCTIVE"] > 5

    @pytest.mark.parametrize("tool, expected", [
        ("sqlmap", Tier.DESTRUCTIVE),
        ("hydra", Tier.DESTRUCTIVE),
        ("metasploit", Tier.DESTRUCTIVE),
        ("john", Tier.DESTRUCTIVE),
        ("hashcat", Tier.DESTRUCTIVE),
        ("msfvenom", Tier.DESTRUCTIVE),
        ("execute_command", Tier.DESTRUCTIVE),
        ("create_file", Tier.DESTRUCTIVE),
        ("nmap_advanced_scan", Tier.DESTRUCTIVE),
        ("nmap", Tier.INTRUSIVE),
        ("nuclei", Tier.INTRUSIVE),
        ("gobuster", Tier.INTRUSIVE),
        ("nikto", Tier.INTRUSIVE),
        ("ffuf", Tier.INTRUSIVE),
        ("nmap_scan", Tier.INTRUSIVE),
        ("subfinder", Tier.SAFE),
        ("httpx_probe", Tier.SAFE),
        ("amass", Tier.SAFE),       # amass_scan is INTRUSIVE, amass passive is SAFE
        ("katana", Tier.SAFE),
        ("server_health", Tier.SAFE),
    ])
    def test_specific_tier_assignments(self, tool, expected):
        assert TOOL_TIERS[tool] is expected


# ---------------------------------------------------------------------------
# classify_tool()
# ---------------------------------------------------------------------------


class TestClassifyTool:
    def test_exact_lookup_is_case_insensitive(self):
        assert classify_tool("NMAP") is Tier.INTRUSIVE
        assert classify_tool("SQLMap") is Tier.DESTRUCTIVE

    def test_empty_string_returns_intrusive(self):
        assert classify_tool("") is Tier.INTRUSIVE

    def test_non_string_returns_intrusive(self):
        assert classify_tool(None) is Tier.INTRUSIVE
        assert classify_tool(42) is Tier.INTRUSIVE

    def test_unknown_tool_default_intrusive(self):
        # 'foobar' has no token overlap with the fallback tables.
        assert classify_tool("foobar_no_match") is Tier.INTRUSIVE

    @pytest.mark.parametrize("name, expected", [
        ("myexploit", Tier.DESTRUCTIVE),     # contains 'exploit'
        ("custom_brute", Tier.DESTRUCTIVE),  # contains 'brute'
        ("myhashcrack", Tier.DESTRUCTIVE),   # contains 'crack' and 'hash'
        ("portscanner", Tier.INTRUSIVE),     # contains 'scan'
        ("ufuzzer", Tier.INTRUSIVE),         # contains 'fuzz'
        ("whois_lookup", Tier.SAFE),         # contains 'whois' and 'lookup'
        ("shodan_query", Tier.SAFE),         # contains 'shodan'
        ("dns_resolver", Tier.SAFE),         # contains 'dns'
    ])
    def test_token_fallback(self, name, expected):
        assert classify_tool(name) is expected

    def test_destructive_token_takes_precedence_over_safe(self):
        # 'passive_exploit_scanner' contains both 'passive' and 'exploit';
        # destructive wins because it is checked first.
        assert classify_tool("passive_exploit_scanner") is Tier.DESTRUCTIVE

    # --- parameter-aware overrides ---------------------------------------

    def test_execute_command_always_destructive(self):
        assert classify_tool("execute_command", params={}) is Tier.DESTRUCTIVE
        assert classify_tool("execute_command", params=None) is Tier.DESTRUCTIVE

    def test_create_file_always_destructive(self):
        assert classify_tool("create_file", params={}) is Tier.DESTRUCTIVE

    def test_nmap_aggressive_promoted_to_destructive(self):
        assert classify_tool("nmap", params={}) is Tier.INTRUSIVE
        assert classify_tool("nmap", params={"aggressive": True}) is Tier.DESTRUCTIVE
        assert classify_tool("nmap", params={"aggressive": "true"}) is Tier.DESTRUCTIVE
        assert classify_tool("nmap", params={"aggressive": 1}) is Tier.DESTRUCTIVE

    def test_rustscan_aggressive_promoted_to_destructive(self):
        assert classify_tool("rustscan", params={"aggressive": True}) is Tier.DESTRUCTIVE

    def test_nmap_advanced_scan_destructive_by_default(self):
        # nmap_advanced_scan is mapped as DESTRUCTIVE; the aggressive param
        # just confirms it.
        assert classify_tool("nmap_advanced_scan") is Tier.DESTRUCTIVE
        assert classify_tool("nmap_advanced_scan", params={"aggressive": True}) is Tier.DESTRUCTIVE

    def test_tiers_summary_format(self):
        s = tiers_summary()
        assert set(s.keys()) == {"by_tier", "total"}
        assert set(s["by_tier"].keys()) == {"SAFE", "INTRUSIVE", "DESTRUCTIVE"}
        assert s["total"] == sum(s["by_tier"].values())
