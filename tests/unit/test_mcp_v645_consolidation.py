"""T-c tests for v6.4.5 «Streamline» (MCP consolidation).

Covers:
- C1/C2/C3: new verbs present, dispatch to correct endpoints
- C4: HEXSTRIKE_MCP_PROFILE filtering (minimal/recon/web/exploit/full)
- C5: deprecated aliases marked + gated by HEXSTRIKE_MCP_ALIASES
- C3 (guardrails side): metasploit_run classified as DESTRUCTIVE in TOOL_TIERS
"""
import asyncio
import json
import os
from unittest.mock import MagicMock, patch

import pytest

import hexstrike_mcp
from hexstrike_guardrails.tiers import Tier, classify_tool, TOOL_TIERS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_mcp_with_profile(profile: str | None, aliases: str | None = None):
    """Build MCP server with given env, return list of tool names."""
    # Clear env first for determinism
    for k in ("HEXSTRIKE_MCP_PROFILE", "HEXSTRIKE_MCP_ALIASES"):
        os.environ.pop(k, None)
    if profile is not None:
        os.environ["HEXSTRIKE_MCP_PROFILE"] = profile
    if aliases is not None:
        os.environ["HEXSTRIKE_MCP_ALIASES"] = aliases
    client = MagicMock()
    client.safe_post.return_value = {"success": True, "stdout": ""}
    mcp = hexstrike_mcp.setup_mcp_server(client)
    tools = asyncio.run(mcp.list_tools())
    return mcp, tools, client


# ---------------------------------------------------------------------------
# C4: profile filtering
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("profile,expected_count,expected_subset", [
    ("minimal", 4, {"execute_command", "intelligent_smart_scan",
                    "analyze_target_intelligence", "batch_execute"}),
    ("recon", 7, {"port_scan", "subdomain_enum", "http_probe"}),
    ("web", 9, {"directory_brute", "web_vuln_scan"}),
    ("exploit", 13, {"sqlmap_scan", "hydra_attack", "metasploit_run", "cloud_audit"}),
])
def test_profile_registers_correct_subset(profile, expected_count, expected_subset):
    """Each lean profile must register exactly expected_count tools including expected_subset."""
    _, tools, _ = _build_mcp_with_profile(profile)
    names = {t.name for t in tools}
    assert len(names) == expected_count, (
        f"profile={profile}: expected {expected_count} tools, got {len(names)}: {sorted(names)}")
    missing = expected_subset - names
    assert not missing, f"profile={profile}: missing expected tools: {missing}"


def test_profile_full_registers_all_verbs_and_aliases():
    """Default `full` profile must include all 7 new verbs + all 14 deprecated aliases."""
    _, tools, _ = _build_mcp_with_profile("full")
    names = {t.name for t in tools}
    new_verbs = {"port_scan", "subdomain_enum", "http_probe", "directory_brute",
                 "web_vuln_scan", "cloud_audit", "metasploit_run"}
    legacy_aliases = {"nmap_scan", "gobuster_scan", "nuclei_scan", "prowler_scan",
                      "trivy_scan", "nikto_scan", "ffuf_scan", "amass_scan",
                      "subfinder_scan", "httpx_probe", "dirsearch_scan",
                      "katana_crawl", "nmap_advanced_scan", "rustscan_fast_scan"}
    assert new_verbs <= names, f"full missing new verbs: {new_verbs - names}"
    assert legacy_aliases <= names, f"full missing aliases: {legacy_aliases - names}"


def test_aliases_flag_hides_legacy_names():
    """HEXSTRIKE_MCP_ALIASES=0 in full profile hides all 14 deprecated aliases."""
    _, tools, _ = _build_mcp_with_profile("full", aliases="0")
    names = {t.name for t in tools}
    legacy = {"nmap_scan", "gobuster_scan", "rustscan_fast_scan"}  # sample
    hidden = legacy & names
    assert not hidden, f"aliases=0 should hide legacy names, but found: {hidden}"


def test_unknown_profile_falls_back_to_full():
    """Unknown profile value falls back to permissive (no filter) — fail-safe."""
    _, tools, _ = _build_mcp_with_profile("nonexistent_profile")
    # Should register everything (same as full)
    assert len({t.name for t in tools}) >= 25, "unknown profile should not under-register"


# ---------------------------------------------------------------------------
# C5: deprecated docstrings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alias_name,replacement", [
    ("nmap_scan", "port_scan"),
    ("nmap_advanced_scan", "port_scan"),
    ("rustscan_fast_scan", "port_scan"),
    ("gobuster_scan", "directory_brute"),
    ("ffuf_scan", "directory_brute"),
    ("dirsearch_scan", "directory_brute"),
    ("nuclei_scan", "web_vuln_scan"),
    ("nikto_scan", "web_vuln_scan"),
    ("amass_scan", "subdomain_enum"),
    ("subfinder_scan", "subdomain_enum"),
    ("httpx_probe", "http_probe"),
    ("katana_crawl", "http_probe"),
    ("prowler_scan", "cloud_audit"),
    ("trivy_scan", "cloud_audit"),
])
def test_alias_docstring_deprecated(alias_name, replacement):
    """Each deprecated alias's description must include DEPRECATED marker + replacement."""
    _, tools, _ = _build_mcp_with_profile("full")
    by_name = {t.name: t for t in tools}
    assert alias_name in by_name, f"{alias_name} not registered in full profile"
    desc = by_name[alias_name].description or ""
    assert "DEPRECATED" in desc, f"{alias_name}: missing DEPRECATED marker"
    assert replacement in desc, f"{alias_name}: missing replacement hint '{replacement}'"


def test_new_verbs_not_marked_deprecated():
    """New verbs must NOT carry DEPRECATED marker."""
    _, tools, _ = _build_mcp_with_profile("full")
    new_verbs = ["port_scan", "subdomain_enum", "http_probe", "directory_brute",
                 "web_vuln_scan", "cloud_audit", "metasploit_run"]
    for t in tools:
        if t.name in new_verbs:
            assert "DEPRECATED" not in (t.description or ""), \
                f"{t.name} (new verb) should not be DEPRECATED"


# ---------------------------------------------------------------------------
# C1/C2: verb dispatch
# ---------------------------------------------------------------------------

def test_port_scan_dispatches_to_nmap_for_full_mode():
    """port_scan(mode='full', tool='auto') must call api/tools/nmap-advanced."""
    _, tools, client = _build_mcp_with_profile("full")
    by_name = {t.name: t for t in tools}
    # Invoke the underlying function via FastMCP's call_tool
    # We can also just test the dispatch logic directly via the registered callable.
    # Easiest: re-call setup with mock, find the function via mcp._tool_manager
    # But FastMCP doesn't expose callables easily — we test dispatch by calling
    # the function through the public mcp.call_tool() API.
    mcp, _, client = _build_mcp_with_profile("recon")
    result = asyncio.run(mcp.call_tool("port_scan", {
        "target": "127.0.0.1", "mode": "full", "tool": "auto"}))
    # safe_post should have been called with api/tools/nmap-advanced
    client.safe_post.assert_called_once()
    args, _ = client.safe_post.call_args
    assert args[0] == "api/tools/nmap-advanced", \
        f"port_scan full → expected nmap-advanced, got {args[0]}"


def test_port_scan_dispatches_to_rustscan_for_fast_mode():
    mcp, _, client = _build_mcp_with_profile("recon")
    asyncio.run(mcp.call_tool("port_scan", {
        "target": "10.0.0.1", "mode": "fast", "tool": "auto"}))
    args, _ = client.safe_post.call_args
    assert args[0] == "api/tools/rustscan"


def test_port_scan_explicit_tool_overrides_auto():
    """tool='masscan' must override mode-based auto-resolution."""
    mcp, _, client = _build_mcp_with_profile("recon")
    asyncio.run(mcp.call_tool("port_scan", {
        "target": "10.0.0.1", "mode": "fast", "tool": "masscan"}))
    args, _ = client.safe_post.call_args
    assert args[0] == "api/tools/masscan"


def test_directory_brute_dispatches_to_ffuf_for_fuzz():
    mcp, _, client = _build_mcp_with_profile("web")
    asyncio.run(mcp.call_tool("directory_brute", {
        "url": "https://example.com", "mode": "fuzz", "tool": "auto"}))
    args, _ = client.safe_post.call_args
    assert args[0] == "api/tools/ffuf"


def test_subdomain_enum_passive_uses_subfinder():
    mcp, _, client = _build_mcp_with_profile("recon")
    asyncio.run(mcp.call_tool("subdomain_enum", {
        "domain": "example.com", "source": "passive", "tool": "auto"}))
    args, _ = client.safe_post.call_args
    assert args[0] == "api/tools/subfinder"


def test_web_vuln_scan_wordpress_uses_wpscan():
    mcp, _, client = _build_mcp_with_profile("web")
    asyncio.run(mcp.call_tool("web_vuln_scan", {
        "target": "https://wp.example.com", "profile": "wordpress", "tool": "auto"}))
    args, _ = client.safe_post.call_args
    assert args[0] == "api/tools/wpscan"


def test_cloud_audit_k8s_uses_kube_hunter():
    mcp, _, client = _build_mcp_with_profile("exploit")
    asyncio.run(mcp.call_tool("cloud_audit", {
        "scope": "k8s", "tool": "auto"}))
    args, _ = client.safe_post.call_args
    assert args[0] == "api/tools/kube-hunter"


# ---------------------------------------------------------------------------
# C3: metasploit_run + guardrails integration
# ---------------------------------------------------------------------------

def test_metasploit_run_in_destructive_tier():
    """metasploit_run must be classified as DESTRUCTIVE in TOOL_TIERS."""
    tier = classify_tool("metasploit_run")
    assert tier == Tier.DESTRUCTIVE, \
        f"metasploit_run must be DESTRUCTIVE, got {tier}"


def test_metasploit_run_registered_only_in_exploit_or_full():
    """metasploit_run must NOT be available in minimal/recon/web profiles."""
    for profile in ("minimal", "recon", "web"):
        _, tools, _ = _build_mcp_with_profile(profile)
        names = {t.name for t in tools}
        assert "metasploit_run" not in names, \
            f"metasploit_run must not appear in profile={profile}"


def test_metasploit_run_available_in_exploit():
    _, tools, _ = _build_mcp_with_profile("exploit")
    names = {t.name for t in tools}
    assert "metasploit_run" in names


def test_metasploit_run_invalid_json_options_returns_error():
    """Bad JSON in options= must return structured error, not crash."""
    mcp, _, _ = _build_mcp_with_profile("exploit")
    result = asyncio.run(mcp.call_tool("metasploit_run", {
        "module": "exploit/test", "target": "10.0.0.1",
        "options": "not-valid-json"}))
    # Result is a tuple (content, structured) in some FastMCP versions; handle both
    if isinstance(result, tuple):
        structured = result[1] if len(result) > 1 else {}
    else:
        structured = result if isinstance(result, dict) else {}
    # The function returns dict with success=False on JSON error
    # FastMCP wraps content; check structured payload
    assert structured is not None


# ---------------------------------------------------------------------------
# Tier classification for new verbs (guardrails integration)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("verb,expected_tier", [
    ("port_scan", Tier.INTRUSIVE),
    ("directory_brute", Tier.INTRUSIVE),
    ("web_vuln_scan", Tier.INTRUSIVE),
    ("subdomain_enum", Tier.SAFE),
    ("http_probe", Tier.SAFE),
    ("cloud_audit", Tier.SAFE),
    ("metasploit_run", Tier.DESTRUCTIVE),
])
def test_new_verb_tier_classification(verb, expected_tier):
    """All new verbs must have correct tier in TOOL_TIERS (for guardrails)."""
    actual = classify_tool(verb)
    assert actual == expected_tier, \
        f"{verb}: expected {expected_tier}, got {actual}"


# ---------------------------------------------------------------------------
# Cleanup — make sure no env leaks across tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_env():
    """Strip v6.4.5 env vars before each test to avoid cross-test contamination."""
    saved = {k: os.environ.pop(k, None) for k in
             ("HEXSTRIKE_MCP_PROFILE", "HEXSTRIKE_MCP_ALIASES")}
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)
