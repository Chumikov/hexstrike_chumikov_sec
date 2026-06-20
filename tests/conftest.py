"""Shared pytest fixtures for HexStrike tests.

The heavy `hexstrike_server` module (~742KB) is imported lazily inside the
fixtures that actually need it, so collecting/running the MCP-only unit tests
does not pay that cost.
"""
import importlib.util
import sys
import types

import pytest


def _install_optional_kali_module_stubs() -> None:
    """Stub Kali-only modules so `hexstrike_server` imports in non-Kali CI.

    `hexstrike_server.py` imports `mitmproxy` at module top level. On Kali it is
    a system package (visible via the venv's --system-site-packages); in CI it is
    absent and the import fails, breaking every test that touches the server
    module. We inject lightweight stubs ONLY when the real package is not
    importable, so Kali/local runs are unaffected.
    """
    if importlib.util.find_spec("mitmproxy") is not None:
        return  # real mitmproxy available (Kali/local) — nothing to do

    mp = types.ModuleType("mitmproxy")
    mp_http = types.ModuleType("mitmproxy.http")
    mp_tools = types.ModuleType("mitmproxy.tools")
    mp_tools_dump = types.ModuleType("mitmproxy.tools.dump")
    mp_options = types.ModuleType("mitmproxy.options")

    class DumpMaster:  # minimal stub; never instantiated by the tested code paths
        pass

    class Options:
        pass

    mp_tools_dump.DumpMaster = DumpMaster
    mp_options.Options = Options
    mp.http = mp_http
    mp.tools = mp_tools
    mp_tools.dump = mp_tools_dump
    mp.options = mp_options

    sys.modules["mitmproxy"] = mp
    sys.modules["mitmproxy.http"] = mp_http
    sys.modules["mitmproxy.tools"] = mp_tools
    sys.modules["mitmproxy.tools.dump"] = mp_tools_dump
    sys.modules["mitmproxy.options"] = mp_options


_install_optional_kali_module_stubs()


@pytest.fixture
def lru_cache():
    """Fresh LRU cache (small capacity) from hexstrike_mcp."""
    from hexstrike_mcp import LRUCache
    return LRUCache(max_size=3, default_ttl=600)


@pytest.fixture
def retry_strategy_no_jitter():
    """RetryStrategy with jitter disabled for deterministic delay assertions."""
    from hexstrike_mcp import RetryStrategy
    return RetryStrategy(max_retries=3, base_delay=1.0, max_delay=30.0,
                         exponential_base=2.0, jitter=False)


@pytest.fixture
def decision_engine():
    """IntelligentDecisionEngine instance (no constructor args)."""
    from hexstrike_server import IntelligentDecisionEngine
    return IntelligentDecisionEngine()


@pytest.fixture
def make_profile():
    """Factory for TargetProfile dataclass instances.

    Usage: ``profile = make_profile(target="x", target_type=TargetType.WEB_APPLICATION)``
    """
    from hexstrike_server import TargetProfile

    def _make(**kwargs):
        defaults = {"target": "example.com"}
        defaults.update(kwargs)
        return TargetProfile(**defaults)

    return _make


@pytest.fixture
def bug_bounty_manager():
    """BugBountyWorkflowManager instance (owner of _get_test_scenarios)."""
    from hexstrike_server import BugBountyWorkflowManager
    return BugBountyWorkflowManager()


@pytest.fixture
def ctf_automator():
    """CTFChallengeAutomator instance (owner of flag extraction/validation)."""
    from hexstrike_server import CTFChallengeAutomator
    return CTFChallengeAutomator()


@pytest.fixture
def sample_ctf_challenge():
    """A representative CTFChallenge dataclass instance."""
    from hexstrike_server import CTFChallenge
    return CTFChallenge(
        name="SQLi Login",
        category="web",
        description="A login form vulnerable to SQL injection. Find the flag.",
        points=200,
        difficulty="medium",
        url="http://target.ctf/login",
    )
