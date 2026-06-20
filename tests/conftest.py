"""Shared pytest fixtures for HexStrike tests.

The heavy `hexstrike_server` module (~742KB) is imported lazily inside the
fixtures that actually need it, so collecting/running the MCP-only unit tests
does not pay that cost.
"""
import pytest


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
