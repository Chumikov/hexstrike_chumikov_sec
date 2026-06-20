"""Unit tests for hexstrike_mcp.RetryStrategy."""
import pytest

from hexstrike_mcp import RetryStrategy, EnhancedError, ErrorCategory, ErrorSeverity


def _err(category, recoverable=True):
    return EnhancedError(
        category=category,
        severity=ErrorSeverity.MEDIUM,
        message="x",
        recoverable=recoverable,
    )


class TestShouldRetry:
    def test_retries_recoverable_error_within_limit(self, retry_strategy_no_jitter):
        assert retry_strategy_no_jitter.should_retry(_err(ErrorCategory.NETWORK), attempt=0) is True

    def test_stops_at_max_retries(self, retry_strategy_no_jitter):
        assert retry_strategy_no_jitter.should_retry(_err(ErrorCategory.NETWORK), attempt=3) is False
        assert retry_strategy_no_jitter.should_retry(_err(ErrorCategory.NETWORK), attempt=2) is True

    def test_never_retries_auth(self, retry_strategy_no_jitter):
        assert retry_strategy_no_jitter.should_retry(_err(ErrorCategory.AUTH), attempt=0) is False

    def test_never_retries_non_recoverable(self, retry_strategy_no_jitter):
        assert retry_strategy_no_jitter.should_retry(
            _err(ErrorCategory.SERVER, recoverable=False), attempt=0) is False

    def test_auth_takes_precedence_over_attempt(self):
        s = RetryStrategy(max_retries=5)
        assert s.should_retry(_err(ErrorCategory.AUTH), attempt=0) is False


class TestGetDelay:
    def test_no_jitter_is_deterministic_and_exponential(self, retry_strategy_no_jitter):
        # base=1, exp=2 -> attempt0: 1, attempt1: 2, attempt2: 4
        assert retry_strategy_no_jitter.get_delay(0) == pytest.approx(1.0)
        assert retry_strategy_no_jitter.get_delay(1) == pytest.approx(2.0)
        assert retry_strategy_no_jitter.get_delay(2) == pytest.approx(4.0)

    def test_capped_at_max_delay(self):
        s = RetryStrategy(max_retries=3, base_delay=10.0, max_delay=15.0,
                          exponential_base=2.0, jitter=False)
        # 10 * 2^2 = 40 -> capped to 15
        assert s.get_delay(2) == pytest.approx(15.0)
        assert s.get_delay(5) == pytest.approx(15.0)

    def test_jitter_keeps_delay_within_bounds(self):
        s = RetryStrategy(max_retries=3, base_delay=4.0, jitter=True)
        for attempt in range(4):
            base = 4.0 * (2 ** attempt)
            d = s.get_delay(attempt)
            # jitter multiplies by (0.5 + r) where r in [0,1) -> [0.5, 1.5)
            assert 0.5 * base <= d < 1.5 * base
