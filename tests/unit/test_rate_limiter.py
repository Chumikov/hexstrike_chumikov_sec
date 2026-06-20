"""Unit tests for hexstrike_mcp.RateLimiter (token bucket)."""
from hexstrike_mcp import RateLimiter


class TestAcquire:
    def test_fresh_limiter_serves_burst(self):
        rl = RateLimiter(requests_per_second=10.0, burst_size=5)
        results = [rl.acquire(timeout=0)[0] for _ in range(5)]
        assert all(results)  # burst tokens available immediately

    def test_zero_burst_with_low_timeout_can_reject(self):
        rl = RateLimiter(requests_per_second=0.1, burst_size=1)
        ok1, _ = rl.acquire(timeout=0)
        assert ok1 is True
        # tokens exhausted and refill is ~0; with timeout=0 the next may be rejected
        rl2 = RateLimiter(requests_per_second=0.0001, burst_size=1)
        rl2.acquire(timeout=0)
        ok2, _ = rl2.acquire(timeout=0)
        assert ok2 is False

    def test_returns_tuple_of_bool_and_float(self):
        rl = RateLimiter(burst_size=10)
        result = rl.acquire(timeout=1.0)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], float)


class TestStats:
    def test_initial_stats(self):
        rl = RateLimiter(requests_per_second=10.0, burst_size=20)
        stats = rl.get_stats()
        assert stats["requests_per_second"] == 10.0
        assert stats["burst_size"] == 20
        assert stats["total_requests"] == 0
        assert stats["rejected_requests"] == 0

    def test_counts_total_requests(self):
        rl = RateLimiter(requests_per_second=10.0, burst_size=3)
        for _ in range(3):
            rl.acquire(timeout=0)
        assert rl.get_stats()["total_requests"] == 3
