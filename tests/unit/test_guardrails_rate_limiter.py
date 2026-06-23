"""Unit tests for hexstrike_guardrails.rate_limiter (G3)."""
import threading
import time

import pytest

from hexstrike_guardrails import TargetRateLimiter


pytestmark = pytest.mark.guardrails


class TestConstructor:
    def test_defaults(self):
        rl = TargetRateLimiter()
        assert rl.max_concurrent == 5
        assert rl.max_rps == 10

    @pytest.mark.parametrize("kwargs", [
        {"max_concurrent": 0},
        {"max_concurrent": -1},
        {"max_rps": 0},
        {"max_rps": -1},
        {"stale_ttl_sec": 0},
        {"stale_ttl_sec": -1},
    ])
    def test_invalid_args_rejected(self, kwargs):
        with pytest.raises(ValueError):
            TargetRateLimiter(**kwargs)


class TestConcurrency:
    def test_fresh_target_succeeds(self):
        rl = TargetRateLimiter(max_concurrent=2, max_rps=100)
        assert rl.try_acquire("host") is True

    def test_max_concurrent_then_block(self):
        rl = TargetRateLimiter(max_concurrent=2, max_rps=100)
        assert rl.try_acquire("h") is True
        assert rl.try_acquire("h") is True
        assert rl.try_acquire("h") is False  # 3rd one rejected

    def test_release_frees_slot(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=100)
        assert rl.try_acquire("h") is True
        assert rl.try_acquire("h") is False
        rl.release("h")
        assert rl.try_acquire("h") is True

    def test_release_is_idempotent(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=100)
        rl.try_acquire("h")
        rl.release("h")
        rl.release("h")  # second release: no error
        rl.release("h")

    def test_per_target_isolation(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=100)
        assert rl.try_acquire("h1") is True
        assert rl.try_acquire("h1") is False  # h1 saturated
        assert rl.try_acquire("h2") is True   # h2 is independent

    def test_empty_target_rejected(self):
        rl = TargetRateLimiter()
        assert rl.try_acquire("") is False
        assert rl.acquire("", timeout=0.1) is False
        rl.release("")  # no-op, must not raise


class TestRateLimit:
    def test_rps_cap_enforced(self):
        rl = TargetRateLimiter(max_concurrent=10, max_rps=3)
        results = [rl.try_acquire("h") for _ in range(5)]
        # First 3 should succeed (concurrency is plenty), last 2 blocked by rps.
        assert results == [True, True, True, False, False]

    def test_check_rate_does_not_consume_slot(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=1)
        # Pre-check returns True; consume returns True.
        assert rl.check_rate("h") is True
        assert rl.try_acquire("h") is True
        # Now both gates are saturated; pre-check still reports concurrency
        # alone (it does not know about concurrency cap), but another acquire
        # must fail.
        assert rl.try_acquire("h") is False


class TestAcquireWithTimeout:
    def test_zero_timeout_equivalent_to_try(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=100)
        assert rl.acquire("h", timeout=0) is True
        assert rl.acquire("h", timeout=0) is False

    def test_blocking_acquire_fails_after_timeout(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=100)
        rl.try_acquire("h")
        t0 = time.time()
        result = rl.acquire("h", timeout=0.15)
        dt = time.time() - t0
        assert result is False
        assert dt >= 0.1

    def test_blocking_acquire_succeeds_when_slot_freed(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=100)
        rl.try_acquire("h")

        def releaser():
            time.sleep(0.1)
            rl.release("h")

        threading.Thread(target=releaser, daemon=True).start()
        result = rl.acquire("h", timeout=1.0)
        assert result is True


class TestCleanupStale:
    def test_idle_target_evicted(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=100, stale_ttl_sec=1)
        rl.try_acquire("h")
        rl.release("h")
        assert rl.tracked_targets() == 1
        time.sleep(1.05)
        pruned = rl.cleanup_stale()
        assert pruned == 1
        assert rl.tracked_targets() == 0

    def test_in_flight_target_not_evicted(self):
        rl = TargetRateLimiter(max_concurrent=1, max_rps=100, stale_ttl_sec=1)
        rl.try_acquire("h")  # slot still held
        time.sleep(1.05)
        pruned = rl.cleanup_stale()
        assert pruned == 0
        assert rl.tracked_targets() == 1


class TestSnapshot:
    def test_snapshot_structure(self):
        rl = TargetRateLimiter(max_concurrent=3, max_rps=5)
        snap = rl.snapshot()
        assert set(snap.keys()) == {
            "tracked_targets", "in_flight_slots",
            "max_concurrent", "max_rps",
        }
        assert snap["max_concurrent"] == 3
        assert snap["max_rps"] == 5
        assert snap["tracked_targets"] == 0
        assert snap["in_flight_slots"] == 0

    def test_in_flight_reflects_active_acquires(self):
        rl = TargetRateLimiter(max_concurrent=3, max_rps=100)
        rl.try_acquire("h1")
        rl.try_acquire("h2")
        snap = rl.snapshot()
        assert snap["tracked_targets"] == 2
        assert snap["in_flight_slots"] == 2


class TestConcurrencyMultiThread:
    """Smoke test: 50 threads racing for 5 slots on the same target."""

    def test_never_exceed_concurrency(self):
        rl = TargetRateLimiter(max_concurrent=5, max_rps=1000)
        active = 0
        max_active = 0
        lock = threading.Lock()

        def worker():
            nonlocal active, max_active
            if not rl.try_acquire("shared"):
                return
            try:
                with lock:
                    active += 1
                    if active > max_active:
                        max_active = active
                time.sleep(0.01)
            finally:
                with lock:
                    active -= 1
                rl.release("shared")

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert max_active <= 5, f"concurrency exceeded: observed {max_active}"
