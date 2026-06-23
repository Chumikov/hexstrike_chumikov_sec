"""Unit tests for hexstrike_guardrails.audit (G5)."""
import threading

import pytest

from hexstrike_guardrails import AuditEvent, AuditLogger, AuditStatus, Tier


pytestmark = pytest.mark.guardrails


def _log_sample(audit: AuditLogger, session_id="s1"):
    audit.log(session_id, "nmap", "example.com", Tier.INTRUSIVE,
              AuditStatus.ALLOWED, duration_ms=42)
    audit.log(session_id, "sqlmap", "evil.com", Tier.DESTRUCTIVE,
              AuditStatus.BLOCKED_SCOPE)
    audit.log(session_id, "hydra", "example.com", Tier.DESTRUCTIVE,
              AuditStatus.BLOCKED_TIER, error="needs confirmation")
    audit.log(session_id, "ffuf", "example.com", Tier.INTRUSIVE,
              AuditStatus.BLOCKED_RATE)
    audit.log(None, "system", None, Tier.SAFE,
              AuditStatus.KILLED, error="kill switch")


class TestAuditStatus:
    def test_values(self):
        assert AuditStatus.ALLOWED.value == "allowed"
        assert AuditStatus.BLOCKED_SCOPE.value == "blocked_scope"
        assert AuditStatus.BLOCKED_TIER.value == "blocked_tier"
        assert AuditStatus.BLOCKED_RATE.value == "blocked_rate"
        assert AuditStatus.KILLED.value == "killed"
        assert AuditStatus.ERROR.value == "error"


class TestLog:
    def test_single_log_round_trip(self, audit_logger):
        audit_logger.log("s1", "nmap", "ex.com", Tier.INTRUSIVE,
                         AuditStatus.ALLOWED, duration_ms=10)
        events = audit_logger.get_events(session_id="s1")
        assert len(events) == 1
        e = events[0]
        assert e["session_id"] == "s1"
        assert e["tool"] == "nmap"
        assert e["target"] == "ex.com"
        assert e["tier"] == "INTRUSIVE"
        assert e["status"] == "allowed"
        assert e["duration_ms"] == 10

    def test_string_tier_and_status(self, audit_logger):
        audit_logger.log("s", "tool", "t", "SAFE", "allowed")
        events = audit_logger.get_events()
        assert events[0]["tier"] == "SAFE"
        assert events[0]["status"] == "allowed"

    def test_log_event_with_dataclass(self, audit_logger):
        ev = AuditEvent(
            session_id="s2", tool="hydra", target="x", tier="DESTRUCTIVE",
            status=AuditStatus.BLOCKED_TIER, error="reason",
        )
        audit_logger.log_event(ev)
        events = audit_logger.get_events(session_id="s2")
        assert len(events) == 1
        assert events[0]["status"] == "blocked_tier"
        assert events[0]["error"] == "reason"

    def test_log_many(self, audit_logger):
        events = [
            AuditEvent(f"s{i}", "nmap", "h", "INTRUSIVE", AuditStatus.ALLOWED)
            for i in range(10)
        ]
        written = audit_logger.log_many(events)
        assert written == 10
        assert audit_logger.count_total() == 10

    def test_log_many_empty(self, audit_logger):
        assert audit_logger.log_many([]) == 0


class TestGetEvents:
    def test_filter_by_session(self, audit_logger):
        _log_sample(audit_logger)
        s1 = audit_logger.get_events(session_id="s1")
        assert len(s1) == 4
        for e in s1:
            assert e["session_id"] == "s1"

    def test_filter_by_status(self, audit_logger):
        _log_sample(audit_logger)
        blocked = audit_logger.get_events(status=AuditStatus.BLOCKED_SCOPE)
        assert len(blocked) == 1
        assert blocked[0]["status"] == "blocked_scope"

    def test_limit_and_offset(self, audit_logger):
        for i in range(10):
            audit_logger.log("s", "t", "h", "SAFE", AuditStatus.ALLOWED)
        page1 = audit_logger.get_events(limit=3, offset=0)
        page2 = audit_logger.get_events(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        # Newest first -> page1[0] is newer than page2[0]
        assert page1[0]["id"] > page2[0]["id"]

    def test_negative_limit_normalised_to_zero(self, audit_logger):
        audit_logger.log("s", "t", "h", "SAFE", AuditStatus.ALLOWED)
        assert audit_logger.get_events(limit=-5) == []


class TestCounts:
    def test_count_by_status(self, audit_logger):
        _log_sample(audit_logger)
        counts = audit_logger.count_by_status()
        assert counts["allowed"] == 1
        assert counts["blocked_scope"] == 1
        assert counts["blocked_tier"] == 1
        assert counts["blocked_rate"] == 1
        assert counts["killed"] == 1
        assert counts["error"] == 0

    def test_count_by_status_per_session(self, audit_logger):
        _log_sample(audit_logger)
        s1 = audit_logger.count_by_status(session_id="s1")
        assert s1["allowed"] == 1
        assert s1["blocked_scope"] == 1
        assert s1["killed"] == 0   # kill event had session_id=None

    def test_count_total(self, audit_logger):
        _log_sample(audit_logger)
        assert audit_logger.count_total() == 5
        assert audit_logger.count_total(session_id="s1") == 4


class TestSnapshot:
    def test_snapshot_structure(self, audit_logger):
        _log_sample(audit_logger)
        snap = audit_logger.snapshot(recent_limit=3)
        assert set(snap.keys()) == {"counts", "total", "recent"}
        assert snap["total"] == 5
        assert len(snap["recent"]) == 3


class TestThreadSafety:
    """10 threads × 50 rows: all should land without loss."""

    def test_concurrent_writes(self, audit_logger):
        N_THREADS = 10
        N_PER_THREAD = 50

        def writer(tid):
            for i in range(N_PER_THREAD):
                audit_logger.log(
                    f"s{tid}", "tool", "host", "INTRUSIVE", AuditStatus.ALLOWED,
                )

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert audit_logger.count_total() == N_THREADS * N_PER_THREAD
