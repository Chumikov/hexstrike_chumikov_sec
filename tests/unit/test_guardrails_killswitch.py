"""Unit tests for hexstrike_guardrails.killswitch (G4)."""
import os
import signal
import subprocess
import time

import pytest

from hexstrike_guardrails import KillSwitch
from hexstrike_guardrails.killswitch import KillOutcome


pytestmark = pytest.mark.guardrails


def _sleep_proc(seconds: int = 30) -> subprocess.Popen:
    """Spawn a `sleep N` subprocess; tests must wait()/kill() it."""
    return subprocess.Popen(["sleep", str(seconds)])


class TestRegisterUnregister:
    def test_register_increments_count(self, kill_switch):
        ks = kill_switch
        assert ks.registered_count() == 0
        ks.register("s1", 100)
        assert ks.registered_count() == 1
        ks.register("s1", 101)
        assert ks.registered_count() == 2
        assert ks.registered_count("s1") == 2

    def test_unregister_decrements(self, kill_switch):
        ks = kill_switch
        ks.register("s1", 100)
        ks.register("s1", 101)
        ks.unregister("s1", 100)
        assert ks.registered_count("s1") == 1
        ks.unregister("s1", 101)
        assert ks.registered_count("s1") == 0
        # Empty buckets are removed.
        assert ks.engaged_session_ids() == []

    def test_unregister_unknown_is_noop(self, kill_switch):
        ks = kill_switch
        ks.unregister("nope", 999)  # never registered
        ks.register("s1", 100)
        ks.unregister("s1", 999)    # pid never registered
        assert ks.registered_count("s1") == 1

    def test_register_bad_input_ignored(self, kill_switch):
        ks = kill_switch
        ks.register("", 100)        # empty session
        ks.register("s1", 0)        # invalid pid
        ks.register("s1", -1)       # invalid pid
        ks.register("s1", "abc")    # type error pass
        assert ks.registered_count() == 0


class TestEngagedSession:
    def test_engaged_initially_false(self, kill_switch):
        assert kill_switch.is_engaged() is False

    def test_session_specific_kill_does_not_set_global(self, kill_switch):
        ks = kill_switch
        p = _sleep_proc()
        try:
            ks.register("s1", p.pid, p)
            report = ks.engage(session_id="s1", reason="abort", kill_grace_sec=1.0)
            assert report.session_id == "s1"
            assert p.pid in report.killed
            assert ks.is_engaged() is False    # global flag NOT toggled
            # Process is gone.
            assert p.poll() is not None
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()

    def test_engage_unknown_session_no_op(self, kill_switch):
        ks = kill_switch
        report = ks.engage(session_id="never-existed", reason="x")
        assert report.killed == []
        assert report.failed == []
        assert ks.is_engaged() is False

    def test_report_to_dict(self, kill_switch):
        ks = kill_switch
        p = _sleep_proc()
        try:
            ks.register("s1", p.pid, p)
            report = ks.engage(session_id="s1", reason="r", kill_grace_sec=1.0)
            d = report.to_dict()
            assert d["session_id"] == "s1"
            assert d["reason"] == "r"
            assert d["killed_count"] == 1
            assert "engaged_at" in d
            assert str(p.pid) in d["outcomes"]
        finally:
            if p.poll() is None:
                p.kill()


class TestEngageAll:
    def test_kill_all_sets_global_flag(self, kill_switch):
        ks = kill_switch
        p1 = _sleep_proc()
        p2 = _sleep_proc()
        try:
            ks.register("s1", p1.pid, p1)
            ks.register("s2", p2.pid, p2)
            report = ks.engage(session_id=None, reason="emergency")
            assert len(report.killed) == 2
            assert ks.is_engaged() is True
        finally:
            for p in (p1, p2):
                if p.poll() is None:
                    p.kill()
                    p.wait()

    def test_reset_clears_global_flag(self, kill_switch):
        ks = kill_switch
        ks.engage(session_id=None, reason="x")
        assert ks.is_engaged() is True
        assert ks.reset() is True
        assert ks.is_engaged() is False
        # Second reset returns False (was already idle).
        assert ks.reset() is False


class TestSignalEscalation:
    def test_sigterm_graceful(self, kill_switch):
        ks = kill_switch
        p = _sleep_proc()
        ks.register("s", p.pid, p)
        try:
            report = ks.engage(session_id="s", kill_grace_sec=2.0)
            outcome = report.outcomes[p.pid]
            assert outcome in (KillOutcome.TERMINATED, KillOutcome.NOT_FOUND)
            assert p.poll() is not None
        finally:
            if p.poll() is None:
                p.kill()

    def test_already_dead_process_returns_not_found(self, kill_switch):
        ks = kill_switch
        p = _sleep_proc()
        p.terminate()
        p.wait()
        ks.register("s", p.pid, p)
        report = ks.engage(session_id="s", kill_grace_sec=0.5)
        assert report.outcomes[p.pid] is KillOutcome.NOT_FOUND


class TestPersistence:
    def test_kill_event_stored_in_db(self, kill_switch, guardrails_db):
        """After engage(), a row appears in kill_switch_events."""
        ks = kill_switch
        p = _sleep_proc()
        try:
            ks.register("s1", p.pid, p)
            ks.engage(session_id="s1", reason="recorded")
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
        # Read straight from the DB to verify the row landed.
        from hexstrike_guardrails._db import get_connection
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT session_id, reason, killed_count FROM kill_switch_events"
            ).fetchall()
        assert len(rows) == 1
        assert rows[0]["session_id"] == "s1"
        assert rows[0]["reason"] == "recorded"
        assert rows[0]["killed_count"] == 1


class TestSnapshot:
    def test_snapshot_shape(self, kill_switch):
        ks = kill_switch
        snap = ks.snapshot()
        assert set(snap.keys()) == {"engaged", "sessions_with_procs", "registered_procs"}
        assert snap["engaged"] is False
        assert snap["sessions_with_procs"] == 0
        assert snap["registered_procs"] == 0
