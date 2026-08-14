"""Tests for the v6.4.7 persistent task store (task_store.py).

Verifies that async task state survives an in-process state wipe (which is
what happens when gunicorn recycles a worker) and that ``recover`` correctly
reclassifies leftover running tasks as 'lost'.
"""
from __future__ import annotations

import pytest


# task_store depends on hexstrike_guardrails._db for the connection. Importing
# the guardrails package is cheap (lazy submodule loading).
task_store = pytest.importorskip("task_store")


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """Point the shared guardrails DB at a fresh tmp file for each test."""
    from hexstrike_guardrails import _db
    from hexstrike_guardrails._db import set_db_path, init_db
    db_path = tmp_path / "tasks.db"
    set_db_path(db_path)
    # Reset the initialised flag so init_db runs against the new path.
    _db._INITIALISED = False
    init_db()
    yield db_path
    # restore defaults to avoid bleed into other tests
    set_db_path(_db._DEFAULT_DB_PATH)
    _db._INITIALISED = False


class TestSubmitLifecycle:
    def test_submit_then_get(self, fresh_db):
        tid = task_store.new_task_id()
        assert task_store.submit(tid, command="nmap -sV example.com",
                                 tool="nmap", target="example.com") is True
        row = task_store.get(tid)
        assert row is not None
        assert row["status"] == "queued"
        assert row["tool"] == "nmap"
        assert row["target"] == "example.com"

    def test_mark_running(self, fresh_db):
        tid = task_store.new_task_id()
        task_store.submit(tid)
        assert task_store.mark_running(tid, worker_id=3) is True
        row = task_store.get(tid)
        assert row["status"] == "running"
        assert row["worker_id"] == 3
        assert row["started_at"] is not None

    def test_mark_completed_stores_result_json(self, fresh_db):
        tid = task_store.new_task_id()
        task_store.submit(tid)
        result = {"success": True, "stdout": "open 80", "ports": [80]}
        assert task_store.mark_completed(tid, result, execution_time_ms=1234) is True
        row = task_store.get(tid)
        assert row["status"] == "completed"
        assert row["result"] == result  # decoded back to dict
        assert row["execution_time_ms"] == 1234
        assert row["completed_at"] is not None

    def test_mark_failed_stores_error(self, fresh_db):
        tid = task_store.new_task_id()
        task_store.submit(tid)
        assert task_store.mark_failed(tid, "nmap: not found", 50) is True
        row = task_store.get(tid)
        assert row["status"] == "failed"
        assert row["error"] == "nmap: not found"

    def test_get_unknown_returns_none(self, fresh_db):
        assert task_store.get("does-not-exist-12345") is None


class TestRecoverAfterRecycle:
    """The critical v6.4.7 scenario: worker dies (state wiped), new worker
    boots — what does the poll return?"""

    def test_running_task_marked_lost_on_recover(self, fresh_db):
        # Simulate: previous worker submitted + started a task, then died
        # (in-process state gone, but SQLite row lingers in 'running').
        tid = task_store.new_task_id()
        task_store.submit(tid)
        task_store.mark_running(tid, worker_id=99)

        # New worker boots → recover() runs.
        n = task_store.recover()
        assert n == 1

        row = task_store.get(tid)
        assert row["status"] == "lost"
        # The operator's poll now gets an honest 'lost' instead of 'not_found'.
        assert "recycled" in (row["error"] or "")

    def test_completed_task_not_touched_by_recover(self, fresh_db):
        tid = task_store.new_task_id()
        task_store.submit(tid)
        task_store.mark_completed(tid, {"ok": True}, 100)

        n = task_store.recover()
        assert n == 0  # nothing to recover

        row = task_store.get(tid)
        assert row["status"] == "completed"

    def test_recover_idempotent(self, fresh_db):
        tid = task_store.new_task_id()
        task_store.submit(tid)
        task_store.mark_running(tid)
        assert task_store.recover() == 1
        # Second call on the same DB finds nothing left in running/queued.
        assert task_store.recover() == 0

    def test_multiple_running_tasks_recovered(self, fresh_db):
        for _ in range(5):
            tid = task_store.new_task_id()
            task_store.submit(tid)
            task_store.mark_running(tid)
        assert task_store.recover() == 5


class TestCleanupOld:
    def test_cleanup_removes_old_completed(self, fresh_db, monkeypatch):
        # Insert a row with an old submitted_at timestamp.
        tid = task_store.new_task_id()
        task_store.submit(tid)
        task_store.mark_completed(tid, {"ok": True}, 10)
        # Backdate the row by rewriting submitted_at to 30 days ago.
        from datetime import datetime, timedelta, timezone
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        from hexstrike_guardrails._db import get_connection
        with get_connection() as c:
            c.execute(
                "UPDATE async_tasks SET submitted_at=? WHERE id=?", (old, tid)
            )
        removed = task_store.cleanup_old(days=7)
        assert removed == 1
        assert task_store.get(tid) is None

    def test_cleanup_keeps_recent(self, fresh_db):
        tid = task_store.new_task_id()
        task_store.submit(tid)
        task_store.mark_completed(tid, {"ok": True}, 10)
        assert task_store.cleanup_old(days=7) == 0
        assert task_store.get(tid) is not None
