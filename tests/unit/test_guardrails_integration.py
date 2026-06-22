"""End-to-end tests for GuardrailsState + Flask blueprint integration.

Exercises the full guardrails pipeline: scope -> tier -> rate -> audit
through both the ``GuardrailsState.check`` Python API and the ``/api/...``
HTTP endpoints exposed by ``blueprint.py``.
"""
import pytest

from hexstrike_guardrails import GuardrailsBlocked, Tier


pytestmark = pytest.mark.guardrails


# ---------------------------------------------------------------------------
# GuardrailsState.check()
# ---------------------------------------------------------------------------


class TestCheckEmptyScope:
    def test_empty_scope_allows_any_target(self, fresh_state):
        d = fresh_state.check("nmap", "evil.com")
        assert d.allowed is True
        assert d.tier is Tier.INTRUSIVE

    def test_destructive_blocked_without_confirmation(self, fresh_state):
        d = fresh_state.check("sqlmap", "evil.com")
        assert d.allowed is False
        assert d.reason == "tier"

    def test_destructive_allowed_with_confirmation(self, fresh_state):
        d = fresh_state.check("sqlmap", "evil.com", confirmed=True)
        assert d.allowed is True
        assert d.tier is Tier.DESTRUCTIVE

    def test_execute_command_always_destructive(self, fresh_state):
        d = fresh_state.check("execute_command", "x")
        assert d.tier is Tier.DESTRUCTIVE
        assert d.allowed is False
        assert d.reason == "tier"


class TestCheckWithScope:
    def test_in_scope_allowed(self, fresh_state, sample_scope_rules):
        fresh_state.update_scope(["192.168.0.0/16", "example.com"])
        d = fresh_state.check("nmap", "192.168.1.1")
        assert d.allowed is True

    def test_out_of_scope_blocked(self, fresh_state):
        fresh_state.update_scope(["192.168.0.0/16"])
        d = fresh_state.check("nmap", "evil.com")
        assert d.allowed is False
        assert d.reason == "scope"

    def test_matched_target_allowed_via_wildcard(self, fresh_state):
        fresh_state.update_scope(["*.example.com"])
        d = fresh_state.check("nmap", "sub.example.com")
        assert d.allowed is True

    def test_audit_row_written_for_block(self, fresh_state):
        fresh_state.update_scope(["192.168.0.0/16"])
        fresh_state.check("nmap", "evil.com")
        events = fresh_state.audit.get_events()
        assert any(e["status"] == "blocked_scope" for e in events)


class TestCheckKillSwitch:
    def test_engaged_kills_dispatch(self, fresh_state):
        fresh_state.kill_switch.engage(session_id=None, reason="test")
        d = fresh_state.check("nmap", "anywhere.com")
        assert d.allowed is False
        assert d.reason == "kill"
        fresh_state.kill_switch.reset()

    def test_kill_event_recorded_in_audit(self, fresh_state):
        fresh_state.kill_switch.engage(session_id=None, reason="test")
        fresh_state.check("nmap", "anywhere.com")
        events = fresh_state.audit.get_events(status="killed")
        assert len(events) >= 1
        fresh_state.kill_switch.reset()


class TestCheckRateLimit:
    def test_rate_limit_blocks_excess(self, fresh_state):
        # Use a state with very low rps to trigger the gate quickly.
        from hexstrike_guardrails.rate_limiter import TargetRateLimiter
        fresh_state.rate_limiter = TargetRateLimiter(max_concurrent=10, max_rps=2)
        results = [fresh_state.check("nmap", "h") for _ in range(5)]
        allowed = [r for r in results if r.allowed]
        blocked = [r for r in results if not r.allowed]
        # Exactly max_rps calls succeed; the rest are blocked.
        assert len(allowed) == 2
        assert all(r.reason == "rate" for r in blocked)
        # Release the acquired slots.
        for _ in allowed:
            fresh_state.release_target("h")


class TestEnforceWrapper:
    def test_allowed_returns_result(self, fresh_state):
        result = fresh_state.enforce(
            "nmap", None, lambda: "ok",
        )
        assert result == "ok"

    def test_blocked_raises(self, fresh_state):
        fresh_state.update_scope(["10.0.0.0/8"])
        with pytest.raises(GuardrailsBlocked) as exc_info:
            fresh_state.enforce("nmap", "evil.com", lambda: "never")
        assert exc_info.value.reason == "scope"
        assert exc_info.value.tier is Tier.INTRUSIVE

    def test_release_target_called_after_fn(self, fresh_state):
        from hexstrike_guardrails.rate_limiter import TargetRateLimiter
        fresh_state.rate_limiter = TargetRateLimiter(max_concurrent=1, max_rps=100)
        # First call acquires + releases the slot.
        fresh_state.enforce("nmap", "h", lambda: "first")
        # Second call should also succeed because the slot was released.
        result = fresh_state.enforce("nmap", "h", lambda: "second")
        assert result == "second"


# ---------------------------------------------------------------------------
# Flask blueprint integration
# ---------------------------------------------------------------------------


class TestFlaskStateEndpoint:
    def test_get_state(self, flask_guardrails_client):
        r = flask_guardrails_client.get("/api/guardrails/state")
        assert r.status_code == 200
        data = r.get_json()
        assert "scope_rules" in data
        assert "rate_limiter" in data
        assert "kill_switch" in data
        assert "audit" in data
        assert "tier_counts" in data
        assert data["kill_switch"]["engaged"] is False


class TestFlaskScope:
    def test_get_empty_scope(self, flask_guardrails_client):
        r = flask_guardrails_client.get("/api/guardrails/scope")
        assert r.status_code == 200
        assert r.get_json() == {"rules": []}

    def test_put_and_get_round_trip(self, flask_guardrails_client):
        r = flask_guardrails_client.put("/api/guardrails/scope",
                                        json={"rules": ["10.0.0.0/8"]})
        assert r.status_code == 200
        assert r.get_json()["rules"] == ["10.0.0.0/8"]
        r = flask_guardrails_client.get("/api/guardrails/scope")
        assert r.get_json()["rules"] == ["10.0.0.0/8"]

    def test_put_rejects_bad_rule(self, flask_guardrails_client):
        r = flask_guardrails_client.put("/api/guardrails/scope",
                                        json={"rules": ["r:[invalid"]})
        assert r.status_code == 400
        assert "invalid_scope_rule" in r.get_json()["error"]

    def test_put_rejects_non_list(self, flask_guardrails_client):
        r = flask_guardrails_client.put("/api/guardrails/scope",
                                        json={"rules": "10.0.0.0/8"})
        assert r.status_code == 400


class TestFlaskValidate:
    def test_validate_in_scope(self, flask_guardrails_client):
        flask_guardrails_client.put("/api/guardrails/scope",
                                    json={"rules": ["10.0.0.0/8"]})
        r = flask_guardrails_client.post("/api/guardrails/validate",
                                         json={"target": "10.0.0.5"})
        d = r.get_json()
        assert d["in_scope"] is True
        assert d["matched_rule"] == "10.0.0.0/8"

    def test_validate_out_of_scope(self, flask_guardrails_client):
        flask_guardrails_client.put("/api/guardrails/scope",
                                    json={"rules": ["10.0.0.0/8"]})
        r = flask_guardrails_client.post("/api/guardrails/validate",
                                         json={"target": "192.168.0.1"})
        d = r.get_json()
        assert d["in_scope"] is False
        assert d["matched_rule"] is None

    def test_validate_rejects_missing_target(self, flask_guardrails_client):
        r = flask_guardrails_client.post("/api/guardrails/validate", json={})
        assert r.status_code == 400


class TestFlaskTiers:
    def test_tiers_endpoint(self, flask_guardrails_client):
        r = flask_guardrails_client.get("/api/guardrails/tiers")
        assert r.status_code == 200
        data = r.get_json()
        assert "sqlmap" in data
        assert data["sqlmap"] == "DESTRUCTIVE"
        assert data["subfinder"] == "SAFE"
        assert data["nmap"] == "INTRUSIVE"

    def test_tier_summary_endpoint(self, flask_guardrails_client):
        r = flask_guardrails_client.get("/api/guardrails/tier-summary")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] > 100
        assert set(data["by_tier"].keys()) == {"SAFE", "INTRUSIVE", "DESTRUCTIVE"}


class TestFlaskKillSwitch:
    def test_kill_all_then_reset(self, flask_guardrails_client):
        r = flask_guardrails_client.post("/api/guardrails/kill-all",
                                         json={"reason": "test"})
        assert r.status_code == 200
        assert r.get_json()["killed_count"] == 0  # no procs registered
        # Engaged now.
        r = flask_guardrails_client.get("/api/guardrails/state")
        assert r.get_json()["kill_switch"]["engaged"] is True
        # Reset.
        r = flask_guardrails_client.post("/api/guardrails/reset")
        assert r.status_code == 200
        assert r.get_json()["was_engaged"] is True


class TestFlaskAudit:
    def test_audit_empty_initially(self, flask_guardrails_client):
        r = flask_guardrails_client.get("/api/guardrails/audit")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] == 0
        assert data["events"] == []


class TestFlaskSessionAudit:
    def test_session_audit_endpoint(self, flask_guardrails_client):
        r = flask_guardrails_client.get("/api/session/sess-x/audit")
        assert r.status_code == 200
        data = r.get_json()
        assert data["session_id"] == "sess-x"
        assert data["total"] == 0


class TestErrorHandling:
    def test_blocked_returns_403(self, flask_guardrails_client, fresh_state):
        fresh_state.update_scope(["10.0.0.0/8"])

        @flask_guardrails_client.application.route("/__test_dispatch")
        def _dispatch():
            from flask import jsonify
            try:
                fresh_state.enforce(
                    "nmap", "evil.com", lambda: "ok",
                )
            except GuardrailsBlocked as exc:
                return jsonify(exc.to_dict()), 403
            return jsonify({"ok": True})

        r = flask_guardrails_client.get("/__test_dispatch")
        assert r.status_code == 403
        d = r.get_json()
        assert d["reason"] == "scope"
        assert d["tier"] == "INTRUSIVE"
