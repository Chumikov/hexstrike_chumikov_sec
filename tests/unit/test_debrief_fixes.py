"""Lab-debrief fixes (post-v6.5.1 CTF run): regression tests.

Covers the confirmed issues from the field debrief:

  * BUG-1  /api/tools/httpx tech-detect dead-ended with 501 when only the
           Python encode/httpx CLI (or nothing) was installed — now served
           by a built-in requests+TechnologyDetector probe.
  * BUG-2  gobuster bailed on catch-all sites and the generic recovery
           escalated to a human; now the route auto-adds --exclude-length
           (pre-probe + post-failure retry).
  * BUG-3  execute_command caching returned stale results for identical
           commands (2h TTL) — cache is now strictly opt-in.
  * BUG-4  sqlmap/hydra are DESTRUCTIVE tier and the MCP verbs had no way
           to confirm, so legit in-scope runs 403'd while nmap passed —
           the 403 now explains how to authorise, and the MCP verbs carry
           ``confirmed``.
  * BUG-6  hydra forced -l/-L and vanilla hydra has no http-json module —
           username is optional and http-json is served built-in.
  * BUG-9  nuclei/nikto were silent on catch-all/CDN-blocked targets —
           an empty-but-successful run now carries explicit hints.
"""
from __future__ import annotations

import inspect

import pytest

server = pytest.importorskip("hexstrike_server")

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", url="http://x/"):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = text.encode() if isinstance(text, str) else text
        self.url = url


def _fake_fetch_factory(responses_by_url=None, default=None, error=None):
    """Build a fetch(url, **kwargs) stub for _http_fetch injection."""
    calls = []

    def fetch(url, **kwargs):
        calls.append({"url": url, **kwargs})
        if error is not None:
            raise error
        if responses_by_url is not None:
            for prefix, resp in responses_by_url:
                if url.rstrip("/").startswith(prefix.rstrip("/")):
                    return resp
        return default

    fetch.calls = calls
    return fetch


# ---------------------------------------------------------------------------
# BUG-1: built-in httpx probe / tech-detect
# ---------------------------------------------------------------------------


class TestHttpxBuiltinProbe:
    def test_detects_tech_from_headers_and_content(self):
        resp = FakeResponse(
            status_code=200,
            headers={"Server": "nginx/1.18", "X-Powered-By": "PHP/7.4"},
            text="<html><title> Login </title>wp-content</html>",
        )
        fetch = _fake_fetch_factory(default=resp)
        out = server._httpx_builtin_probe("http://example.com", "tech-detect",
                                          fetch=fetch)
        assert out["success"] is True
        assert out["fallback"] == "builtin-http-probe"
        assert out["status_code"] == 200
        assert out["title"] == "Login"
        assert out["web_server"] == "nginx/1.18"
        assert "nginx" in out["technologies"]["web_servers"]
        assert "php" in out["technologies"]["languages"]
        assert "wordpress" in out["technologies"]["cms"]
        assert out["behind_cloudflare"] is False

    def test_flags_cloudflare(self):
        resp = FakeResponse(status_code=403, headers={"Server": "cloudflare",
                                                      "Cf-Ray": "abc123"},
                            text="Attention Required!")
        out = server._httpx_builtin_probe("https://locked.example",
                                          "probe",
                                          fetch=_fake_fetch_factory(default=resp))
        assert out["behind_cloudflare"] is True

    def test_route_serves_techdetect_without_pd_binary(self, guardrails_db,
                                                       monkeypatch):
        monkeypatch.setattr(server, "resolve_httpx_binary",
                            lambda: (None, None))
        resp_obj = FakeResponse(headers={"Server": "Apache"},
                                text="<title>hi</title>")
        monkeypatch.setattr(server, "_http_fetch",
                            lambda url, **kw: resp_obj)
        client = server.app.test_client()
        r = client.post("/api/tools/httpx",
                        json={"target": "example.com", "mode": "tech-detect"})
        # the old code answered 501 here (python variant) / 503 (no binary)
        assert r.status_code == 200
        body = r.get_json()
        assert body["fallback"] == "builtin-http-probe"
        assert "apache" in body["technologies"]["web_servers"]

    def test_route_serves_probe_without_any_binary(self, guardrails_db,
                                                   monkeypatch):
        monkeypatch.setattr(server, "resolve_httpx_binary",
                            lambda: (None, None))
        resp_obj = FakeResponse(status_code=200, headers={}, text="")
        monkeypatch.setattr(server, "_http_fetch",
                            lambda url, **kw: resp_obj)
        client = server.app.test_client()
        r = client.post("/api/tools/httpx",
                        json={"target": "example.com", "mode": "probe"})
        assert r.status_code == 200
        assert r.get_json()["status_code"] == 200


# ---------------------------------------------------------------------------
# BUG-2: gobuster catch-all auto-recovery
# ---------------------------------------------------------------------------


class TestGobusterWildcard:
    def test_error_signature_matches_gobuster_wording(self):
        msg = ("[ERROR] the server returns a status code that matches the "
               "provided options for non existing directories. To continue "
               "please exclude the status code or the length of the response")
        assert server._looks_like_gobuster_wildcard_error(msg) is True
        assert server._looks_like_gobuster_wildcard_error("") is False
        assert server._looks_like_gobuster_wildcard_error(
            "connection refused") is False

    def test_probe_detects_catch_all(self):
        # both random paths answer identically -> catch-all
        fetch = _fake_fetch_factory(default=FakeResponse(
            status_code=200,
            headers={"Content-Length": "42"},
            text="頁面整理中" + "x" * 10))
        wl = server.probe_catch_all("http://iwan.space", fetch=fetch)
        assert wl == {"status": 200, "length": 42}

    def test_probe_rejects_varying_lengths(self):
        responses = [FakeResponse(status_code=200, text="a" * 10),
                     FakeResponse(status_code=200, text="a" * 11)]

        def fetch(url, **kwargs):
            return responses.pop(0)

        assert server.probe_catch_all("http://x", fetch=fetch) is None

    def test_probe_survives_connection_errors(self):
        fetch = _fake_fetch_factory(error=ConnectionError("no route"))
        assert server.probe_catch_all("http://down.example", fetch=fetch) is None

    def test_declared_status_codes_parsing(self):
        assert server._gobuster_declared_status_codes(
            ["gobuster", "dir", "-u", "x"]) is None
        assert server._gobuster_declared_status_codes(
            ["gobuster", "dir", "--status-codes", "200,301"]) == {200, 301}
        assert server._gobuster_declared_status_codes(
            ["gobuster", "dir", "--exclude-status-codes=404"]) == \
            server._GOBUSTER_DEFAULT_MATCH - {404}

    def test_route_prefilters_and_retries_on_wildcard(self, guardrails_db,
                                                      monkeypatch):
        monkeypatch.setattr(server, "probe_catch_all",
                            lambda url, **kw: {"status": 200, "length": 512})
        runs = []

        def fake_exec(tool, argv, target, params):
            runs.append(list(argv))
            if len(runs) == 1:
                return {"success": False,
                        "stdout": "",
                        "stderr": "the server returns a status code that "
                                  "matches the provided options for non "
                                  "existing directories"}
            return {"success": True, "stdout": "/admin (Status: 200)\n",
                    "stderr": ""}

        monkeypatch.setattr(server, "execute_tool_command", fake_exec)
        client = server.app.test_client()
        r = client.post("/api/tools/gobuster",
                        json={"url": "http://iwan.space", "mode": "dir"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        # pre-probe added --exclude-length before the FIRST run
        assert "--exclude-length" in runs[0] and "512" in runs[0]
        # the (simulated) wildcard bail still triggered exactly one retry
        assert len(runs) == 2
        assert body["wildcard_recovery"], body


# ---------------------------------------------------------------------------
# BUG-3: cache strictly opt-in
# ---------------------------------------------------------------------------


class TestCacheOffByDefault:
    def test_execute_command_signature_defaults_off(self):
        assert inspect.signature(server.execute_command).parameters[
            "use_cache"].default is False
        assert inspect.signature(
            server.execute_command_with_recovery).parameters[
            "use_cache"].default is False

    def test_identical_commands_really_re_execute(self, monkeypatch):
        runs = []

        class StubExecutor:
            def __init__(self, command, **kwargs):
                runs.append(command)

            def execute(self):
                return {"success": True, "stdout": f"run-{len(runs)}"}

        monkeypatch.setattr(server, "EnhancedCommandExecutor", StubExecutor)
        first = server.execute_command(["echo", "hi"])
        second = server.execute_command(["echo", "hi"])
        assert len(runs) == 2, "second identical command must not be cached"
        assert first["stdout"] == "run-1"
        assert second["stdout"] == "run-2"

    def test_opt_in_still_caches(self, monkeypatch):
        runs = []

        class StubExecutor:
            def __init__(self, command, **kwargs):
                runs.append(command)

            def execute(self):
                return {"success": True, "stdout": f"run-{len(runs)}"}

        monkeypatch.setattr(server, "EnhancedCommandExecutor", StubExecutor)
        server.execute_command(["echo", "hi"], use_cache=True)
        server.execute_command(["echo", "hi"], use_cache=True)
        assert len(runs) == 1


# ---------------------------------------------------------------------------
# BUG-4: destructive tier has an authorisation path
# ---------------------------------------------------------------------------


class TestTierConfirmation:
    def test_blocked_detail_tells_how_to_authorise(self, fresh_state):
        decision = fresh_state.check("sqlmap", "10.0.0.1")
        assert decision.allowed is False
        assert decision.reason == "tier"
        assert "confirmed=true" in decision.detail

    def test_confirmed_passes(self, fresh_state):
        decision = fresh_state.check("sqlmap", "10.0.0.1", confirmed=True)
        assert decision.allowed is True
        fresh_state.release_target("10.0.0.1")

    def test_sqlmap_route_accepts_confirmed_flag(self, guardrails_db,
                                                 monkeypatch):
        monkeypatch.setattr(
            server, "execute_tool_command",
            lambda tool, argv, target, params: {
                "success": True, "stdout": "", "stderr": ""})
        client = server.app.test_client()
        r = client.post("/api/tools/sqlmap",
                        json={"url": "http://10.0.0.1/api/login",
                              "confirmed": True})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# BUG-6: hydra — optional username + built-in http-json brute
# ---------------------------------------------------------------------------


class TestHydraHttpJson:
    def _post(self, client, payload):
        return client.post("/api/tools/hydra", json=payload)

    def test_missing_template_is_rejected(self, guardrails_db):
        r = self._post(server.app.test_client(), {
            "target": "http://10.0.0.6/api/login", "service": "http-json",
            "password": "x"})
        assert r.status_code == 400
        assert "json_body" in r.get_json()["error"]

    def test_missing_marker_is_rejected(self, guardrails_db):
        r = self._post(server.app.test_client(), {
            "target": "http://10.0.0.6/api/login", "service": "http-json",
            "json_body": '{"u":"^USER^","p":"^PASS^"}',
            "password": "x"})
        assert r.status_code == 400
        assert "marker" in r.get_json()["error"]

    def test_brute_finds_credentials(self, guardrails_db, monkeypatch,
                                     tmp_path):
        wl = tmp_path / "pw.txt"
        wl.write_text("wrong1\nwrong2\ns3cret\n")

        def fetch(url, *, method="GET", timeout=10, json_body=None,
                  raw_body=None, extra_headers=None, fetch=None):
            assert method == "POST"
            if "s3cret" in (raw_body or ""):
                return FakeResponse(status_code=200, headers={},
                                    text='{"token": "tok"}')
            return FakeResponse(status_code=401, headers={},
                                text='{"error": "invalid"}')

        monkeypatch.setattr(server, "_http_fetch", fetch)
        client = server.app.test_client()
        r = self._post(client, {
            "target": "http://10.0.0.6/api/login", "service": "http-json",
            "username": "admin", "password_file": str(wl),
            "json_body": '{"username":"^USER^","password":"^PASS^"}',
            "success_marker": "token", "confirmed": True})
        assert r.status_code == 200
        body = r.get_json()
        assert body["found"] is True
        assert body["credentials"] == [{"username": "admin",
                                        "password": "s3cret"}]
        assert body["attempts"] == 3

    def test_unconfirmed_brute_is_blocked_by_tier(self, guardrails_db,
                                                  monkeypatch):
        monkeypatch.setattr(server, "_http_fetch",
                            lambda url, **kw: FakeResponse())
        client = server.app.test_client()
        r = self._post(client, {
            "target": "http://10.0.0.6/api/login", "service": "http-json",
            "json_body": '{"p":"^PASS^"}', "success_marker": "x",
            "password": "y"})
        assert r.status_code == 403
        assert r.get_json()["reason"] == "tier"

    def test_regular_service_no_longer_requires_username(self, guardrails_db,
                                                         monkeypatch):
        seen = {}

        def fake_exec(tool, argv, target, params):
            seen["argv"] = list(argv)
            return {"success": True, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server, "execute_tool_command", fake_exec)
        client = server.app.test_client()
        r = self._post(client, {
            "target": "10.0.0.6", "service": "ssh",
            "password_file": "/tmp/pw.txt", "confirmed": True})
        assert r.status_code == 200
        assert "-l" not in seen["argv"] and "-L" not in seen["argv"]
        assert "-P" in seen["argv"]


# ---------------------------------------------------------------------------
# BUG-9: nuclei/nikto explain silent targets
# ---------------------------------------------------------------------------


class TestSilentTargetHints:
    def _patch_scan(self, monkeypatch, stdout=""):
        monkeypatch.setattr(
            server, "execute_tool_command",
            lambda tool, argv, target, params: {
                "success": True, "stdout": stdout, "stderr": ""})

    def test_nuclei_hints_catch_all(self, guardrails_db, monkeypatch):
        self._patch_scan(monkeypatch)
        monkeypatch.setattr(server, "probe_catch_all",
                            lambda url, **kw: {"status": 200, "length": 77})
        client = server.app.test_client()
        r = client.post("/api/tools/nuclei",
                        json={"target": "http://catchall.example"})
        body = r.get_json()
        assert body["hints"][0]["type"] == "catch_all_target"

    def test_nuclei_hints_cloudflare_block(self, guardrails_db, monkeypatch):
        self._patch_scan(monkeypatch)
        monkeypatch.setattr(server, "probe_catch_all",
                            lambda url, **kw: None)
        monkeypatch.setattr(
            server, "_http_fetch",
            lambda url, **kw: FakeResponse(
                status_code=403, headers={"Server": "cloudflare",
                                          "Cf-Ray": "z"}, text=""))
        client = server.app.test_client()
        r = client.post("/api/tools/nuclei",
                        json={"target": "http://cf.example"})
        body = r.get_json()
        assert body["hints"][0]["type"] == "cloudflare_block"

    def test_nuclei_with_findings_gets_no_hints(self, guardrails_db,
                                                monkeypatch):
        self._patch_scan(monkeypatch, stdout="[cve-2021-1234] [high]\n")
        monkeypatch.setattr(server, "probe_catch_all", lambda url, **kw: None)
        monkeypatch.setattr(server, "_http_fetch",
                            lambda url, **kw: FakeResponse())
        client = server.app.test_client()
        r = client.post("/api/tools/nuclei",
                        json={"target": "http://clean.example"})
        assert "hints" not in r.get_json()

    def test_nikto_hints_catch_all(self, guardrails_db, monkeypatch):
        self._patch_scan(monkeypatch)
        monkeypatch.setattr(server, "probe_catch_all",
                            lambda url, **kw: {"status": 200, "length": 77})
        client = server.app.test_client()
        r = client.post("/api/tools/nikto",
                        json={"target": "http://catchall.example"})
        assert r.get_json()["hints"][0]["type"] == "catch_all_target"
