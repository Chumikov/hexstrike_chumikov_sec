"""Tests for the v6.4.7 input-validation and command-injection hardening.

These cover:
  * ``validate_target`` / ``validate_url`` / ``_shell_split`` in
    ``hexstrike_server.py`` — the gate that rejects shell-metacharacter
    injection and CRLF in tool targets/urls;
  * ``EnhancedCommandExecutor`` accepting an argv list and passing it to
    ``subprocess`` with ``shell=False``;
  * the smart-scan helper ``execute_tool_command`` returning a structured
    error dict (rather than raising) when given a poisoned target.

Importing ``hexstrike_server`` pulls in Flask and a number of Kali-only
optional deps (mitmproxy). The conftest already stubs the latter for non-Kali
CI, so a plain import is sufficient.
"""
from __future__ import annotations

import pytest


# Server import is heavy and may be skipped on minimal CI environments.
server = pytest.importorskip("hexstrike_server")


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------


class TestValidateTarget:
    def test_accepts_plain_hostname(self):
        assert server.validate_target("example.com") == "example.com"

    def test_accepts_ipv4(self):
        assert server.validate_target("192.168.1.10") == "192.168.1.10"

    def test_accepts_ipv6(self):
        assert server.validate_target("::1") == "::1"

    def test_accepts_cidr(self):
        assert server.validate_target("10.0.0.0/8") == "10.0.0.0/8"

    def test_strips_surrounding_whitespace(self):
        assert server.validate_target("  example.com  ") == "example.com"

    @pytest.mark.parametrize(
        "poison",
        [
            "127.0.0.1; rm -rf /",
            "example.com$(whoami)",
            "example.com`id`",
            "example.com & curl attacker",
            "example.com | cat /etc/passwd",
            "example.com\nDROP TABLE users",
            "example.com\t-x",
        ],
    )
    def test_rejects_shell_metacharacters(self, poison):
        with pytest.raises(ValueError):
            server.validate_target(poison)

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            server.validate_target("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValueError):
            server.validate_target("   ")

    def test_rejects_non_string(self):
        with pytest.raises(ValueError):
            server.validate_target(None)  # type: ignore[arg-type]

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError):
            server.validate_target("example.com\x00")

    def test_rejects_overlong(self):
        with pytest.raises(ValueError):
            server.validate_target("a" * 2000)


# ---------------------------------------------------------------------------
# validate_url
# ---------------------------------------------------------------------------


class TestValidateUrl:
    def test_accepts_http_url(self):
        assert server.validate_url("http://example.com/") == "http://example.com/"

    def test_accepts_https_with_port_and_path(self):
        u = "https://target.local:8443/api/v1?id=1"
        assert server.validate_url(u) == u

    def test_accepts_bare_host_port(self):
        # No scheme — urlparse puts it in path, we still allow it.
        assert server.validate_url("10.0.0.5:8080") == "10.0.0.5:8080"

    def test_accepts_query_string_with_ampersand(self):
        # & is legitimate inside a URL query — must not be rejected.
        u = "http://example.com/?a=1&b=2"
        assert server.validate_url(u) == u

    def test_rejects_crlf_injection(self):
        with pytest.raises(ValueError):
            server.validate_url("http://example.com/\r\nX-Injected: yes")

    def test_rejects_host_with_shell_metachar(self):
        with pytest.raises(ValueError):
            server.validate_url("http://example.com; rm -rf /")

    def test_rejects_scheme_without_host(self):
        with pytest.raises(ValueError):
            server.validate_url("http://")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            server.validate_url("")


# ---------------------------------------------------------------------------
# _shell_split
# ---------------------------------------------------------------------------


class TestShellSplit:
    def test_empty_returns_empty_list(self):
        assert server._shell_split("") == []

    def test_none_returns_empty_list(self):
        assert server._shell_split(None) == []

    def test_simple_flags(self):
        assert server._shell_split("-T4 -Pn --max-retries 3") == [
            "-T4", "-Pn", "--max-retries", "3",
        ]

    def test_quoted_value_preserved(self):
        # shlex understands the quotes; the resulting token has no quotes,
        # and crucially there is no shell to interpret the contents later.
        assert server._shell_split('--data "a=1&b=2"') == ["--data", "a=1&b=2"]

    def test_unterminated_quote_raises(self):
        with pytest.raises(ValueError):
            server._shell_split("--data 'unterminated")

    def test_semicolon_becomes_literal_token(self):
        # The whole point: a ";" in args is no longer a command separator
        # because subprocess receives it as a literal argv element.
        assert server._shell_split("-x ; rm") == ["-x", ";", "rm"]


# ---------------------------------------------------------------------------
# EnhancedCommandExecutor — argv form
# ---------------------------------------------------------------------------


class TestExecutorArgvForm:
    def test_constructor_marks_argv(self):
        ex = server.EnhancedCommandExecutor(["echo", "hello"])
        assert ex.command_argv is True

    def test_constructor_marks_string(self):
        ex = server.EnhancedCommandExecutor("echo hello")
        assert ex.command_argv is False

    def test_argv_runs_without_shell(self, monkeypatch):
        """When given a list, subprocess.Popen must be called with shell=False
        and the list passed through verbatim — no join, no reinterpretation."""
        captured: dict = {}
        real_popen = server.subprocess.Popen

        class _FakeProc:
            pid = 4242

            def wait(self, timeout=None):
                return 0

            def communicate(self, timeout=None):
                return ("ok", "")

            def terminate(self):
                pass

            def kill(self):
                pass

        def fake_popen(args, *a, **kw):
            captured["args"] = args
            captured["shell"] = kw.get("shell")
            return real_popen.__new__(_FakeProc)

        # Patch at module level. Also neutralise the process manager / threads
        # by short-circuiting the read helpers.
        monkeypatch.setattr(server.subprocess, "Popen", fake_popen)
        ex = server.EnhancedCommandExecutor(["echo", "a; rm -rf /"])
        # We don't care about the result dict shape here, only the Popen call.
        try:
            ex.execute()
        except Exception:
            # Threads/side effects may raise after Popen; the call was still
            # captured.
            pass
        assert captured["shell"] is False
        assert captured["args"] == ["echo", "a; rm -rf /"]


# ---------------------------------------------------------------------------
# execute_tool_command — guardrails + validation integration
# ---------------------------------------------------------------------------


class TestExecuteToolCommand:
    def test_rejects_poisoned_target_without_calling_subprocess(self, monkeypatch):
        """A target containing shell metacharacters must be rejected before
        any subprocess is spawned — proving the injection sink is closed."""
        called: list = []

        class _BoomPopen:
            def __init__(self, *a, **kw):
                called.append((a, kw))
                raise AssertionError("subprocess must not be spawned")

        monkeypatch.setattr(server.subprocess, "Popen", _BoomPopen)

        result = server.execute_tool_command(
            "nmap", ["nmap", "-sV", "127.0.0.1; rm -rf /"],
            target="127.0.0.1; rm -rf /", params={},
        )
        assert result["success"] is False
        assert "invalid target" in result["error"]
        assert called == []  # no subprocess was ever started

    def test_rejects_non_list_argv(self):
        result = server.execute_tool_command("nmap", "nmap -sV x", "x", {})
        assert result["success"] is False
        assert "argv" in result["error"]

    def test_empty_argv_rejected(self):
        result = server.execute_tool_command("nmap", [], "x", {})
        assert result["success"] is False
