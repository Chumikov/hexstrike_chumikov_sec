"""Field-report fixes (post-v6.4.7 CTF weekend): regression tests.

Covers the four confirmed bugs + the audit-coverage observation:

  * BUG-1  httpx binary conflict — PD (Go) vs Python encode/httpx CLI
  * BUG-2  nmap "full" mode dragging in broadcast NSE scripts + no bounds
  * BUG-3  optimizer dedup corrupting positional data (bitmaps/dumps)
  * BUG-4  runaway subprocess output (94 MB / 20 min case)
  * OBS    /api/command executing outside the guardrails audit trail
"""
from __future__ import annotations

import pytest

server = pytest.importorskip("hexstrike_server")

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# BUG-2: build_nmap_advanced_command
# ---------------------------------------------------------------------------


class TestNmapAdvancedCommand:
    BASE = {"target": "192.0.2.10", "scan_type": "-sV -sC", "ports": "1337,22"}

    def test_valid_params_produce_argv(self):
        argv, err = server.build_nmap_advanced_command(self.BASE)
        assert err is None
        assert argv[0] == "nmap"
        assert argv[-1] == "192.0.2.10"
        assert "-sV" in argv and "-sC" in argv

    def test_default_script_set_is_target_scoped(self):
        argv, _ = server.build_nmap_advanced_command(self.BASE)
        scripts = [a for a in argv if a.startswith("--script=")]
        assert any(a == "--script=default,safe" for a in scripts)
        # BUG-2: the old default was default,discovery,safe — discovery pulls
        # in the broadcast/* NSE family (L2 shout, neighbour sniffing).
        assert not any("discovery" in a for a in scripts)

    def test_broadcast_scripts_explicitly_excluded(self):
        argv, _ = server.build_nmap_advanced_command(self.BASE)
        assert "--script-exclude=broadcast" in argv

    def test_broadcast_excluded_even_with_custom_scripts(self):
        argv, err = server.build_nmap_advanced_command(
            {**self.BASE, "nse_scripts": "vuln,safe"})
        assert err is None
        assert "--script=vuln,safe" in argv
        assert "--script-exclude=broadcast" in argv

    def test_host_and_script_timeouts_present(self):
        argv, _ = server.build_nmap_advanced_command(self.BASE)
        assert "--host-timeout=2m" in argv
        assert "--script-timeout=30s" in argv

    def test_aggressive_skips_default_script_block(self):
        argv, _ = server.build_nmap_advanced_command(
            {**self.BASE, "aggressive": True})
        assert "-A" in argv
        assert not any(a == "--script=default,safe" for a in argv)

    def test_stealth_overrides_timing(self):
        argv, _ = server.build_nmap_advanced_command(
            {**self.BASE, "stealth": True})
        assert "-T2" in argv and "-f" in argv
        assert "-T4" not in argv

    @pytest.mark.parametrize("bad", [
        "-sV; rm -rf /", "-sV $(id)", "--datadir", "-iL /etc/passwd",
    ])
    def test_rejects_unknown_scan_type(self, bad):
        argv, err = server.build_nmap_advanced_command(
            {**self.BASE, "scan_type": bad})
        assert argv is None and err is not None

    @pytest.mark.parametrize("bad", ["80; id", "1-65535 $(whoami)", "22&bg"])
    def test_rejects_poisoned_ports(self, bad):
        argv, err = server.build_nmap_advanced_command({**self.BASE, "ports": bad})
        assert argv is None and err is not None

    def test_rejects_poisoned_nse_scripts(self):
        argv, err = server.build_nmap_advanced_command(
            {**self.BASE, "nse_scripts": "safe; rm -rf /"})
        assert argv is None and err is not None

    def test_rejects_bad_timing(self):
        argv, err = server.build_nmap_advanced_command({**self.BASE, "timing": "T9"})
        assert argv is None and "timing" in err


# ---------------------------------------------------------------------------
# BUG-1: httpx binary resolution + flag dialect
# ---------------------------------------------------------------------------


class TestHttpxSniff:
    def _fake_run(self, stdout="", stderr=""):
        class R:
            pass
        r = R()
        r.stdout, r.stderr = stdout, stderr
        return lambda *a, **k: r

    def test_pd_variant_detected_by_flags(self, monkeypatch):
        monkeypatch.setattr(
            server.subprocess, "run",
            self._fake_run(stdout="  -status-code\n  -tech-detect\n"))
        assert server._sniff_httpx_variant("/fake/httpx") == "pd"

    def test_python_variant_detected_by_usage(self, monkeypatch):
        monkeypatch.setattr(
            server.subprocess, "run",
            self._fake_run(stderr="Usage: httpx [OPTIONS] URL\n"))
        assert server._sniff_httpx_variant("/fake/httpx") == "python"

    def test_kali_python3_httpx_dialect_detected(self, monkeypatch):
        # Kali ships httpx from the python3-httpx deb: "Usage: httpx <URL> [OPTIONS]"
        monkeypatch.setattr(
            server.subprocess, "run",
            self._fake_run(stdout="Usage: httpx <URL> [OPTIONS]"))
        assert server._sniff_httpx_variant("/fake/httpx") == "python"

    def test_unknown_help_text(self, monkeypatch):
        monkeypatch.setattr(server.subprocess, "run", self._fake_run(stdout="wat"))
        assert server._sniff_httpx_variant("/fake/httpx") is None

    def test_probe_failure_returns_none(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("nope")
        monkeypatch.setattr(server.subprocess, "run", boom)
        assert server._sniff_httpx_variant("/fake/httpx") is None


class TestHttpxResolver:
    @pytest.fixture(autouse=True)
    def _fresh_cache(self, monkeypatch):
        monkeypatch.setattr(server, "_HTTPX_BIN_CACHE",
                            {"checked": False, "binary": None, "variant": None})

    def _make_bin(self, tmp_path):
        binpath = tmp_path / "httpx"
        binpath.write_text("#!/bin/sh\nexit 0\n")
        binpath.chmod(0o755)
        return str(binpath)

    def test_env_override_with_pd_variant(self, tmp_path, monkeypatch):
        binpath = self._make_bin(tmp_path)
        monkeypatch.setenv("HEXSTRIKE_HTTPX_BIN", binpath)
        monkeypatch.setattr(server, "_sniff_httpx_variant", lambda b: "pd")
        binary, variant = server.resolve_httpx_binary()
        assert (binary, variant) == (binpath, "pd")

    def test_python_variant_is_fallback(self, tmp_path, monkeypatch):
        binpath = self._make_bin(tmp_path)
        monkeypatch.setenv("HEXSTRIKE_HTTPX_BIN", binpath)
        monkeypatch.setattr(server, "_sniff_httpx_variant", lambda b: "python")
        monkeypatch.setattr(server.shutil, "which", lambda name: None)
        binary, variant = server.resolve_httpx_binary()
        assert (binary, variant) == (binpath, "python")

    def test_no_functional_httpx_found(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HEXSTRIKE_HTTPX_BIN", raising=False)
        monkeypatch.setattr(server.shutil, "which", lambda name: None)
        # every candidate binary exists but speaks no known dialect
        monkeypatch.setattr(server, "_sniff_httpx_variant", lambda b: None)
        binary, variant = server.resolve_httpx_binary()
        assert binary is None and variant is None

    def test_result_is_cached(self, tmp_path, monkeypatch):
        binpath = self._make_bin(tmp_path)
        monkeypatch.setenv("HEXSTRIKE_HTTPX_BIN", binpath)
        calls = []
        monkeypatch.setattr(
            server, "_sniff_httpx_variant",
            lambda b: calls.append(b) or "pd")
        server.resolve_httpx_binary()
        server.resolve_httpx_binary()
        assert len(calls) == 1  # second call served from cache


class TestHttpxFlagMapping:
    def test_mode_tech_detect_maps_to_flag(self):
        assert "-tech-detect" in server._httpx_pd_flags(
            {"target": "x", "mode": "tech-detect"})

    def test_mode_probe_implies_status_code(self):
        assert "-status-code" in server._httpx_pd_flags(
            {"target": "x", "mode": "probe"})

    def test_explicit_booleans(self):
        flags = server._httpx_pd_flags(
            {"target": "x", "tech_detect": True, "title": True,
             "content_length": True, "web_server": True})
        for f in ("-tech-detect", "-title", "-content-length", "-web-server"):
            assert f in flags

    def test_pd_dialect_uses_long_flags_not_legacy_short(self):
        # The old string command used -sc/-cl/-server (legacy httpx dialect);
        # PD httpx spells them -status-code/-content-length/-web-server.
        flags = server._httpx_pd_flags(
            {"target": "x", "status_code": True, "content_length": True,
             "web_server": True})
        assert "-sc" not in flags and "-cl" not in flags and "-server" not in flags
        assert "-status-code" in flags and "-content-length" in flags


# ---------------------------------------------------------------------------
# BUG-4: output cap + stdin support in EnhancedCommandExecutor
# ---------------------------------------------------------------------------


class TestOutputCap:
    def test_flooding_process_is_capped_and_killed(self):
        exe = server.EnhancedCommandExecutor(
            ["python3", "-c",
             "import sys\nwhile True: sys.stdout.write('A' * 512 + '\\n');"
             " sys.stdout.flush()"],
            timeout=60,          # generous wall timeout — the CAP must fire
            max_output_bytes=8192,
        )
        result = exe.execute()
        assert result["output_truncated"] is True
        assert result["output_cap_bytes"] == 8192
        assert len(result["stdout"]) + len(result["stderr"]) <= 8192
        # killed by the cap, not by the wall timeout
        assert result["timed_out"] is False
        assert result["execution_time"] < 30

    def test_normal_output_not_flagged(self):
        exe = server.EnhancedCommandExecutor(
            ["python3", "-c", "print('hello')"], timeout=30)
        result = exe.execute()
        assert result["output_truncated"] is False
        assert result["stdout"].strip() == "hello"
        assert "output_cap_bytes" not in result

    def test_stdin_data_is_written_to_child(self):
        exe = server.EnhancedCommandExecutor(["cat"], stdin_data="probe-me\n")
        result = exe.execute()
        assert result["stdout"] == "probe-me\n"


# ---------------------------------------------------------------------------
# OBS: /api/command under guardrails (audit coverage)
# ---------------------------------------------------------------------------


class TestApiCommandGuardrails:
    @pytest.fixture
    def client(self, guardrails_db):
        server.app.config["TESTING"] = True
        return server.app.test_client()

    @pytest.fixture
    def state(self, fresh_state):
        return fresh_state

    def test_bare_command_writes_audit_row(self, client, state):
        before = state.audit.count_total()
        resp = client.post("/api/command", json={"command": "true"})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        assert state.audit.count_total() == before + 1
        events = state.audit.get_events(limit=1)
        assert events[0]["tool"] == "true"
        assert events[0]["status"] == "allowed"

    def test_out_of_scope_command_blocked(self, client, state):
        state.update_scope(["10.0.0.0/8"])
        resp = client.post(
            "/api/command", json={"command": "curl -s http://192.0.2.1/"})
        assert resp.status_code == 403
        body = resp.get_json()
        assert body["reason"] == "scope"
        assert body["target"] == "http://192.0.2.1/"
        assert any(e["status"] == "blocked_scope" for e in state.audit.get_events())

    def test_destructive_binary_requires_confirmation(self, client, state):
        state.update_scope(["10.0.0.0/8"])
        resp = client.post(
            "/api/command",
            json={"command": "sqlmap -u http://10.0.0.5/?id=1 --batch"})
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "tier"

    def test_kill_switch_blocks_everything(self, client, state):
        state.kill_switch.engage(session_id=None, reason="test")
        resp = client.post("/api/command", json={"command": "true"})
        assert resp.status_code == 503
        assert resp.get_json()["reason"] == "kill"
        state.kill_switch.reset()

    def test_tool_and_target_inference(self):
        assert server._infer_bare_tool("nmap -sV 10.0.0.1") == "nmap"
        assert server._infer_bare_tool(["/usr/bin/curl", "-s", "x"]) == "curl"
        assert server._infer_bare_tool("") == "bare-command"
        assert server._infer_bare_target("curl -s http://10.0.0.5/x") == "http://10.0.0.5/x"
        assert server._infer_bare_target("nmap -p 22 192.168.1.1") == "192.168.1.1"
        assert server._infer_bare_target("nmap -sV 10.0.0.0/24") == "10.0.0.0/24"
        assert server._infer_bare_target("ls -la") is None
