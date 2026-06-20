"""Unit tests for hexstrike_optimizer.OutputOptimizer."""
import os

import pytest

from hexstrike_optimizer import OutputOptimizer


@pytest.fixture
def opt():
    # Small thresholds so tests stay compact.
    return OutputOptimizer(enabled=True, max_chars=200, dedup=True,
                           strip_ansi=True, min_chars_to_process=20)


class TestPassthrough:
    def test_disabled_returns_unchanged(self):
        o = OutputOptimizer(enabled=False)
        result = {"output": "x" * 5000}
        assert o.optimize(result) is result  # same object, untouched

    def test_non_dict_returned_unchanged(self, opt):
        assert opt.optimize(["a", "b"]) == ["a", "b"]
        assert opt.optimize("string") == "string"

    def test_short_strings_untouched(self, opt):
        result = {"status": "ok", "version": "6.3.0"}
        out = opt.optimize(result)
        assert out == {"status": "ok", "version": "6.3.0"}
        assert "_optimizer" not in out


class TestStripAnsi:
    def test_removes_color_codes(self, opt):
        text = "\x1b[91mRED\x1b[0m normal " + "x" * 50
        out = opt.optimize({"output": text})
        assert "\x1b" not in out["output"]
        assert "RED" in out["output"]
        assert "normal" in out["output"]

    def test_removes_csi_sequences(self, opt):
        text = "\x1b[1;33;40mBOLD-YELLOW\x1b[0m" + "y" * 50
        out = opt.optimize({"output": text})
        assert "BOLD-YELLOW" in out["output"]


class TestCarriageReturnCollapse:
    def test_progress_bar_overwrite_keeps_final(self, opt):
        # Simulates an in-place progress bar: each stage overwrites via \r
        text = "PROGRESS 0%\rPROGRESS 50%\rPROGRESS 100% done\n" + "z" * 50
        out = opt.optimize({"output": text})
        assert "PROGRESS 100% done" in out["output"]
        assert "PROGRESS 0%" not in out["output"]
        assert "PROGRESS 50%" not in out["output"]


class TestDedup:
    def test_consecutive_duplicates_removed(self, opt):
        line = "scanning host 10.0.0.1 ..." + "a" * 30
        text = "\n".join([line] * 5)
        out = opt.optimize({"output": text})
        # The repeated line should appear only once now.
        assert out["output"].count(line) == 1
        assert "duplicate lines removed: 4" in out["output"]


class TestTruncate:
    def test_long_output_truncated_with_marker(self):
        o = OutputOptimizer(enabled=True, max_chars=100, min_chars_to_process=10)
        text = "H" * 400 + "T" * 400  # 800 chars
        out = o.optimize({"output": text})
        result = out["output"]
        assert "[truncated" in result
        assert "original 800" in result
        assert len(result) < 800

    def test_truncate_preserves_head_and_tail(self):
        o = OutputOptimizer(enabled=True, max_chars=100, min_chars_to_process=10)
        # HEAD token at start, MIDDLE bulk, TAIL token at end — sized so the
        # head window (60) captures only HEAD and tail window (40) only TAIL.
        text = "HEADSTART" + "H" * 60 + "MIDDLE" * 80 + "T" * 60 + "TAILEND"
        out = o.optimize({"output": text})
        assert "HEADSTART" in out["output"]
        assert "TAILEND" in out["output"]
        assert "MIDDLE" not in out["output"]


class TestMetaAndStats:
    def test_optimizer_meta_added_when_changed(self, opt):
        text = "\x1b[31m" + "x" * 50
        out = opt.optimize({"output": text})
        assert out["_optimizer"]["enabled"] is True
        assert out["_optimizer"]["max_chars"] == 200

    def test_no_meta_when_unchanged(self, opt):
        # Long enough to process, but no ANSI/dup/overflow -> identical -> no meta
        text = "plain line only " + "p" * 50
        out = opt.optimize({"output": text})
        assert "_optimizer" not in out

    def test_stats_track_processing(self):
        o = OutputOptimizer(enabled=True, max_chars=100, min_chars_to_process=10)
        o.optimize({"output": "H" * 400})
        stats = o.get_stats()
        assert stats["responses_processed"] == 1
        assert stats["responses_truncated"] == 1
        assert stats["chars_in"] == 400
        assert stats["chars_out"] < 400


class TestFromEnv:
    def test_reads_env_config(self, monkeypatch):
        monkeypatch.setenv("MCP_OPTIMIZER_ENABLED", "false")
        monkeypatch.setenv("MCP_OPTIMIZER_MAX_CHARS", "1234")
        monkeypatch.setenv("MCP_OPTIMIZER_DEDUP", "no")
        o = OutputOptimizer.from_env()
        assert o.enabled is False
        assert o.max_chars == 1234
        assert o.dedup is False

    def test_defaults_when_env_absent(self, monkeypatch):
        for var in ("MCP_OPTIMIZER_ENABLED", "MCP_OPTIMIZER_MAX_CHARS",
                    "MCP_OPTIMIZER_DEDUP", "MCP_OPTIMIZER_STRIP_ANSI"):
            monkeypatch.delenv(var, raising=False)
        o = OutputOptimizer.from_env()
        assert o.enabled is True
        assert o.max_chars == 20000
        assert o.dedup is True
        assert o.strip_ansi is True


class TestNmapLikeOutput:
    """Realistic regression: a large nmap-style output gets meaningfully smaller
    without losing the key findings."""
    def test_nmap_output_shrinks(self):
        o = OutputOptimizer(enabled=True, max_chars=2000, min_chars_to_process=100)
        # Build a noisy output: ANSI + progress + repeated lines + a finding.
        lines = []
        for i in range(200):
            lines.append(f"\x1b[32m{chr(27)}[K\rPORT SCAN {i}%\x1b[0m")
        lines.append("22/tcp open ssh OpenSSH 8.9" + "x" * 40)
        lines.append("22/tcp open ssh OpenSSH 8.9" + "x" * 40)  # duplicate
        for _ in range(300):
            lines.append("filler " * 20)
        text = "\n".join(lines)
        result = {"output": text, "success": True}
        out = o.optimize(result)
        assert len(out["output"]) < len(text)
        assert "22/tcp open ssh OpenSSH 8.9" in out["output"]
        assert out["success"] is True
