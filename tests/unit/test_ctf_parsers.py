"""Unit tests for hexstrike_server CTF / BugBounty parsing helpers.

Covers BugBountyWorkflowManager._get_test_scenarios and
CTFChallengeAutomator._extract_flag_candidates / _validate_flag_format.
All deterministic string/regex operations, no I/O.
"""
import pytest


class TestGetTestScenarios:
    def test_known_vuln_types_return_scenarios(self, bug_bounty_manager):
        for vuln_type in ("rce", "sqli", "xss", "ssrf", "idor"):
            scenarios = bug_bounty_manager._get_test_scenarios(vuln_type)
            assert isinstance(scenarios, list)
            assert len(scenarios) >= 1
            assert all("name" in s and "payloads" in s for s in scenarios)

    def test_unknown_vuln_type_returns_empty(self, bug_bounty_manager):
        assert bug_bounty_manager._get_test_scenarios("nonexistent") == []

    def test_sqli_payloads_contain_classical_vectors(self, bug_bounty_manager):
        scenarios = bug_bounty_manager._get_test_scenarios("sqli")
        all_payloads = [p for s in scenarios for p in s["payloads"]]
        assert any("UNION SELECT" in p for p in all_payloads)
        assert any("OR 1=1" in p for p in all_payloads)

    def test_scenarios_are_independent_dicts(self, bug_bounty_manager):
        s1 = bug_bounty_manager._get_test_scenarios("xss")
        s1[0]["payloads"].append("INJECTED")
        s2 = bug_bounty_manager._get_test_scenarios("xss")
        assert "INJECTED" not in s2[0]["payloads"]


class TestExtractFlagCandidates:
    def test_extracts_curly_brace_flags(self, ctf_automator):
        out = "some output flag{w1n} more text CTF{another}"
        candidates = ctf_automator._extract_flag_candidates(out)
        assert "flag{w1n}" in candidates
        assert "CTF{another}" in candidates

    def test_extracts_hash_like_candidates(self, ctf_automator):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha256 = ("e3b0c44298fc1c149afbf4c8996fb924"
                  "27ae41e4649b934ca495991b7852b855")
        candidates = ctf_automator._extract_flag_candidates(f"hash={md5} sha={sha256}")
        assert md5 in candidates
        assert sha256 in candidates

    def test_deduplicates(self, ctf_automator):
        candidates = ctf_automator._extract_flag_candidates("flag{x} flag{x} flag{x}")
        # set() dedup -> only one occurrence
        assert candidates.count("flag{x}") == 1

    def test_empty_output(self, ctf_automator):
        assert ctf_automator._extract_flag_candidates("nothing here") == []


class TestValidateFlagFormat:
    @pytest.mark.parametrize("flag", [
        "flag{abc}",
        "FLAG{ABC}",
        "ctf{123}",
        "CTF{mixed_456}",
        "my_prefix{custom}",
    ])
    def test_valid_formats(self, ctf_automator, flag):
        assert ctf_automator._validate_flag_format(flag) is True

    @pytest.mark.parametrize("flag", [
        "flag{no-closing",
        "plainstring",
        "{missing_name}",
        "",
        "flag",
        "flag{}",  # .+ requires at least one char inside -> depends; {} has empty -> no match
    ])
    def test_invalid_formats(self, ctf_automator, flag):
        # Note: "flag{}" has empty braces; regex ^flag\{.+\}$ requires >=1 char -> invalid.
        assert ctf_automator._validate_flag_format(flag) is False
