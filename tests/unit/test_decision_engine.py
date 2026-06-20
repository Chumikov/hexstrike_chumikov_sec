"""Unit tests for hexstrike_server.IntelligentDecisionEngine.

Targets the pure heuristics: target-type classification and per-tool parameter
optimizers. No I/O, no mocks.
"""
import pytest

from hexstrike_server import TargetType, TechnologyStack


class TestDetermineTargetType:
    @pytest.mark.parametrize("target,expected", [
        ("http://example.com", TargetType.WEB_APPLICATION),
        ("https://app.example.com/", TargetType.WEB_APPLICATION),
        ("https://api.example.com/api/users", TargetType.API_ENDPOINT),
        ("http://host/api", TargetType.API_ENDPOINT),
        ("192.168.1.1", TargetType.NETWORK_HOST),
        ("10.0.0.255", TargetType.NETWORK_HOST),
        ("example.com", TargetType.WEB_APPLICATION),
        ("sub.example.co.uk", TargetType.WEB_APPLICATION),
        # NOTE (latent bug): the file-extension branch is unreachable for "clean"
        # names like "malware.exe" because the domain regex
        # ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ matches them first -> WEB_APPLICATION.
        # BINARY_FILE is only reached when the name contains a char outside the
        # domain class (e.g. an underscore), which breaks the domain regex.
        ("malware.exe", TargetType.WEB_APPLICATION),
        ("my_file.exe", TargetType.BINARY_FILE),
        ("weird_elf.elf", TargetType.BINARY_FILE),
        ("my_app.so", TargetType.BINARY_FILE),
    ])
    def test_known_classifications(self, decision_engine, target, expected):
        assert decision_engine._determine_target_type(target) == expected

    def test_unknown_for_garbage(self, decision_engine):
        assert decision_engine._determine_target_type("just-a-name") == TargetType.UNKNOWN

    def test_cloud_service_when_not_matching_domain_regex(self, decision_engine):
        # No dot -> bypasses the domain branch; contains 'azure' -> CLOUD_SERVICE
        assert decision_engine._determine_target_type("my-azure-blob") == TargetType.CLOUD_SERVICE


class TestOptimizeNmap:
    def test_web_application_default_timing(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test", target_type=TargetType.WEB_APPLICATION)
        params = decision_engine._optimize_nmap_params(p, context={})
        assert params["target"] == "https://app.test"
        assert params["scan_type"] == "-sV -sC"
        assert "443" in params["ports"]
        assert "-T4" in params["additional_args"]

    def test_network_host_uses_syn_scan(self, decision_engine, make_profile):
        p = make_profile(target="10.0.0.1", target_type=TargetType.NETWORK_HOST)
        params = decision_engine._optimize_nmap_params(p, context={})
        assert params["scan_type"] == "-sS -O"
        assert "--top-ports 1000" in params["additional_args"]

    def test_stealth_context_slows_timing(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test", target_type=TargetType.WEB_APPLICATION)
        params = decision_engine._optimize_nmap_params(p, context={"stealth": True})
        assert "-T2" in params["additional_args"]
        assert "-T4" not in params["additional_args"]


class TestOptimizeGobuster:
    def test_php_extensions(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test", technologies=[TechnologyStack.PHP])
        params = decision_engine._optimize_gobuster_params(p, context={})
        assert "-x php,html,txt,xml" in params["additional_args"]

    def test_aggressive_boosts_threads(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test")
        params = decision_engine._optimize_gobuster_params(p, context={"aggressive": True})
        assert "-t 50" in params["additional_args"]

    def test_default_threads(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test")
        params = decision_engine._optimize_gobuster_params(p, context={})
        assert "-t 20" in params["additional_args"]


class TestOptimizeNuclei:
    def test_quick_limits_severity(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test")
        params = decision_engine._optimize_nuclei_params(p, context={"quick": True})
        assert params["severity"] == "critical,high"

    def test_full_severity_without_quick(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test")
        params = decision_engine._optimize_nuclei_params(p, context={})
        assert params["severity"] == "critical,high,medium"

    def test_wordpress_tag(self, decision_engine, make_profile):
        p = make_profile(target="https://wp.test", technologies=[TechnologyStack.WORDPRESS])
        params = decision_engine._optimize_nuclei_params(p, context={})
        assert params.get("tags") == "wordpress"


class TestOptimizeSqlmap:
    def test_php_selects_mysql(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test", technologies=[TechnologyStack.PHP])
        params = decision_engine._optimize_sqlmap_params(p, context={})
        assert "--dbms=mysql" in params["additional_args"]
        assert "--batch" in params["additional_args"]

    def test_dotnet_selects_mssql(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test", technologies=[TechnologyStack.DOTNET])
        params = decision_engine._optimize_sqlmap_params(p, context={})
        assert "--dbms=mssql" in params["additional_args"]

    def test_aggressive_raises_level(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test")
        params = decision_engine._optimize_sqlmap_params(p, context={"aggressive": True})
        assert "--level=3 --risk=2" in params["additional_args"]


class TestOptimizeFfuf:
    def test_api_endpoint_match_codes(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test/api", target_type=TargetType.API_ENDPOINT)
        params = decision_engine._optimize_ffuf_params(p, context={})
        assert "201" in params["match_codes"]

    def test_default_match_codes(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test")
        params = decision_engine._optimize_ffuf_params(p, context={})
        assert "204" in params["match_codes"]

    def test_stealth_lowers_threads(self, decision_engine, make_profile):
        p = make_profile(target="https://app.test")
        params = decision_engine._optimize_ffuf_params(p, context={"stealth": True})
        assert "-t 10" in params["additional_args"]
