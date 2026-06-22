"""Unit tests for hexstrike_guardrails.scope (G1).

Covers ScopeRule parsing, target normalisation, validator behaviour for
every rule kind (CIDR/wildcard/regex/hostname) and edge cases identified
in the netcuter audit (IPv6 brackets, trailing dots, scheme stripping).
"""
import ipaddress

import pytest

from hexstrike_guardrails import ScopeParseError, ScopeRule, ScopeValidator
from hexstrike_guardrails.scope import RuleType, normalize_target


pytestmark = pytest.mark.guardrails


# ---------------------------------------------------------------------------
# normalize_target()
# ---------------------------------------------------------------------------


class TestNormalizeTarget:
    @pytest.mark.parametrize("raw, expected", [
        ("example.com", "example.com"),
        ("example.com.", "example.com"),                        # trailing dot
        ("EXAMPLE.COM", "example.com"),                         # case
        ("https://example.com/", "example.com"),
        ("https://example.com:8443/path?q=1", "example.com"),
        ("http://user:pass@example.com/", "example.com"),
        ("https://[::1]:8080/path", "::1"),                     # bracketed IPv6
        ("[2001:db8::1]", "2001:db8::1"),
        ("192.168.0.5", "192.168.0.5"),
        ("192.168.0.5:22", "192.168.0.5"),                      # host:port
        ("10.0.0.5:8080/foo", "10.0.0.5"),
        ("  spaced.com  ", "spaced.com"),                       # whitespace
    ])
    def test_strips_correctly(self, raw, expected):
        assert normalize_target(raw) == expected

    @pytest.mark.parametrize("bad", ["", None, "   ", "//:8080"])
    def test_returns_empty_for_garbage(self, bad):
        assert normalize_target(bad) == ""


# ---------------------------------------------------------------------------
# ScopeRule.parse()
# ---------------------------------------------------------------------------


class TestScopeRuleParse:
    def test_cidr_v4(self):
        r = ScopeRule.parse("192.168.0.0/24")
        assert r.kind is RuleType.CIDR
        assert r.network == ipaddress.ip_network("192.168.0.0/24")

    def test_bare_ip_becomes_cidr(self):
        r = ScopeRule.parse("10.0.0.5")
        assert r.kind is RuleType.CIDR
        # ip_network(strict=False) treats a bare host as /32
        assert r.network.prefixlen == 32

    def test_cidr_v6(self):
        r = ScopeRule.parse("::1/128")
        assert r.kind is RuleType.CIDR
        assert r.network.version == 6

    def test_hostname(self):
        r = ScopeRule.parse("example.com")
        assert r.kind is RuleType.HOSTNAME
        assert r.pattern == "example.com"

    def test_hostname_strips_trailing_dot(self):
        r = ScopeRule.parse("example.com.")
        assert r.kind is RuleType.HOSTNAME
        assert r.pattern == "example.com"

    def test_wildcard(self):
        r = ScopeRule.parse("*.example.com")
        assert r.kind is RuleType.WILDCARD
        assert r.regex is not None

    def test_regex(self):
        r = ScopeRule.parse(r"r:^.*\.internal$")
        assert r.kind is RuleType.REGEX
        assert r.regex is not None

    def test_empty_rule_raises(self):
        with pytest.raises(ScopeParseError):
            ScopeRule.parse("")
        with pytest.raises(ScopeParseError):
            ScopeRule.parse("   ")

    def test_whitespace_in_hostname_raises(self):
        with pytest.raises(ScopeParseError):
            ScopeRule.parse("evil .com")

    def test_bad_regex_raises(self):
        with pytest.raises(ScopeParseError):
            ScopeRule.parse("r:[invalid")

    def test_oversized_regex_rejected(self):
        with pytest.raises(ScopeParseError):
            ScopeRule.parse("r:" + "a" * 300)


# ---------------------------------------------------------------------------
# ScopeValidator
# ---------------------------------------------------------------------------


class TestScopeValidatorEmpty:
    def test_empty_scope_allows_everything(self):
        v = ScopeValidator([])
        assert v.has_rules() is False
        for t in ["evil.com", "192.168.0.1", "::1", "[::1]:80"]:
            in_scope, matched = v.validate(t)
            assert in_scope is True
            assert matched is None


class TestScopeValidatorCidr:
    def test_v4_inside(self):
        v = ScopeValidator(["192.168.1.0/24"])
        for ok in ["192.168.1.1", "192.168.1.254", "http://192.168.1.5:80/"]:
            assert v.validate(ok)[0] is True

    def test_v4_outside(self):
        v = ScopeValidator(["192.168.1.0/24"])
        for bad in ["192.168.0.1", "10.0.0.1", "192.168.2.1"]:
            assert v.validate(bad)[0] is False

    def test_v6_inside(self):
        v = ScopeValidator(["::1/128"])
        assert v.validate("http://[::1]:8080/")[0] is True

    def test_v6_outside(self):
        v = ScopeValidator(["::1/128"])
        assert v.validate("::2")[0] is False

    def test_v4_rule_does_not_match_v6_target(self):
        v = ScopeValidator(["0.0.0.0/0"])
        # IPv6 should not be authorised by an IPv4 CIDR (even 0.0.0.0/0).
        assert v.validate("::1")[0] is False

    def test_bare_ip_rule_matches_only_that_ip(self):
        v = ScopeValidator(["10.0.0.5"])
        assert v.validate("10.0.0.5")[0] is True
        assert v.validate("10.0.0.6")[0] is False


class TestScopeValidatorHostname:
    def test_exact_match(self):
        v = ScopeValidator(["example.com"])
        assert v.validate("example.com")[0] is True
        assert v.validate("EXAMPLE.COM")[0] is True

    def test_subdomain_does_not_match_apex(self):
        v = ScopeValidator(["example.com"])
        assert v.validate("sub.example.com")[0] is False

    def test_url_form(self):
        v = ScopeValidator(["example.com"])
        assert v.validate("https://example.com:443/x")[0] is True
        assert v.validate("https://user:pass@example.com/x")[0] is True


class TestScopeValidatorWildcard:
    def test_single_level_subdomain(self):
        v = ScopeValidator(["*.example.com"])
        assert v.validate("a.example.com")[0] is True

    def test_multi_level_subdomain(self):
        # Documented behaviour: ``*`` matches dots, so multi-level also matches.
        v = ScopeValidator(["*.example.com"])
        assert v.validate("a.b.example.com")[0] is True

    def test_apex_does_not_match_wildcard(self):
        v = ScopeValidator(["*.example.com"])
        assert v.validate("example.com")[0] is False


class TestScopeValidatorRegex:
    def test_match(self):
        v = ScopeValidator([r"r:^host\d+\.internal$"])
        assert v.validate("host1.internal")[0] is True
        assert v.validate("host42.internal")[0] is True

    def test_no_match(self):
        v = ScopeValidator([r"r:^host\d+\.internal$"])
        assert v.validate("host.internal")[0] is False
        assert v.validate("evil.com")[0] is False

    def test_case_insensitive(self):
        v = ScopeValidator([r"r:^INTERNAL$"])
        assert v.validate("internal")[0] is True


class TestScopeValidatorMixed:
    def test_any_rule_match_suffices(self):
        v = ScopeValidator([
            "192.168.0.0/16", "example.com", "*.corp", r"r:^.*\.internal$",
        ])
        assert v.validate("192.168.5.5")[0] is True
        assert v.validate("example.com")[0] is True
        assert v.validate("host.corp")[0] is True
        assert v.validate("deep.internal")[0] is True
        assert v.validate("evil.org")[0] is False

    def test_matched_rule_returned(self):
        v = ScopeValidator(["192.168.0.0/16", "example.com"])
        in_scope, matched = v.validate("192.168.5.5")
        assert in_scope is True
        assert matched == "192.168.0.0/16"
        in_scope, matched = v.validate("example.com")
        assert matched == "example.com"
        in_scope, matched = v.validate("evil.org")
        assert in_scope is False
        assert matched is None

    def test_to_raw_list_roundtrip(self):
        rules = ["10.0.0.0/8", "*.example.com"]
        v = ScopeValidator(rules)
        assert v.to_raw_list() == rules

    def test_add_rule_appends(self):
        v = ScopeValidator(["10.0.0.0/8"])
        v.add_rule("example.com")
        assert sorted(v.to_raw_list()) == sorted(["10.0.0.0/8", "example.com"])

    def test_clear_drops_all_rules(self):
        v = ScopeValidator(["10.0.0.0/8", "example.com"])
        assert v.has_rules()
        v.clear()
        assert not v.has_rules()
        # After clear, validator is allow-all.
        assert v.validate("evil.com")[0] is True
