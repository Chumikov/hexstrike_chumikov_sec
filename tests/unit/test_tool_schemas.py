"""Regression test for MCP tool inputSchemas (F3, v6.3.0; updated v6.4.5).

Locks in two properties discovered during the F3 audit:
1. Every tool exposes a valid JSON-Schema `inputSchema` (type=object, proper
   properties/required) — this is what lets OpenCode call tools without
   "broken inputSchema" errors.
2. Every parameter carries a human-readable `description` (via Annotated/Field),
   so the agent understands each argument. FastMCP does NOT parse docstring
   `Args:` blocks, so descriptions must be supplied explicitly.

v6.4.5 update: count is now 32 = 25 legacy tools + 7 new verbs
(`port_scan`, `subdomain_enum`, `http_probe`, `directory_brute`,
`web_vuln_scan`, `cloud_audit`, `metasploit_run`).
"""
import asyncio
import os

import pytest

import hexstrike_mcp


@pytest.fixture(scope="module")
def tools():
    """All registered MCP tools (introspected once per module) under default profile."""
    # Force default profile (full + aliases on) for stable count regardless of env.
    os.environ.pop("HEXSTRIKE_MCP_PROFILE", None)
    os.environ.pop("HEXSTRIKE_MCP_ALIASES", None)
    class _DummyClient:
        pass
    mcp = hexstrike_mcp.setup_mcp_server(_DummyClient())
    return asyncio.run(mcp.list_tools())


def test_all_tools_registered(tools):
    # v6.4.0: 25 tools. v6.4.5: 32 = 25 legacy + 7 new verbs (port_scan, etc.).
    names = {t.name for t in tools}
    assert len(names) == 32, f"expected 32 tools, got {len(names)}: {sorted(names)}"


def test_v645_new_verbs_present(tools):
    """All 7 new verbs from v6.4.5 must be registered in default profile."""
    names = {t.name for t in tools}
    expected_verbs = {"port_scan", "subdomain_enum", "http_probe",
                      "directory_brute", "web_vuln_scan", "cloud_audit",
                      "metasploit_run"}
    missing = expected_verbs - names
    assert not missing, f"missing v6.4.5 verbs: {missing}"


def test_input_schemas_are_valid_jsonschema(tools):
    bad = []
    for t in tools:
        s = t.inputSchema
        if not isinstance(s, dict):
            bad.append(f"{t.name}: inputSchema not a dict")
            continue
        if s.get("type") != "object":
            bad.append(f"{t.name}: type={s.get('type')!r} (expected 'object')")
        if not isinstance(s.get("properties"), dict):
            bad.append(f"{t.name}: properties not a dict")
        if not isinstance(s.get("required", []), list):
            bad.append(f"{t.name}: required not a list")
    assert not bad, "invalid inputSchemas:\n  " + "\n  ".join(bad)


def test_every_parameter_has_a_description(tools):
    """Descriptions must reach the schema (agent relies on them)."""
    missing = []
    for t in tools:
        for pname, pdef in t.inputSchema.get("properties", {}).items():
            if not isinstance(pdef, dict) or "description" not in pdef:
                missing.append(f"{t.name}.{pname}")
    assert not missing, "parameters without description:\n  " + "\n  ".join(missing)


def test_required_matches_params_without_defaults(tools):
    """A parameter is 'required' iff it has no default in its schema."""
    for t in tools:
        props = t.inputSchema.get("properties", {})
        required = set(t.inputSchema.get("required", []))
        for pname, pdef in props.items():
            has_default = "default" in pdef
            if has_default and pname in required:
                pytest.fail(f"{t.name}.{pname}: has default but listed required")
