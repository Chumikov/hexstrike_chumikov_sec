"""Regression test for MCP tool inputSchemas (F3, v6.3.0).

Locks in two properties discovered during the F3 audit:
1. Every tool exposes a valid JSON-Schema `inputSchema` (type=object, proper
   properties/required) — this is what lets OpenCode call tools without
   "broken inputSchema" errors.
2. Every parameter carries a human-readable `description` (via Annotated/Field),
   so the agent understands each argument. FastMCP does NOT parse docstring
   `Args:` blocks, so descriptions must be supplied explicitly.
"""
import asyncio

import pytest

import hexstrike_mcp


@pytest.fixture(scope="module")
def tools():
    """All registered MCP tools (introspected once per module)."""
    class _DummyClient:
        pass
    mcp = hexstrike_mcp.setup_mcp_server(_DummyClient())
    return asyncio.run(mcp.list_tools())


def test_all_tools_registered(tools):
    # 25 tools in the trimmed mcp.py; guard against accidental drops.
    names = {t.name for t in tools}
    assert len(names) == 25, f"expected 25 tools, got {len(names)}: {sorted(names)}"


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
