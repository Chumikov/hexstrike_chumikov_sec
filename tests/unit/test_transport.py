"""Unit tests for MCP transport configuration (F2, v6.3.0).

Does NOT start a real server — only validates the mapping/env logic and that
the FastMCP object is configured with the expected host/port.
"""
import pytest

import hexstrike_mcp


def test_transport_map_covers_all_choices():
    for choice in ("stdio", "sse", "streamable", "http"):
        assert choice in hexstrike_mcp.TRANSPORT_MAP


def test_transport_map_targets_valid_fastmcp_literals():
    # FastMCP.run accepts only these literals.
    valid = {"stdio", "sse", "streamable-http"}
    for mapped in hexstrike_mcp.TRANSPORT_MAP.values():
        assert mapped in valid


def test_http_alias_maps_to_streamable():
    assert hexstrike_mcp.TRANSPORT_MAP["http"] == "streamable-http"
    assert hexstrike_mcp.TRANSPORT_MAP["streamable"] == "streamable-http"
    assert hexstrike_mcp.TRANSPORT_MAP["sse"] == "sse"
    assert hexstrike_mcp.TRANSPORT_MAP["stdio"] == "stdio"


def test_setup_mcp_server_applies_host_port():
    class _Dummy:
        pass
    mcp = hexstrike_mcp.setup_mcp_server(_Dummy(), host="0.0.0.0", port=9999)
    assert mcp.settings.host == "0.0.0.0"
    assert mcp.settings.port == 9999


def test_setup_mcp_server_defaults_to_mcp_port():
    class _Dummy:
        pass
    mcp = hexstrike_mcp.setup_mcp_server(_Dummy())
    # Default MCP port is 9010 (separate from the Flask server on 8888).
    assert mcp.settings.port == hexstrike_mcp.DEFAULT_MCP_PORT
    assert hexstrike_mcp.DEFAULT_MCP_PORT == 9010
