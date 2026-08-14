#!/usr/bin/env python3
"""Minimal stdio JSON-RPC client for hexstrike_mcp.py (lab use only).

Speaks enough MCP to initialize, list tools and call them, with a timeout on
every read so a hung MCP server fails the check instead of hanging the lab.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time


class McpStdioClient:
    def __init__(self, server_script: str, env_extra: dict | None = None,
                 server_url: str = "http://127.0.0.1:8888"):
        env = dict(os.environ)
        env.update(env_extra or {})
        env.setdefault("MCP_TRANSPORT", "stdio")
        self.proc = subprocess.Popen(
            [os.environ.get("PYTHON", "python3"), server_script,
             "--server", server_url],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env=env,
        )
        self._lines: "queue.Queue[str]" = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._next_id = 0

    def _read_loop(self):
        try:
            for line in self.proc.stdout:
                self._lines.put(line)
        except Exception:
            pass

    def _send(self, payload: dict):
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def _recv(self, timeout: float) -> dict:
        line = self._lines.get(timeout=timeout)
        data = json.loads(line)
        if isinstance(data, list):  # batch — take first
            data = data[0]
        return data

    def _wait_response(self, req_id: int, timeout: float) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self._recv(timeout=max(0.1, deadline - time.time()))
            if msg.get("id") == req_id:
                return msg
        raise TimeoutError(f"no response for id={req_id}")

    def initialize(self, timeout: float = 30.0) -> dict:
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05",
                               "capabilities": {},
                               "clientInfo": {"name": "synthetic-lab",
                                              "version": "1.0"}}})
        resp = self._wait_response(rid, timeout)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp.get("result", {})

    def list_tools(self, timeout: float = 30.0) -> list:
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": "tools/list"})
        resp = self._wait_response(rid, timeout)
        return resp.get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict, timeout: float = 240.0):
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments}})
        resp = self._wait_response(rid, timeout)
        if "error" in resp:
            return {"isError": True, "error": resp["error"]}
        return resp.get("result", {})

    @staticmethod
    def tool_text(result: dict) -> str:
        parts = []
        for item in result.get("content", []):
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
        return "\n".join(parts)

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
