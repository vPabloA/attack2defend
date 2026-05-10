"""Minimal read-only stdio MCP-style server.

Supports JSON-RPC style requests:
- {"method":"tools/list","id":1}
- {"method":"tools/call","params":{"name":"defense_route","arguments":{"id":"CVE-2021-44228"}},"id":2}
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .tools import run_tool, tool_definitions


def response(request_id: Any, result: Any = None, error: Any = None) -> dict[str, Any]:
    payload = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result
    return payload


def handle(request: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    request_id = request.get("id")
    if method in {"initialize", "mcp/initialize"}:
        return response(request_id, {"server": "attack2defend", "version": "1.0.0", "capabilities": {"tools": True}})
    if method == "tools/list":
        return response(request_id, {"tools": tool_definitions()})
    if method == "tools/call":
        params = request.get("params", {})
        name = params.get("name")
        arguments = params.get("arguments", {})
        return response(request_id, {"content": [{"type": "json", "json": run_tool(name, arguments)}]})
    return response(request_id, error={"code": -32601, "message": f"Unknown method {method}"})


def serve_stdio() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            print(json.dumps(handle(request), ensure_ascii=False), flush=True)
        except Exception as exc:
            print(json.dumps(response(None, error={"code": -32000, "message": str(exc)}), ensure_ascii=False), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Attack2Defend read-only MCP-style stdio server")
    parser.add_argument("--list-tools", action="store_true")
    args = parser.parse_args(argv)
    if args.list_tools:
        print(json.dumps({"tools": tool_definitions()}, indent=2, ensure_ascii=False))
        return 0
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
