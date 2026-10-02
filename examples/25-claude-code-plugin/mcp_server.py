"""Local stand-in for a real MCP server (stdlib only, no network).

Usage: ``python3 mcp_server.py TOOLS_JSON``

Answers ``initialize`` and ``tools/list`` over stdio with the tools listed in
``TOOLS_JSON`` (re-read on every call); any other method returns -32601.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    tools_path = Path(sys.argv[1])
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if "id" not in msg:
            continue  # notification
        response: dict[str, object] = {"jsonrpc": "2.0", "id": msg["id"]}
        if msg.get("method") == "initialize":
            response["result"] = {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "example-docs", "version": "0.1.0"},
            }
        elif msg.get("method") == "tools/list":
            tools = json.loads(tools_path.read_text(encoding="utf-8"))
            response["result"] = {"tools": tools}
        else:
            response["error"] = {"code": -32601, "message": "Method not found"}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
