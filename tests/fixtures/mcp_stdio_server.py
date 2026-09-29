"""Minimal stdio MCP server used as a test fixture (stdlib only, no network).

Usage: ``python mcp_stdio_server.py TOOLS_JSON [REQUIRED_ENV_VAR]``

* ``TOOLS_JSON`` - path to a JSON list of tools, re-read on every ``tools/list``
  so a test can change a description between runs.
* ``REQUIRED_ENV_VAR`` - optional; the process exits 1 unless it is set.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    tools_path = Path(sys.argv[1])
    if len(sys.argv) > 2 and not os.environ.get(sys.argv[2]):
        return 1
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
                "serverInfo": {"name": "fixture", "version": "0"},
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
