#!/usr/bin/env bash
# Run the remote agent scan example end-to-end.
#
# This script starts the vulnerable demo server, scans it with ZIRAN,
# then stops the server.  Uses the examples pyproject.toml venv via uv.
#
# Usage:
#   cd examples/15-remote-agent-scan
#   bash run.sh

set -euo pipefail
cd "$(dirname "$0")"
EXAMPLES_ROOT="$(cd .. && pwd)"

PORT=${PORT:-8899}
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        echo "⏹  Stopping demo server (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "============================================"
echo "  ZIRAN — Remote Agent Scan Example"
echo "============================================"
echo ""

# -------------------------------------------------------------------
# 1.  Start the vulnerable demo server
# -------------------------------------------------------------------
echo "▶  Starting vulnerable demo server on http://localhost:${PORT} ..."
uv run --project "$EXAMPLES_ROOT" --extra remote \
    uvicorn vulnerable_server:app --port "$PORT" --log-level warning &
SERVER_PID=$!
sleep 2  # give the server a moment to bind

# Quick health check
if ! curl -sf "http://localhost:${PORT}/health" > /dev/null; then
    echo "❌  Server failed to start.  Install with:  uv sync --extra remote  (from examples/)"
    exit 1
fi
echo "✅  Server is running."
echo ""

# -------------------------------------------------------------------
# 2.  Run the ZIRAN scan
# -------------------------------------------------------------------
echo "▶  Running ZIRAN scan..."
echo ""
uv run --project "$EXAMPLES_ROOT" --extra remote python main.py
echo ""
echo "Done!  Check the reports/ directory for results."
