#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🔌 ZIRAN — Custom Adapter Example"
echo "   Implement BaseAgentAdapter to integrate any agent framework."
echo ""

uv run python main.py
