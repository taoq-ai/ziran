#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🔍 ZIRAN — Static Analysis Example"
echo "   Scan Python files for security anti-patterns without running an agent."
echo ""

uv run python main.py
