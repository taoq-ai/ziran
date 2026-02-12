#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🚦 ZIRAN — CI/CD Quality Gate Example"
echo "   Run quality gates and generate SARIF reports for GitHub Code Scanning."
echo ""

uv run python main.py
