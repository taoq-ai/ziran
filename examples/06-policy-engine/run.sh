#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "📋 ZIRAN — Policy Engine Example"
echo "   Evaluate scan results against organisational security policies."
echo ""

uv run python main.py
