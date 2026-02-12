#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🎯 ZIRAN — Dynamic Vector Generator Example"
echo "   Generate tailored attack vectors from agent capabilities."
echo ""

uv run python main.py
