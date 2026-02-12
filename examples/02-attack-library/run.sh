#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "📚 ZIRAN — Attack Library Example"
echo "   Browse and filter 40+ built-in attack vectors."
echo ""

uv run python main.py
