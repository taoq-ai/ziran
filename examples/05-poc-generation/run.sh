#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🧪 ZIRAN — PoC Generation Example"
echo "   Generate proof-of-concept exploit scripts from attack results."
echo ""

uv run python main.py
